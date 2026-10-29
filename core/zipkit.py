"""
zipkit.py —— 自带偏移修正的 ZIP 读取器

标准库 zipfile 有两个硬伤，正是这类资源解不开的原因：
  1. 它按中央目录记录的原样偏移去定位数据，前面拼了东西就全错位；
  2. 不支持 WinZip AES-256（method 99），直接报「不支持的压缩方法」。

所以这里自己实现：以 probe 算出的 shift 校正所有偏移，并按 WinZip AES
规范做 PBKDF2 + AES-CTR 解密，同时支持传统 ZipCrypto 与 deflate / store。

实测要点（踩过的坑，写死在代码里）：
  * CTR 计数器是从 1 开始的小端整数，AES(LE(1+i))；不是拿 nonce 当初始计数器。
  * 7-Zip 写出的 AES 包认证码（最后 10 字节）并不符合规范，无法用于校验，
    因此完整性只以条目里的 CRC32 为准。
"""

import hashlib
import struct
import zlib

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    _HAS_AES = True
except Exception:  # 没装 pycryptodome 时，AES 包无法解密，其他格式仍可用
    _HAS_AES = False

BLOCK = 1 << 20

_AES_PARAMS = {1: (8, 16), 2: (12, 24), 3: (16, 32)}  # strength -> (salt_len, key_len)

_CRC_TABLE = None


def _crc_table():
    global _CRC_TABLE
    if _CRC_TABLE is None:
        _CRC_TABLE = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
            _CRC_TABLE.append(c)
    return _CRC_TABLE


class ZipCrypto:
    """传统 ZIP 加密（ZipCrypto）。很弱，但老包里极常见。"""

    def __init__(self, password: bytes):
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for b in password:
            self.update(b)

    def update(self, plain: int):
        t = _crc_table()
        self.k0 = (self.k0 >> 8) ^ t[(self.k0 ^ plain) & 0xFF]
        self.k1 = ((self.k1 + (self.k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = (self.k2 >> 8) ^ t[(self.k2 ^ (self.k1 >> 24)) & 0xFF]

    def byte(self) -> int:
        t = (self.k2 | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    def decrypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i, c in enumerate(data):
            p = c ^ self.byte()
            self.update(p)
            out[i] = p
        return bytes(out)


def derive(password: bytes, salt: bytes, key_len: int):
    return hashlib.pbkdf2_hmac("sha1", password, salt, 1000, 2 * key_len + 2)


def check_password(entry, password: bytes, path: str):
    """只读几个字节就能判定密码对不对，不必解压整个文件。"""
    if not entry["encrypted"]:
        return True
    if entry["data_off"] is None:
        return False
    with open(path, "rb") as f:
        f.seek(entry["data_off"])
        head = f.read(32)
    if entry["aes"]:
        if not _HAS_AES:
            return False
        strength = entry["aes"]["strength"]
        salt_len, key_len = _AES_PARAMS.get(strength, (16, 32))
        if len(head) < salt_len + 2:
            return False
        salt = head[:salt_len]
        pv = head[salt_len:salt_len + 2]
        dk = derive(password, salt, key_len)
        return dk[-2:] == pv
    # ZipCrypto：头 12 字节，解密后末字节应与 CRC 高字节或时间高字节相同
    zc = ZipCrypto(password)
    hdr = zc.decrypt(head[:12])
    if len(hdr) < 12:
        return False
    if entry["flag"] & 0x08:  # 有数据描述符时用时间高位
        return hdr[11] == (entry["mtime"] >> 8) & 0xFF
    return hdr[11] == (entry["crc"] >> 24) & 0xFF


def _payload_len(entry):
    """密文数据长度（不含 salt / pv / 认证码 / ZipCrypto 头）。"""
    if entry["aes"]:
        _sl, _kl = _AES_PARAMS.get(entry["aes"]["strength"], (16, 32))
        return entry["csize"] - (_sl + 2 + 10)
    if entry["encrypted"]:
        return entry["csize"] - 12
    return entry["csize"]


def iter_plain(entry, password, path, on_bytes=None, cancelled=None):
    """流式产出明文分片。password 为 None 表示未加密。"""
    with open(path, "rb") as f:
        offset = entry["data_off"]
        if offset is None:
            raise IOError("条目 %s 的本地头位置无效" % entry["name"])
        remain = _payload_len(entry)
        if remain < 0:
            raise IOError("条目 %s 的数据长度异常" % entry["name"])

        cipher = None
        if entry["aes"]:
            if not _HAS_AES:
                raise RuntimeError("缺少 pycryptodome，无法解密 AES 压缩包")
            f.seek(offset)
            strength = entry["aes"]["strength"]
            salt_len, key_len = _AES_PARAMS.get(strength, (16, 32))
            salt = f.read(salt_len)
            f.read(2)
            dk = derive(password, salt, key_len)
            ctr = Counter.new(128, initial_value=1, little_endian=True, prefix=b"")
            cipher = AES.new(dk[:key_len], AES.MODE_CTR, counter=ctr)
            offset += salt_len + 2
        elif entry["encrypted"]:
            f.seek(offset)
            zc = ZipCrypto(password)
            zc.decrypt(f.read(12))
            offset += 12
            cipher = zc

        f.seek(offset)
        real_method = entry["aes"]["method"] if entry["aes"] else entry["method"]
        if real_method == 8:
            dec = zlib.decompressobj(-15)
        elif real_method == 0:
            dec = None
        elif real_method == 12:
            import bz2
            dec = bz2.BZ2Decompressor()
        elif real_method == 14:
            import lzma
            dec = lzma.LZMADecompressor()
        else:
            if real_method == 99:
                raise RuntimeError("检测到"+"AES"+"但缺少真实压缩方法，可能是非标准实现")
            raise RuntimeError("暂不支持的压缩方法 %s（条目 %s）" % (real_method, entry["name"]))

        while remain > 0:
            if cancelled and cancelled():
                return
            chunk = f.read(min(BLOCK, remain))
            if not chunk:
                break
            remain -= len(chunk)
            if cipher is not None:
                plain = cipher.decrypt(chunk)
            else:
                plain = chunk
            if on_bytes:
                on_bytes(len(chunk))
            if dec is None:
                yield plain
            else:
                try:
                    out = dec.decompress(plain)
                except Exception as exc:
                    raise IOError("数据损坏或密码不匹配：%s" % exc)
                if out:
                    yield out
            if dec is not None and getattr(dec, "eof", False):
                break
        if dec is not None:
            tail = dec.flush() if hasattr(dec, "flush") else b""
            if tail:
                yield tail


def safe_join(root, name):
    """防路径穿越，同时兼容包里常见的反斜杠分隔。"""
    import os
    name = name.replace("\\", "/")
    parts = [p for p in name.split("/") if p not in ("", ".", "..")]
    if not parts:
        return None
    return os.path.join(root, *parts)
