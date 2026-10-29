"""
probe.py —— 容器文件结构探测

职责：只看文件结构，不做解压。回答三个问题
  1. 这个文件外层是什么（真正的媒体？还是被拼了外壳的压缩包？）
  2. 压缩包在哪里（起始/结束偏移），标准工具为什么打不开
  3. 里面有多少条目、是否加密、预计解出多少数据

关键难点：ZIP 的中央目录里记录的是「相对于压缩包起点」的偏移。
一旦有人在压缩包前面拼了视频，所有偏移就整体错位，解压器据此算出
的位置全是垃圾数据，于是报「文件损坏 / 不是压缩包」。
本模块通过「中央目录的真实位置 - 记录位置」反推出错位量 shift，
后续所有定位都加上 shift，从而无需落地任何中间文件。
"""

import os
import struct

ZIP_LFH = b"PK\x03\x04"
ZIP_CDH = b"PK\x01\x02"
ZIP_EOCD = b"PK\x05\x06"
ZIP64_EOCD = b"PK\x06\x06"
ZIP64_LOC = b"PK\x06\x07"

SIG_7Z = b"7z\xbc\xaf\x27\x1c"
SIG_RAR = b"Rar!\x1a\x07"

# 常见媒体外壳的识别（魔数 -> 说明）
MEDIA_MAGICS = [
    (b"\x00\x00\x00", "MP4/MOV (ftyp)", 4),
    (b"\x1a\x45\xdf\xa3", "Matroska (mkv/webm)", 0),
    (b"RIFF", "AVI/WAV", 0),
    (b"\xff\xd8\xff", "JPEG", 0),
    (b"\x89PNG", "PNG", 0),
    (b"FLV\x01", "FLV", 0),
]

CHUNK = 8 << 20


def _read_tail(path, window):
    size = os.path.getsize(path)
    start = max(0, size - window)
    with open(path, "rb") as f:
        f.seek(start)
        return start, f.read(size - start)


def find_eocd_candidates(path, window=4 << 20):
    """从文件尾部向前找出所有 EOCD（0x06054b50）候选偏移，新->旧。"""
    base, buf = _read_tail(path, window)
    out = []
    idx = len(buf)
    while True:
        idx = buf.rfind(ZIP_EOCD, 0, idx)
        if idx < 0:
            break
        if idx + 22 <= len(buf):
            comment_len = struct.unpack("<H", buf[idx + 20:idx + 22])[0]
            # 注释可被窗口截断，允许超出，但要能容纳 22 字节基本结构
            out.append(base + idx)
        idx -= 1
    return out


def _parse_zip64_eocd(f, loc_pos):
    """locator 紧跟在 zip64 EOCD 记录之后；记录长度可变，向前搜签名。"""
    lo = max(0, loc_pos - 4096)
    f.seek(lo)
    buf = f.read(loc_pos - lo + 20)
    idx = buf.rfind(ZIP64_EOCD, 0, len(buf))
    if idx < 0:
        return None
    pos = lo + idx
    f.seek(pos)
    rec = f.read(56)
    if len(rec) < 56:
        return None
    (_sig, _size, _vm, _vn, _disk, _cdd, _n1, nrec,
     cdsize, cdoff) = struct.unpack("<IQHHIIQQQQ", rec)
    return {"pos": pos, "nrec": nrec, "cdsize": cdsize, "cdoff": cdoff}


def _decode_name(raw, flag):
    if flag & 0x800:
        return raw.decode("utf-8", "replace")
    try:
        return raw.decode("cp437")
    except Exception:
        pass
    for enc in ("utf-8", "gbk", "gb18030"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("latin1", "replace")


def _parse_extra(extra, flag):
    """抽出 zip64(0x0001) 与 AES(0x9901) 两个关键扩展字段。"""
    zip64 = {}
    aes = None
    p = 0
    while p + 4 <= len(extra):
        hid, hsz = struct.unpack("<HH", extra[p:p + 4])
        body = extra[p + 4:p + 4 + hsz]
        if hid == 0x0001:
            q = 0
            for key in ("usize", "csize", "lho"):
                if q + 8 <= len(body):
                    zip64[key] = struct.unpack("<Q", body[q:q + 8])[0]
                    q += 8
        elif hid == 0x9901 and len(body) >= 7:
            ver, vendor = struct.unpack("<HH", body[:4])
            strength = body[4]
            real_method = struct.unpack("<H", body[5:7])[0]
            aes = {"version": ver, "vendor": vendor, "strength": strength,
                   "method": real_method}
        p += 4 + hsz
    return zip64, aes


def parse_zip(path, eocd_pos):
    """解析指定 EOCD 对应的 ZIP，返回结构与条目列表（含真实数据偏移）。"""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        f.seek(eocd_pos)
        eocd = f.read(22)
        if len(eocd) < 22 or eocd[:4] != ZIP_EOCD:
            return None
        (_s, disk, cd_disk, n_disk, nrec, cdsize,
         cdoff, clen) = struct.unpack("<IHHHHIIH", eocd)
        eocd_end = min(size, eocd_pos + 22 + clen)

        zip64 = None
        # 7-Zip 即使字段够放，也会写 ZIP64 记录，所以不能只看 0xFFFF 哨兵值，
        # 必须以「EOCD 前 20 字节是否为 ZIP64 定位器」为准。
        if eocd_pos >= 20:
            f.seek(eocd_pos - 20)
            loc = f.read(20)
            if loc[:4] == ZIP64_LOC:
                zip64 = _parse_zip64_eocd(f, eocd_pos - 20)
        if zip64:
            nrec = zip64["nrec"]
            cdsize = zip64["cdsize"]
            cdoff = zip64["cdoff"]

        # 中央目录真实结束位置 = zip64 EOCD 位置（若有）或 EOCD 位置
        cd_end_real = zip64["pos"] if zip64 else eocd_pos
        cd_start_real = cd_end_real - cdsize
        if cd_start_real < 0:
            return None
        # 校验：真从这里开始就应该是一条中央目录头
        if nrec > 0:
            f.seek(cd_start_real)
            if f.read(4) != ZIP_CDH:
                return None

        shift = cd_start_real - cdoff

        entries = []
        total_usize = 0
        enc_count = 0
        aes_count = 0
        f.seek(cd_start_real)
        for _ in range(nrec):
            hdr = f.read(46)
            if len(hdr) < 46 or hdr[:4] != ZIP_CDH:
                break
            (_sig, _vmade, _vneed, flag, method, mtime, mdate, crc,
             csize, usize, nlen, elen, clen_e, _dstart, _iattr,
             _eattr, lho) = struct.unpack("<IHHHHHHIIIHHHHHII", hdr)
            raw_name = f.read(nlen)
            extra = f.read(elen)
            if clen_e:
                f.read(clen_e)
            name = _decode_name(raw_name, flag)
            z64, aes = _parse_extra(extra, flag)
            if csize == 0xFFFFFFFF and "csize" in z64:
                csize = z64["csize"]
            if usize == 0xFFFFFFFF and "usize" in z64:
                usize = z64["usize"]
            if lho == 0xFFFFFFFF and "lho" in z64:
                lho = z64["lho"]

            # 真实本地头位置，读取它自己的名字/扩展长度（比中央目录更可靠）
            data_off = None
            if lho + shift + 30 <= size:
                pos = f.tell()
                f.seek(lho + shift)
                lfh = f.read(30)
                if lfh[:4] == ZIP_LFH:
                    lnl, lel = struct.unpack("<HH", lfh[26:30])
                    data_off = lho + shift + 30 + lnl + lel
                f.seek(pos)

            encrypted = bool(flag & 1)
            is_dir = name.endswith("/") or name.endswith("\\")
            if encrypted:
                enc_count += 1
            if aes:
                aes_count += 1
            total_usize += usize
            entries.append({
                "name": name,
                "flag": flag,
                "method": method,
                "aes": aes,
                "crc": crc,
                "csize": csize,
                "usize": usize,
                "lho": lho,
                "data_off": data_off,
                "encrypted": encrypted,
                "is_dir": is_dir,
                "mtime": mdate,
            })

        start = (min(e["lho"] for e in entries) + shift) if entries else shift
        if start < 0 or start >= size:
            start = max(0, min(shift, size))
        return {
            "kind": "zip",
            "eocd_pos": eocd_pos,
            "start": start,
            "end": eocd_end,
            "shift": shift,
            "cd_start": cd_start_real,
            "entries": entries,
            "entry_count": len(entries),
            "encrypted_count": enc_count,
            "aes_count": aes_count,
            "total_usize": total_usize,
            "zip64": bool(zip64),
        }


def scan_signatures(path, head=8 << 20, tail=8 << 20):
    """在文件首尾各 8MB 内找 7z / RAR 签名（深度扫描时全文件扫）。"""
    size = os.path.getsize(path)
    hits = []

    def _scan(offset, data):
        for sig, kind in ((SIG_7Z, "7z"), (SIG_RAR, "rar")):
            i = data.find(sig)
            while i >= 0:
                hits.append({"kind": kind, "offset": offset + i})
                i = data.find(sig, i + 1)

    with open(path, "rb") as f:
        _scan(0, f.read(min(head, size)))
        if size > head + tail:
            f.seek(size - tail)
            _scan(size - tail, f.read(tail))
    return hits


def scan_signatures_full(path):
    size = os.path.getsize(path)
    hits = []
    with open(path, "rb") as f:
        base = 0
        prev = b""
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            buf = prev + chunk
            for sig, kind in ((SIG_7Z, "7z"), (SIG_RAR, "rar"),
                              (ZIP_LFH, "zip-lfh")):
                i = buf.find(sig)
                while i >= 0:
                    hits.append({"kind": kind, "offset": base - len(prev) + i})
                    i = buf.find(sig, i + 1)
            base += len(chunk)
            prev = chunk[-32:]
    return hits


def detect_media(path):
    with open(path, "rb") as f:
        head = f.read(64)
    for magic, label, _off in MEDIA_MAGICS:
        if head.startswith(magic):
            if label.startswith("MP4"):
                box = head[4:8]
                if box == b"ftyp":
                    return {"type": "MP4", "detail": "ftyp=" + head[8:12].decode("latin1", "replace")}
                return None
            return {"type": label.split()[0], "detail": label}
    return None


def scan_file(path, deep=False):
    """完整结构报告。返回可 JSON 化的 dict。"""
    size = os.path.getsize(path)
    media = detect_media(path)
    archives = []

    for pos in find_eocd_candidates(path):
        info = parse_zip(path, pos)
        if info:
            archives.append(info)
            break  # 取最后一个有效 EOCD 即可（通常是唯一的）

    sig_hits = scan_signatures_full(path) if deep else scan_signatures(path)
    for hit in sig_hits:
        if hit["kind"] in ("7z", "rar"):
            # 与已识别的 zip 区域重叠的签名忽略
            if any(a["start"] <= hit["offset"] < a["end"] for a in archives):
                continue
            archives.append({
                "kind": hit["kind"],
                "start": hit["offset"],
                "end": size,
                "shift": hit["offset"],
            })

    archives.sort(key=lambda a: a["start"])
    for a in archives:
        a["size"] = max(0, a["end"] - a["start"])

    # 去掉「诱饵签名」：打包者常在压缩包结尾贴一串假 RAR / 7z 头来误导排查。
    # 判据 —— 长度很小（<128KB）且紧贴前一个压缩包的结尾（<64KB）。
    real, decoys = [], []
    for a in archives:
        if (a["kind"] in ("7z", "rar") and a["size"] < 128 * 1024 and real
                and abs(a["start"] - real[-1]["end"]) <= 64 * 1024):
            decoys.append(a)
        else:
            real.append(a)
    archives = real

    segments = []
    cursor = 0
    for a in archives:
        if a["start"] > cursor:
            kind = "media" if (cursor == 0 and media) else "filler"
            segments.append({"kind": kind, "start": cursor, "end": a["start"],
                             "size": a["start"] - cursor})
        segments.append({"kind": a["kind"], "start": a["start"], "end": a["end"],
                         "size": a["size"], "arch": a})
        cursor = max(cursor, a["end"])
    if cursor < size:
        segments.append({"kind": "filler", "start": cursor, "end": size,
                         "size": size - cursor})

    primary = None
    for a in archives:
        if a["kind"] == "zip":
            primary = a
            break
    if primary is None and archives:
        primary = archives[0]

    return {
        "path": path,
        "name": os.path.basename(path),
        "size": size,
        "media": media,
        "archives": archives,
        "segments": segments,
        "primary": primary,
        "decoys": decoys,
        "deep": deep,
    }


def to_public(report):
    """转成给前端用的精简结构（不含 13k 条目的完整列表）。"""
    def arch_view(a):
        v = {k: a[k] for k in ("kind", "start", "end", "size", "shift") if k in a}
        if a["kind"] == "zip":
            names = [e["name"] for e in a["entries"] if not e["is_dir"]][:8]
            v.update({
                "entry_count": a["entry_count"],
                "encrypted_count": a["encrypted_count"],
                "aes_count": a["aes_count"],
                "total_usize": a["total_usize"],
                "zip64": a["zip64"],
                "names": names,
            })
        return v

    segs = []
    total = report["size"] or 1
    for s in report["segments"]:
        segs.append({
            "kind": s["kind"],
            "start": s["start"],
            "end": s["end"],
            "size": s["size"],
            "pct": round(s["size"] * 100.0 / total, 3),
        })
    return {
        "path": report["path"],
        "name": report["name"],
        "size": report["size"],
        "media": report["media"],
        "segments": segs,
        "archives": [arch_view(a) for a in report["archives"]],
        "primary": arch_view(report["primary"]) if report.get("primary") else None,
        "decoys": [{"kind": d["kind"], "start": d["start"], "size": d["size"]}
                   for d in report.get("decoys", [])],
        "deep": report["deep"],
    }
