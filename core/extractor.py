"""
extractor.py —— 解压编排

分工：
  * ZIP    —— 走 zipkit，直接按修正后的偏移流式读取，不需要落地中间包
  * 7z/RAR —— 7z.exe 处理（Python 传中文密码实测可靠）；若压缩包不在文件开头，
              先把它截取到临时文件再交给 7z，因为 7z 的偏移也必须从 0 起算
  * 递归   —— 解完自动在输出目录里找下一层（7z/zip/rar 魔数，或「媒体+尾部 EOCD」）
"""

import os
import re
import shutil
import subprocess
import time
import zlib

from . import passwords, probe, zipkit

_7Z_CANDIDATES = [
    r"C:\Program Files\7-Zip\7z.exe",
    r"C:\Program Files (x86)\7-Zip\7z.exe",
    r"C:\Program Files\Bandizip\bz.exe",
]

MEDIA_EXT = {".mp4", ".mkv", ".avi", ".mov", ".flv", ".wmv", ".m4v",
             ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".wav", ".flac"}

# 这些虽然本质也是 ZIP，但属于「安装包/文档容器」，展开它们只会把游戏目录
# 搞乱（APK 尤其严重），因此递归时一律跳过。
CONTAINER_EXT = {".apk", ".jar", ".xpi", ".crx", ".ipa", ".deb", ".rpm", ".whl",
                 ".nupkg", ".vsix", ".aar", ".docx", ".xlsx", ".pptx", ".odt",
                 ".ods", ".odp", ".epub", ".cbz", ".kra", ".sketch", ".love"}


class Cancelled(Exception):
    pass


class Ctx:
    def __init__(self, log, progress, cancelled, span=(0.0, 100.0)):
        self._log = log
        self._progress = progress
        self._cancelled = cancelled
        self.span = span

    def log(self, msg, level="info"):
        self._log(msg, level)

    def check(self):
        if self._cancelled():
            raise Cancelled()

    def set(self, ratio):
        lo, hi = self.span
        self._progress(lo + (hi - lo) * max(0.0, min(1.0, ratio)))

    def child(self, lo, hi):
        return Ctx(self._log, self._progress, self._cancelled,
                   (self.span[0] + (self.span[1] - self.span[0]) * lo,
                    self.span[0] + (self.span[1] - self.span[0]) * hi))


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return "%.2f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024.0


def find_7z():
    for p in _7Z_CANDIDATES:
        if os.path.isfile(p):
            return p
    for name in ("7z", "7za", "7z.exe"):
        w = shutil.which(name)
        if w:
            return w
    return None


# ---------------------------------------------------------------- 结构说明

def describe(report, ctx):
    ctx.log("文件：%s（%s）" % (report["name"], human(report["size"])))
    media = report["media"]
    primary = report.get("primary")
    if primary and primary.get("kind") == "zip":
        if media and primary["start"] > 0:
            ctx.log("外壳：检测到 %s 媒体头，占用前 %s —— 压缩包被拼在它后面"
                    % (media["type"], human(primary["start"])), "warn")
        if primary["shift"]:
            ctx.log("错位：中央目录记录的位置比真实位置小 %s，标准解压器据此定位必然失败"
                    % human(primary["shift"]), "warn")
        aes = primary["aes_count"]
        ctx.log("压缩包：ZIP · %s · %d 个条目 · %s"
                % (human(primary["size"]), primary["entry_count"],
                   "AES-256 加密（%d 条）" % aes if aes else
                   ("加密（%d 条）" % primary["encrypted_count"] if primary["encrypted_count"] else "未加密")))
        ctx.log("预计解出：%s" % human(primary["total_usize"]))
    elif primary and primary["kind"] in ("7z", "rar"):
        offset = primary["start"]
        ctx.log("压缩包：%s · %s%s" % (primary["kind"].upper(), human(primary["size"]),
                                     "（位于偏移 %d，需先截取）" % offset if offset else ""))
    else:
        ctx.log("未在文件中发现可识别的压缩包结构", "warn")


# ---------------------------------------------------------------- ZIP 解包

def pick_password(enc_entries, cands, path, ctx):
    ctx.log("校验密码（共 %d 个候选，命中即停）" % len(cands))
    for cand in cands:
        ok = True
        for e in enc_entries[:4]:
            if not zipkit.check_password(e, cand["raw"], path):
                ok = False
                break
        if ok:
            ctx.log("密码命中：%s" % cand["label"], "ok")
            return cand
    return None


def extract_zip(arch, path, dest, cands, ctx):
    entries = [e for e in arch["entries"] if not e["is_dir"]]
    enc = [e for e in entries if e["encrypted"]]
    key = None
    if enc:
        key = pick_password(enc, cands, path, ctx)
        if key is None:
            tried = "、".join(sorted({c["label"].split(" · ")[0] for c in cands})) or "（空）"
            raise RuntimeError("密码未命中，已尝试编码：%s。请补充正确密码后重试" % tried)
    total = sum(e["csize"] for e in entries) or 1
    done = 0
    ok_files = 0
    bad_files = []
    out_bytes = 0
    for i, e in enumerate(entries, 1):
        ctx.check()
        target = zipkit.safe_join(dest, e["name"])
        if not target:
            continue
        os.makedirs(os.path.dirname(target) or dest, exist_ok=True)
        crc = 0
        try:
            with open(target, "wb") as w:
                for chunk in zipkit.iter_plain(e, key["raw"] if key else None, path):
                    crc = zlib.crc32(chunk, crc)
                    w.write(chunk)
                    out_bytes += len(chunk)
                    done += len(chunk)
                    ctx.set(done / total)
        except Exception as exc:
            bad_files.append((e["name"], str(exc)))
            ctx.log("解压失败：%s（%s）" % (e["name"], exc), "error")
            continue
        if (crc & 0xFFFFFFFF) != (e["crc"] & 0xFFFFFFFF):
            # 7-Zip 创建 AES 条目时会把 CRC 写成 0（表示未记录），不能当失败
            if e["crc"] == 0:
                ok_files += 1
            else:
                bad_files.append((e["name"], "CRC 校验不符"))
                ctx.log("校验不符：%s" % e["name"], "warn")
        else:
            ok_files += 1
        if i % 200 == 0:
            ctx.log("进度 %d/%d 个文件" % (i, len(entries)))
    return {"files": ok_files, "bytes": out_bytes, "bad": bad_files}


# ---------------------------------------------------------------- 7z/RAR

def _run_7z(sevenzip, args, ctx, progress=None):
    """执行 7z，实时解析百分比；返回退出码与输出。"""
    ctx.check()
    proc = subprocess.Popen([sevenzip] + args, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, bufsize=0)
    buf = b""
    last = 0.0
    while True:
        if ctx._cancelled():
            proc.kill()
            raise Cancelled()
        chunk = proc.stdout.read(256)
        if not chunk:
            break
        buf = (buf + chunk)[-4096:]
        hits = re.findall(rb"(\d{1,3})%", buf)
        if hits and progress:
            pct = int(hits[-1])
            if pct >= last:
                last = pct
                progress(pct / 100.0)
    proc.wait()
    text = buf.decode("gbk", "replace")
    return proc.returncode, text


def carve(path, start, end, dest_dir):
    tmp = os.path.join(dest_dir, ".carve_%d.tmp" % int(time.time() * 1000))
    with open(path, "rb") as f, open(tmp, "wb") as w:
        f.seek(start)
        remain = max(0, (end or os.path.getsize(path)) - start)
        while remain > 0:
            b = f.read(min(8 << 20, remain))
            if not b:
                break
            w.write(b)
            remain -= len(b)
    return tmp


def _list_7z(sevenzip, path, password_text):
    args = ["l", "-slt", "-ba"]
    if password_text is not None:
        args.append("-p" + password_text)
    proc = subprocess.run([sevenzip] + args + [path],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = proc.stdout.decode("gbk", "replace")
    if proc.returncode != 0:
        return None
    items, cur = [], {}
    for line in out.splitlines():
        if not line.strip():
            if cur.get("Path"):
                items.append(cur)
            cur = {}
            continue
        if " = " in line:
            k, v = line.split(" = ", 1)
            cur[k.strip()] = v.strip()
    if cur.get("Path"):
        items.append(cur)
    return items


def extract_foreign(kind, path, start, dest, cands, ctx):
    sevenzip = find_7z()
    if not sevenzip:
        raise RuntimeError("未找到 7-Zip，解 %s 需要它（安装后重试）" % kind.upper())
    src = path
    tmp = None
    if start and start > 0:
        ctx.log("截取压缩包：从偏移 %d 到文件末尾" % start)
        tmp = carve(path, start, os.path.getsize(path), dest)
        src = tmp
    try:
        # 先用目录列表判断头部是否加密，并挑最小的文件做密码校验
        items = _list_7z(sevenzip, src, None)
        chosen = None
        if items is not None:
            files = [it for it in items if not it.get("Folder") and it.get("Path")
                     and it.get("Path") != os.path.basename(src)]
            files.sort(key=lambda it: int(it.get("Size") or 0))
            probe_file = files[0]["Path"] if files else None
            if probe_file:
                for cand in cands:
                    rc, _ = _run_7z(sevenzip, ["t", "-p" + cand["text"], src, probe_file], ctx)
                    if rc == 0:
                        chosen = cand
                        ctx.log("密码命中：%s" % cand["label"], "ok")
                        break
        else:
            # 头部加密：只能用密码去列表，能列出即为正确
            for cand in cands:
                if _list_7z(sevenzip, src, cand["text"]) is not None:
                    chosen = cand
                    ctx.log("密码命中（头部加密）：%s" % cand["label"], "ok")
                    break

        args = ["x", "-y", "-bsp1", "-o" + dest]
        args.append("-p" + chosen["text"] if chosen else "-p")
        if chosen is None and cands:
            raise RuntimeError("密码未命中，已尝试 %d 个候选" % len(cands))
        before = {os.path.abspath(p) for p in _walk(dest)} if os.path.isdir(dest) else set()
        child = ctx.child(0.1, 1.0)
        rc, tail = _run_7z(sevenzip, args + [src], ctx, progress=lambda r: child.set(r))
        if rc not in (0, 1):
            raise RuntimeError("7-Zip 返回错误码 %d：%s" % (rc, tail[-300:].strip()))
        after = {os.path.abspath(p) for p in _walk(dest)}
        after.discard(os.path.abspath(os.path.join(dest, os.path.basename(src))))
        return {"files": len(after - before), "bytes": 0, "bad": []}
    finally:
        if tmp and os.path.exists(tmp):
            os.remove(tmp)


# ---------------------------------------------------------------- 递归

def _walk(root):
    for dirpath, _dirs, names in os.walk(root):
        for n in names:
            yield os.path.join(dirpath, n)


def triage(path):
    """快速判断文件是否值得当作压缩包处理。返回 (是否, 原因)。

    这里刻意做得便宜：只看魔数和文件尾 1MB，避免对几万个素材文件做全量扫描。
    """
    try:
        size = os.path.getsize(path)
        if size < 32:  # 只是排除空壳，真实压缩包可以很小（最小 7z 约 120 字节）
            return False, ""
        with open(path, "rb") as f:
            head = f.read(8)
        ext = os.path.splitext(path)[1].lower()
        if head.startswith(probe.SIG_7Z):
            return True, "7z"
        if head.startswith(probe.SIG_RAR):
            return True, "rar"
        if head.startswith(probe.ZIP_LFH):
            if ext in CONTAINER_EXT:
                return False, "容器格式 %s，不展开" % ext
            return True, "zip"
        if ext in CONTAINER_EXT:
            return False, ""
        if ext in MEDIA_EXT or ext in ("", ".bin", ".dat", ".tmp", ".bak", ".iso",
                                       ".img", ".zipx", ".001"):
            with open(path, "rb") as f:
                f.seek(max(0, size - (1 << 20)))
                tail = f.read()
            if b"PK\x05\x06" in tail:
                return True, "媒体外壳 + 尾部 ZIP"
        return False, ""
    except OSError:
        return False, ""


def looks_like_archive(path):
    return triage(path)[0]


def extract_one(arch, path, dest, cands, ctx):
    os.makedirs(dest, exist_ok=True)
    kind = arch["kind"]
    if kind == "zip":
        if arch["shift"]:
            ctx.log("按偏移修正 %+d 直接读取，无需生成中间压缩包" % arch["shift"])
        return extract_zip(arch, path, dest, cands, ctx)
    return extract_foreign(kind, path, arch["start"], dest, cands, ctx)


def run(src, out_dir, pw_texts, opts, ctx):
    started = time.time()
    os.makedirs(out_dir, exist_ok=True)
    report = probe.scan_file(src, deep=bool(opts.get("deep")))
    describe(report, ctx)

    cands = passwords.candidates(pw_texts)
    ctx.log("密码候选：%s" % passwords.summary(cands))

    primary = report.get("primary")
    if not primary:
        raise RuntimeError("没有找到可解压的结构。若确实是压缩包，可勾选「深度扫描」再试")
    if opts.get("export_repaired") and primary["kind"] == "zip" and primary["shift"]:
        fixed = os.path.join(os.path.dirname(src),
                             os.path.splitext(os.path.basename(src))[0] + "_repaired.zip")
        ctx.log("导出修复后的 ZIP：%s" % fixed)
        with open(src, "rb") as f, open(fixed, "wb") as w:
            f.seek(primary["start"])
            remain = primary["end"] - primary["start"]
            while remain > 0:
                b = f.read(min(8 << 20, remain))
                if not b:
                    break
                w.write(b)
                remain -= len(b)

    ctx.log("开始解第 1 层 → %s" % out_dir)
    res1 = extract_one(primary, src, out_dir, cands, ctx.child(0.0, 0.6))
    total_files = res1["files"]
    total_bytes = res1["bytes"]
    bad = list(res1["bad"])
    ctx.log("第 1 层完成：%d 个文件" % res1["files"], "ok")

    # 递归后续层
    max_depth = int(opts.get("max_depth") or 3)
    done = {os.path.abspath(src)}
    for depth in range(2, max_depth + 1):
        ctx.check()
        pending, skipped = [], 0
        for f in _walk(out_dir):
            ap = os.path.abspath(f)
            if ap in done:
                continue
            ok, why = triage(f)
            if ok:
                pending.append(f)
            elif why:
                skipped += 1
        if not pending:
            break
        if len(pending) > 100:
            ctx.log("候选过多（%d），只处理前 100 个，其余请单独解压" % len(pending), "warn")
            pending = pending[:100]
        ctx.log("发现第 %d 层候选 %d 个%s" % (depth, len(pending),
                                          "（跳过 %d 个容器格式）" % skipped if skipped else ""))
        lo = 0.6 + (depth - 2) * 0.1
        for idx, f in enumerate(pending):
            ctx.check()
            done.add(os.path.abspath(f))
            sub = probe.scan_file(f, deep=False)
            arch = sub.get("primary")
            if not arch:
                continue
            ctx.log("解第 %d 层：%s（%s）" % (depth, os.path.basename(f),
                                          human(sub["size"])), "section")
            ctx.log("→ " + os.path.dirname(f))
            try:
                r = extract_one(arch, f, os.path.dirname(f), cands,
                                ctx.child(lo, min(lo + 0.1, 0.99)))
                total_files += r["files"]
                total_bytes += r["bytes"]
                bad.extend(r["bad"])
                # 只有确实解出了内容才清理中间包，避免「解失败还把源文件删了」
                if opts.get("cleanup_nested", True) and r["files"] > 0:
                    os.remove(f)
                    ctx.log("已清理中间包：%s" % os.path.basename(f))
            except Cancelled:
                raise
            except Exception as exc:
                ctx.log("第 %d 层失败：%s（%s）" % (depth, os.path.basename(f), exc), "error")

    elapsed = time.time() - started
    ctx.set(1.0)
    ctx.log("全部完成：%d 个文件，用时 %.1f 秒" % (total_files, elapsed), "ok")
    return {
        "files": total_files,
        "bytes": total_bytes,
        "bad": bad[:50],
        "elapsed": round(elapsed, 1),
        "out": out_dir,
    }
