"""
冒烟测试：不依赖 7-Zip、不依赖网络，可被 pytest 收集，也可直接运行

    python tests/test_smoke.py

覆盖的核心断言：
  1. 「媒体外壳 + 尾部 ZIP」能被识别，且错位量/起止偏移算得准
  2. 按修正偏移能读出与原始内容逐字节一致的文件
  3. 递归解压能把内层 ZIP 也解出来
  4. 乱码密码能被还原成正确字节
  5. 容器格式（APK 等）不会被误当作待解压的层
"""

import io
import os
import random
import shutil
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import extractor, passwords, probe, zipkit  # noqa: E402

MEDIA_HEAD = b"\x00\x00\x00\x20ftypisom"

PAYLOAD = {
    "hello.txt": "你好，隐包解构器".encode("utf-8") * 50,
    "sub/data.bin": bytes(range(256)) * 40,
}


def _mk_zip(path, entries):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def _disguise(media_path, zip_path, prefix_size=2 << 20):
    """造一个「媒体外壳 + ZIP」的伪装文件，返回外壳长度。"""
    rnd = random.Random(20261029)
    head = MEDIA_HEAD + bytes(rnd.getrandbits(8) for _ in range(prefix_size))
    with open(media_path, "wb") as w:
        w.write(head)
        with open(zip_path, "rb") as f:
            shutil.copyfileobj(f, w)
    return len(head)


def test_shift_and_extract():
    tmp = tempfile.mkdtemp(prefix="hat_test_")
    try:
        inner = _mk_zip(os.path.join(tmp, "plain.zip"), PAYLOAD)
        media = os.path.join(tmp, "movie.mp4")
        prefix = _disguise(media, inner)

        rep = probe.scan_file(media)
        arch = rep["primary"]
        assert arch is not None, "未识别出 ZIP"
        assert arch["shift"] == prefix, "偏移修正量不对：%r != %r" % (arch["shift"], prefix)
        assert arch["start"] == prefix
        assert arch["end"] == os.path.getsize(media)
        assert arch["entry_count"] == len(PAYLOAD)
        assert rep["media"]["type"] == "MP4"

        # 逐条目读出来对比
        for e in arch["entries"]:
            if e["is_dir"]:
                continue
            data = b"".join(zipkit.iter_plain(e, None, media))
            assert data == PAYLOAD[e["name"]], "内容不一致：%s" % e["name"]

        # 端到端解压
        out = os.path.join(tmp, "out")
        ctx = extractor.Ctx(lambda *a, **k: None, lambda *a, **k: None, lambda: False)
        res = extractor.run(media, out, [], {"max_depth": 2}, ctx)
        assert res["files"] >= len(PAYLOAD)
        with open(os.path.join(out, "hello.txt"), "rb") as f:
            assert f.read() == PAYLOAD["hello.txt"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_recursive_layer():
    """ZIP 里再套一层 ZIP，递归应当解开。"""
    tmp = tempfile.mkdtemp(prefix="hat_test_")
    try:
        inner = _mk_zip(os.path.join(tmp, "deep.zip"), PAYLOAD)
        outer = _mk_zip(os.path.join(tmp, "outer.zip"),
                        {"deep.zip": open(inner, "rb").read()})
        media = os.path.join(tmp, "clip.mkv")
        _disguise(media, outer)

        out = os.path.join(tmp, "out")
        logs = []
        ctx = extractor.Ctx(lambda m, l="info": logs.append(m), lambda *a: None,
                            lambda: False)
        res = extractor.run(media, out, [], {"max_depth": 3, "cleanup_nested": True}, ctx)
        assert os.path.exists(os.path.join(out, "hello.txt")), "\n".join(logs)
        assert not os.path.exists(os.path.join(out, "deep.zip")), "中间包未清理"
        assert res["bad"] == []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_password_encoding_candidates():
    """乱码密码应当被还原成正确字节；多种编码都要能生成。"""
    mojibake = "鏌愪笉鐭ュ悕缃戝弸鍒嗕韩"          # UTF-8 被 GBK 误读的样子
    plain = "某不知名网友分享"
    raws = [c["raw"] for c in passwords.candidates([mojibake])]
    assert plain.encode("utf-8") in raws, "乱码未能还原"
    raws2 = [c["raw"] for c in passwords.candidates([plain])]
    assert plain.encode("utf-8") in raws2
    assert plain.encode("gbk") in raws2


def test_triage_skips_containers():
    tmp = tempfile.mkdtemp(prefix="hat_test_")
    try:
        apk = _mk_zip(os.path.join(tmp, "app.apk"), {"AndroidManifest.xml": b"<x/>"})
        ok, why = extractor.triage(apk)
        assert not ok and "容器" in why, (ok, why)

        z = _mk_zip(os.path.join(tmp, "normal.zip"), {"a.txt": b"a"})
        ok2, _ = extractor.triage(z)
        assert ok2

        media = os.path.join(tmp, "x.mp4")
        _disguise(media, z)
        ok3, why3 = extractor.triage(media)
        assert ok3 and "ZIP" in why3, (ok3, why3)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_path_traversal_blocked():
    dest = os.path.join(tempfile.gettempdir(), "dest")
    # 无论用 / 还是 \ 分隔，都不允许跳出 dest
    for evil in ("../../etc/passwd", "..\\..\\win.ini"):
        got = zipkit.safe_join(dest, evil)
        assert got is not None
        assert os.path.abspath(got).startswith(os.path.abspath(dest) + os.sep), got
    assert zipkit.safe_join(dest, "../..") is None


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS  %s" % name)
            except AssertionError as exc:
                failed += 1
                print("FAIL  %s -> %s" % (name, exc))
            except Exception as exc:  # noqa: BLE001
                failed += 1
                print("ERROR %s -> %s: %s" % (name, type(exc).__name__, exc))
    print("\n%s" % ("全部通过" if not failed else "%d 项失败" % failed))
    sys.exit(1 if failed else 0)
