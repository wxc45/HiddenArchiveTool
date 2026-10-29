"""
passwords.py —— 密码候选生成

这类资源的翻车点几乎都是编码，而不是密码本身写错：
同一句「某不知名网友分享」，Bandizip 可能按 GBK 送进算法，7-Zip 按 UTF-8，
解压器与打包器的编码不一致，校验值天然对不上，于是永远提示密码错误。

另外网盘转贴时常见「乱码密码」——UTF-8 字节被 GBK 误读后的样子
（例如 鏌愪笉鐭ュ悕缃戝弸鍒嗕韩）。这里把乱码反向修复也一并作为候选。
"""

ENCODINGS = [
    ("UTF-8", "utf-8"),
    ("GBK", "gbk"),
    ("GB18030", "gb18030"),
    ("UTF-16LE", "utf-16-le"),
    ("Latin1", "latin1"),
]

# 常见平台在「没有密码」时的占位输入
EMPTY_TOKENS = {"", "无", "none", "null", "-"}


def _repairs(text: str):
    """把可能的乱码字符串还原成原话，返回若干个变体。"""
    out = []
    # UTF-8 字节被 GBK / GB18030 误读  ->  还原
    for enc in ("gbk", "gb18030", "cp936"):
        try:
            fixed = text.encode(enc, "strict").decode("utf-8", "strict")
            if fixed and fixed != text:
                out.append(fixed)
        except Exception:
            pass
    # GBK 字节被 UTF-8 / Latin1 误读  ->  还原
    for enc in ("latin1", "cp1252"):
        try:
            fixed = text.encode(enc, "ignore").decode("gbk", "strict")
            if fixed and fixed != text:
                out.append(fixed)
        except Exception:
            pass
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def candidates(user_texts):
    """user_texts: 用户输入的密码（每行一个）。产出 [{label, text, raw}]，去重保序。"""
    result = []
    seen = set()

    def add(label, text, enc):
        try:
            raw = text.encode(enc)
        except Exception:
            return
        if raw in seen:
            return
        seen.add(raw)
        result.append({"label": label, "text": text, "raw": raw})

    for text in user_texts:
        text = (text or "").strip("\r\n")
        if text in EMPTY_TOKENS:
            continue
        bases = [(text, "原样")] + [(r, "乱码修复") for r in _repairs(text)]
        for base, note in bases:
            for name, enc in ENCODINGS:
                label = "%s · %s" % (name, note) if note == "原样" else "%s · %s" % (name, note)
                add(label, base, enc)
    return result


def summary(cands):
    if not cands:
        return "无密码"
    names = sorted({c["label"].split(" · ")[0] for c in cands})
    return "%d 个候选（%s）" % (len(cands), "/".join(names))
