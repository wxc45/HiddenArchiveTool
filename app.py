"""
app.py —— 本地 Web 前端（Flask）

启动后自动打开浏览器。所有操作都在本机进行，不上传任何文件；
前端只提交「路径字符串」，文件读写全部由后端完成。
"""

import os
import sys
import threading
import time
import traceback
import uuid

from flask import Flask, jsonify, render_template, request

from core import extractor, passwords, probe

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False

JOBS = {}
JOBS_LOCK = threading.Lock()


class Job:
    def __init__(self, path, out_dir, pw_texts, opts):
        self.id = uuid.uuid4().hex[:12]
        self.path = path
        self.out_dir = out_dir
        self.pw_texts = pw_texts
        self.opts = opts
        self.logs = []
        self.progress = 0.0
        self.status = "running"
        self.result = None
        self.error = None
        self._cancel = False
        self._lock = threading.Lock()
        self._t0 = time.time()

    def log(self, msg, level="info"):
        with self._lock:
            self.logs.append({
                "t": round(time.time() - self._t0, 2),
                "msg": msg,
                "level": level,
            })
            if len(self.logs) > 4000:
                del self.logs[:1000]

    def set_progress(self, value):
        with self._lock:
            self.progress = round(float(value), 2)

    def cancelled(self):
        return self._cancel

    def snapshot(self, since=0):
        with self._lock:
            return {
                "id": self.id,
                "status": self.status,
                "progress": self.progress,
                "elapsed": round(time.time() - self._t0, 1),
                "path": self.path,
                "out": self.out_dir,
                "logs": self.logs[since:],
                "log_count": len(self.logs),
                "result": self.result,
                "error": self.error,
            }


def _worker(job):
    ctx = extractor.Ctx(job.log, job.set_progress, job.cancelled)
    try:
        result = extractor.run(job.path, job.out_dir, job.pw_texts, job.opts, ctx)
        job.result = result
        job.status = "done"
        job.set_progress(100)
    except extractor.Cancelled:
        job.status = "cancelled"
        job.log("已按请求停止", "warn")
    except Exception as exc:
        job.status = "error"
        job.error = str(exc)
        job.log("失败：%s" % exc, "error")
        job.log(traceback.format_exc(limit=3), "muted")


def _clean_path(raw):
    """去掉引号与多余分隔符，统一成 Windows 风格路径。"""
    if not raw:
        return ""
    p = str(raw).strip().strip('"').strip()
    if not p:
        return ""
    return os.path.normpath(p.replace("/", "\\")) if "\\" in p or ":" in p else p


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True)
    path = _clean_path(data.get("path"))
    if not path:
        return jsonify({"error": "请填写文件路径"}), 400
    if not os.path.isfile(path):
        return jsonify({"error": "文件不存在：%s" % path}), 404
    try:
        report = probe.scan_file(path, deep=bool(data.get("deep")))
        return jsonify(probe.to_public(report))
    except Exception as exc:
        return jsonify({"error": "%s: %s" % (type(exc).__name__, exc)}), 500


@app.route("/api/jobs", methods=["POST"])
def api_start():
    data = request.get_json(force=True)
    path = _clean_path(data.get("path"))
    if not os.path.isfile(path):
        return jsonify({"error": "文件不存在：%s" % path}), 404
    out_dir = _clean_path(data.get("out"))
    if not out_dir:
        stem = os.path.splitext(os.path.basename(path))[0]
        out_dir = os.path.join(os.path.dirname(path), stem + "_extracted")
    pw_texts = [ln for ln in (data.get("passwords") or "").splitlines()]
    opts = {
        "deep": bool(data.get("deep")),
        "export_repaired": bool(data.get("export_repaired")),
        "cleanup_nested": bool(data.get("cleanup_nested", True)),
        "max_depth": int(data.get("max_depth") or 3),
    }
    job = Job(path, out_dir, pw_texts, opts)
    with JOBS_LOCK:
        JOBS[job.id] = job
    threading.Thread(target=_worker, args=(job,), daemon=True).start()
    return jsonify({"id": job.id, "out": out_dir})


@app.route("/api/jobs/<job_id>")
def api_job(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "任务不存在"}), 404
    since = int(request.args.get("since") or 0)
    return jsonify(job.snapshot(since))


@app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
def api_cancel(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "任务不存在"}), 404
    job._cancel = True
    return jsonify({"ok": True})


@app.route("/api/browse", methods=["POST"])
def api_browse():
    """在本机弹出原生文件/目录选择框（服务与浏览器同一台机器时可用）。"""
    data = request.get_json(force=True)
    kind = data.get("kind", "file")
    result = {}

    def _ask():
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        try:
            if kind == "dir":
                result["path"] = filedialog.askdirectory(title="选择输出目录")
            else:
                result["path"] = filedialog.askopenfilename(
                    title="选择要解构的文件",
                    filetypes=[("所有文件", "*.*")])
        finally:
            root.destroy()

    t = threading.Thread(target=_ask)
    t.start()
    t.join(timeout=180)
    if not result.get("path"):
        return jsonify({"error": "未选择或对话框不可用，可直接粘贴路径"}), 400
    return jsonify({"path": result["path"].replace("/", "\\")})


def _pick_port(preferred):
    """端口被占用时自动往后找一个空闲的。"""
    import socket
    for p in range(preferred, preferred + 30):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return preferred


def serve(port=None):
    port = int(port or os.environ.get("HAT_PORT", "8770"))
    real = _pick_port(port)
    if real != port:
        print("[提示] 端口 %d 被占用，改用 %d" % (port, real))
    url = "http://127.0.0.1:%d" % real
    print("[启动] %s" % url)
    print("[提示] 浏览器没有自动打开的话，手动访问上面的地址；按 Ctrl+C 停止。")
    print()
    try:
        import webbrowser
        if not os.environ.get("HAT_NO_BROWSER"):
            threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    except Exception:
        pass
    app.run(host="127.0.0.1", port=real, threaded=True, debug=False)


def main():
    serve()


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()
