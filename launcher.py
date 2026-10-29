"""
launcher.py —— 启动器（给 run.bat 调用）

放在这里的原因是：cmd 对批处理文件的编码与换行非常挑剔，
中文 + LF 换行会直接把脚本解析坏掉。所以 .bat 只保留纯 ASCII 的最小逻辑，
所有中文提示、依赖检查都交给 Python 输出（Python 走 WriteConsoleW，中文稳定）。
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REQUIRED = [("flask", "flask"), ("Crypto", "pycryptodome")]


def has_dep():
    missing = []
    for mod, pkg in REQUIRED:
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    return missing


def pip_install(pkgs, mirror=None):
    cmd = [sys.executable, "-m", "pip", "install",
           "--disable-pip-version-check", "-q"] + pkgs
    if mirror:
        cmd += ["-i", mirror]
    print("  执行：" + " ".join(cmd[2:]))
    return subprocess.call(cmd) == 0


def ensure_deps():
    missing = has_dep()
    if not missing:
        return True
    print("[依赖] 缺少：%s，正在自动安装…" % "、".join(missing))
    if pip_install(missing):
        print("[依赖] 安装完成")
        return not has_dep()
    print("[依赖] 默认源失败，尝试国内镜像…")
    if pip_install(missing, "https://pypi.tuna.tsinghua.edu.cn/simple"):
        print("[依赖] 安装完成（镜像）")
        return not has_dep()
    print("[依赖] 安装失败。请手动执行：")
    print("       %s -m pip install -r requirements.txt" % sys.executable)
    return False


def check_7zip():
    try:
        from core import extractor
        path = extractor.find_7z()
    except Exception:
        path = None
    if path:
        print("[环境] 7-Zip：%s" % path)
    else:
        print("[环境] 未检测到 7-Zip —— 只能解 ZIP，解不了 .7z / .rar 层。")
        print("       下载：https://www.7-zip.org/  （装完重新双击本文件即可）")


def main():
    os.chdir(HERE)
    sys.path.insert(0, HERE)

    print("=" * 60)
    print("  隐包解构器  HiddenArchiveTool")
    print("  剥媒体外壳 / 修偏移错位 / 自动识别密码编码 / 递归解多层")
    print("=" * 60)
    print("[环境] Python %s" % sys.version.split()[0])
    print("[环境] 解释器 %s" % sys.executable)

    if not ensure_deps():
        print()
        input("按回车键退出…")
        return 1

    check_7zip()

    import app
    try:
        app.serve()
    except KeyboardInterrupt:
        print("\n已停止。")
    except OSError as exc:
        print("\n[错误] 启动失败：%s" % exc)
        print("       如果提示端口被占用，可设置环境变量 HAT_PORT 换一个端口。")
        input("按回车键退出…")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
