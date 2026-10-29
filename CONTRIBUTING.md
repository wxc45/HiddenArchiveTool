# 贡献指南

感谢你愿意改进这个工具。它是一个**只做本地文件结构解析**的小项目，
所以下面几条约定比其他项目更重要一些。

---

## 可以贡献什么

- **新的伪装/嵌套形态**：更多外壳类型、更多压缩格式、特殊的分卷结构
- **解析正确性**：ZIP/ZIP64、AES、ZipCrypto 的边界情况
- **密码编码**：其他语言/平台下出现的编码差异
- **界面与文案**：错误提示说得更清楚，比多一个功能更有价值
- **文档**：真实的排错记录，比漂亮的介绍更值钱

---

## 开发环境

```bash
git clone https://github.com/wxc45/HiddenArchiveTool.git
cd HiddenArchiveTool
python -m venv .venv
# Windows: .venv\Scripts\activate / macOS、Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py           # 起界面，默认 http://127.0.0.1:8770
python tests/test_smoke.py
```

解 `.7z` / `.rar` 需要本机装 [7-Zip](https://www.7-zip.org/)。测试用例**不依赖** 7-Zip。

---

## 结构分工

| 文件 | 职责 | 改动注意 |
|---|---|---|
| `core/probe.py` | 只读结构：EOCD/ZIP64 解析、偏移错位反推、诱饵识别 | 不要在这里做任何解压 |
| `core/zipkit.py` | 按修正偏移读取条目、AES/ZipCrypto 解密、流式解压 | 必须保持流式，不能整文件读入内存 |
| `core/passwords.py` | 密码候选生成（多编码 + 乱码还原） | 候选去重靠原始字节，不靠字符串 |
| `core/extractor.py` | 编排：ZIP 自研、7z/RAR 走 7-Zip、递归、清理 | 递归必须跳过容器格式，删文件仅在解出内容后 |
| `app.py` | Flask 路由、任务线程、进度与日志 | 任务线程与请求线程共享状态要加锁 |
| `static/`、`templates/` | 前端，原生 JS，无构建步骤 | 不要引入前端框架或构建链 |

**硬性要求**

1. **不新增重依赖**。启动器要保持「只要 Python + flask + pycryptodome」就能跑。
2. **所有落盘路径必须走 `zipkit.safe_join`**，防止压缩包里的 `../` 穿越。
3. **大文件必须流式处理**。测试基线：3.4 GB 的 AES 条目不应整读进内存。
4. **不要删除用户的文件**，除非确认解压成功。清理中间包也有同样前提。
5. 日志与注释保持中文，术语（如 `shift`、`pv`、`EOCD`）保留英文原词。

---

## 测试

```bash
python tests/test_smoke.py     # 也可以 pytest tests/
```

提交解析相关的改动时，请附一个**合成样本**的测试：

- 用 `zipfile` / 字节拼接现造文件（见 `tests/test_smoke.py` 里的 `_disguise`）
- 断言偏移量、条目数、解出内容逐字节一致
- 测试必须能在 Ubuntu 与 Windows 上同时通过（CI 会跑）

---

## 提交规范

用 Conventional Commits，中文描述即可：

```
feat(probe): 识别 7z 头部被截断的情况
fix(zipkit): CRC 为 0 时不再误报校验失败
docs: 补充 Windows 批处理换行的坑
test: 增加 ZipCrypto 大文件用例
```

一个提交只做一件事。修 bug 时，如果方便，把「修复前的错误现象」写进提交信息正文。

---

## 提 PR

1. Fork → 从 `main` 拉分支：`git checkout -b fix/aes-crc`
2. 改完跑 `python tests/test_smoke.py`，确保全过
3. PR 描述里写清三件事：**问题现象、根因、验证方式**
4. 有界面改动的话附一张截图

---

## 报 Bug 时请附上

1. 文件结构（界面「扫描结构」的输出，或日志前几行）
2. 完整错误日志
3. 系统版本、Python 版本、7-Zip 版本（如果涉及）
4. 复现这一现象的最小步骤

---

## ⚠️ 请注意

**不要上传、链接或提交任何受版权保护的资源文件**（视频、游戏、破解包等）。
需要复现时请用合成文件，或只提供结构信息（偏移量、条目名、加密方式）。
涉及侵权内容的 Issue 会被直接关闭。
