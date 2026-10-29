const $ = (id) => document.getElementById(id);

let state = {
  report: null,
  jobId: null,
  since: 0,
  timer: null,
  running: false,
};

/* ---------------- 工具 ---------------- */
function human(n) {
  if (n === undefined || n === null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v.toFixed(0) : v.toFixed(2)) + " " + u[i];
}
function num(n) {
  return (n === undefined || n === null) ? "—" : n.toLocaleString("zh-CN");
}
function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}
async function api(url, body) {
  const r = await fetch(url, {
    method: body === undefined ? "GET" : "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
  return data;
}

/* ---------------- 扫描 ---------------- */
async function scan() {
  const path = $("path").value.trim();
  if (!path) { $("path").focus(); return; }
  const btn = $("btnScan");
  btn.disabled = true; btn.textContent = "扫描中…";
  try {
    const rep = await api("/api/scan", { path, deep: $("deep").checked });
    state.report = rep;
    render(rep);
    $("cardStruct").classList.remove("hidden");
    $("cardRun").classList.remove("hidden");
    $("btnStart").disabled = !rep.primary;
    if (!rep.primary) {
      $("btnStart").disabled = true;
    }
  } catch (e) {
    renderError(e.message);
    $("cardStruct").classList.remove("hidden");
    $("btnStart").disabled = true;
  } finally {
    btn.disabled = false; btn.textContent = "扫描结构";
  }
}

function render(rep) {
  // 分段条
  const bar = $("segbar");
  bar.innerHTML = "";
  const legend = [];
  const labelOf = { media: "媒体外壳", zip: "ZIP", "7z": "7Z", rar: "RAR", filler: "残留" };
  rep.segments.forEach((s, i) => {
    const d = document.createElement("div");
    d.className = "seg " + (s.kind === "zip" ? "zip" : s.kind === "7z" ? "zip7" : s.kind);
    d.style.width = `max(${s.pct}%, 7px)`;
    d.title = `${labelOf[s.kind] || s.kind}  偏移 ${num(s.start)} – ${num(s.end)}  (${human(s.size)})`;
    d.textContent = s.pct > 9 ? (labelOf[s.kind] || s.kind) : "";
    bar.appendChild(d);
    if (!legend.find((x) => x.kind === s.kind)) legend.push(s);
  });
  $("legend").innerHTML = legend.map((s) =>
    `<span><i class="${s.kind === "zip" ? "seg zip" : "seg " + s.kind}" style="width:10px;height:10px;border-radius:3px;display:inline-block"></i>
     ${labelOf[s.kind] || s.kind} · ${human(s.size)}</span>`).join("");

  // 指标
  const p = rep.primary;
  const media = rep.media ? `${rep.media.type} <small>${esc(rep.media.detail || "")}</small>` : "无";
  let rows = [
    ["文件大小", human(rep.size)],
    ["外层", media],
    ["压缩包", p ? `${p.kind.toUpperCase()} <small>${human(p.size)}</small>` : "未发现"],
    ["偏移修正", p && p.shift ? `<span style="color:#b45309">+${num(p.shift)}</span>` : "无需"],
  ];
  if (p && p.entry_count !== undefined) {
    rows.push(["条目数", num(p.entry_count)]);
    rows.push(["加密", p.aes_count ? `AES-256 <small>${num(p.aes_count)} 条</small>`
      : (p.encrypted_count ? `ZipCrypto <small>${num(p.encrypted_count)} 条</small>` : "无")]);
    rows.push(["预计解出", human(p.total_usize)]);
    rows.push(["ZIP64", p.zip64 ? "是" : "否"]);
  }
  $("metrics").innerHTML = rows.map(([k, v]) =>
    `<div class="kv"><div class="k">${k}</div><div class="v">${v}</div></div>`).join("");

  // 结论
  const notes = [];
  if (!p) {
    notes.push(`<div class="note err">没有找到可识别的压缩包结构。可以勾选「深度扫描」再试一次；
      或者确认这个文件是不是已经是被解压过的内容。</div>`);
  } else {
    if (p.shift) {
      notes.push(`<div class="note warn"><b>偏移错位 ${num(p.shift)} 字节</b> ——
        有人在压缩包前面拼了 ${human(p.shift)} 的 ${rep.media ? rep.media.type : "数据"}。
        ZIP 内部记录的位置比真实位置小这么多，所以 Bandizip / WinRAR / 7-Zip 都会报
        「不是压缩包」或「文件损坏」。本工具会按修正后的偏移直接读取，不需要你先手工切割文件。</div>`);
    }
    if (!p.shift && rep.media) {
      notes.push(`<div class="note warn">文件开头是 ${rep.media.type}，压缩包在后面且偏移正常，
        标准工具应当能直接打开；若仍失败，多半是密码编码问题。</div>`);
    }
    if (p.shift === 0 && !rep.media && p.kind === "zip") {
      notes.push(`<div class="note ok">标准 ZIP 结构，偏移正常。可以直接解压。</div>`);
    }
    if (p.names && p.names.length) {
      notes.push(`<div class="note ok">包内示例：<b>${esc(p.names.slice(0, 4).join("　·　"))}</b>
        ${p.entry_count > 4 ? `　…共 ${num(p.entry_count)} 项` : ""}</div>`);
    }
  }
  $("notes").innerHTML = notes.join("");
}

function renderError(msg) {
  $("segbar").innerHTML = "";
  $("legend").innerHTML = "";
  $("metrics").innerHTML = "";
  $("notes").innerHTML = `<div class="note err">${esc(msg)}</div>`;
}

/* ---------------- 执行 ---------------- */
async function start() {
  const path = $("path").value.trim();
  if (!path) return;
  $("cardProgress").classList.remove("hidden");
  $("log").innerHTML = "";
  state.since = 0;
  state.running = true;
  $("btnStart").disabled = true;
  $("btnStart").classList.add("spin");
  $("btnStart").textContent = "执行中";
  $("btnCancel").disabled = false;
  setBar(0, "running");
  $("statusText").textContent = "准备中…";

  try {
    const res = await api("/api/jobs", {
      path,
      out: $("out").value.trim(),
      passwords: $("pw").value,
      deep: $("deep").checked,
      export_repaired: $("exportRepaired").checked,
      cleanup_nested: $("cleanNested").checked,
      max_depth: parseInt($("maxDepth").value || "3", 10),
    });
    state.jobId = res.id;
    if (!$("out").value.trim()) $("out").value = res.out;
    // 把任务号写进地址栏，刷新页面还能接回这次任务
    try { history.replaceState(null, "", "?job=" + res.id); } catch (e) { }
    poll();
  } catch (e) {
    appendLog({ t: 0, msg: e.message, level: "error" });
    finish("error", e.message);
  }
}

function poll() {
  clearTimeout(state.timer);
  state.timer = setTimeout(async () => {
    if (!state.jobId) return;
    try {
      const j = await api(`/api/jobs/${state.jobId}?since=${state.since}`);
      j.logs.forEach(appendLog);
      state.since = j.log_count;
      $("pct").textContent = Math.round(j.progress) + "%";
      $("bar").firstElementChild.style.width = j.progress + "%";
      $("statusText").textContent = j.status === "running"
        ? `执行中… ${j.elapsed}s` : `${mapStatus(j.status)} · ${j.elapsed}s`;
      if (j.status === "running") {
        poll();
      } else {
        finish(j.status, j.error, j.result);
      }
    } catch (e) {
      finish("error", e.message);
    }
  }, 420);
}

function mapStatus(s) {
  return { done: "完成", error: "失败", cancelled: "已停止" }[s] || s;
}

function finish(status, error, result) {
  state.running = false;
  clearTimeout(state.timer);
  $("btnStart").disabled = false;
  $("btnStart").classList.remove("spin");
  $("btnStart").textContent = "开始解压";
  $("btnCancel").disabled = true;
  if (status === "done") {
    setBar(100, "done");
    $("pct").textContent = "100%";
    const r = result || {};
    $("statusText").innerHTML = `完成 · ${num(r.files)} 个文件 · ${r.elapsed}s`;
    if (r.out) $("out").value = r.out;
  } else if (status === "error") {
    setBar(100, "fail");
    $("statusText").textContent = "失败：" + (error || "未知错误");
  } else {
    $("statusText").textContent = "已停止";
  }
}

function setBar(pct, cls) {
  const bar = $("bar");
  bar.className = "bar" + (cls ? " " + cls : "");
  bar.firstElementChild.style.width = pct + "%";
}

function appendLog(l) {
  const box = $("log");
  if (box.querySelector(".empty")) box.innerHTML = "";
  const d = document.createElement("div");
  d.className = "line";
  const lvl = l.level && l.level !== "info" ? l.level : "";
  d.innerHTML = `<span class="t">${String(l.t).padStart(6, " ")}s</span><span class="${lvl}">${esc(l.msg)}</span>`;
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
  box.appendChild(d);
  if (atBottom) box.scrollTop = box.scrollHeight;
}

async function cancel() {
  if (!state.jobId) return;
  try { await api(`/api/jobs/${state.jobId}/cancel`, {}); } catch (e) { /* ignore */ }
  $("btnCancel").disabled = true;
}

async function browse(kind) {
  try {
    const r = await api("/api/browse", { kind });
    if (kind === "dir") $("out").value = r.path;
    else { $("path").value = r.path; scan(); }
  } catch (e) {
    appendNote(e.message);
  }
}

function appendNote(msg) {
  $("cardStruct").classList.remove("hidden");
  const div = document.createElement("div");
  div.className = "note warn";
  div.textContent = msg;
  $("notes").appendChild(div);
}

/* ---------------- 事件 ---------------- */
$("btnScan").addEventListener("click", scan);
$("btnStart").addEventListener("click", start);
$("btnCancel").addEventListener("click", cancel);
$("btnBrowse").addEventListener("click", () => browse("file"));
$("btnOut").addEventListener("click", () => browse("dir"));
$("path").addEventListener("keydown", (e) => { if (e.key === "Enter") scan(); });
$("deep").addEventListener("change", () => { if (state.report) scan(); });

/* 支持 ?path=xxx 直接带文件打开（命令行 / 快捷方式调用） */
(function initFromQuery() {
  const q = new URLSearchParams(location.search);

  // ?job=xxx 附着到已有任务：刷新页面不丢日志，也便于分享进度
  const job = q.get("job");
  if (job) {
    state.jobId = job;
    $("cardProgress").classList.remove("hidden");
    $("btnCancel").disabled = false;
    (async () => {
      try {
        const j = await api("/api/jobs/" + job);
        if (j.path) {
          $("path").value = j.path;
          $("out").value = j.out || "";
          scan();               // 还原结构/设置卡片
        }
      } catch (e) { }
      poll();
    })();
    return;
  }

  const p = q.get("path");
  if (!p) return;
  $("path").value = p;
  if (q.get("pw")) $("pw").value = q.get("pw");
  scan().then(() => {
    if (q.get("auto") === "1") start();
  });
})();
