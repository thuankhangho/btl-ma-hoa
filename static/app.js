// Giao diện: gọi API Flask, không làm phép toán mật mã nào ở trình duyệt.
const $ = (id) => document.getElementById(id);
const state = { keys: [], file: null, signed: null, signedName: "", sigJson: "", verBlob: null };

const fmtSize = (n) => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(2) + " MB";
const shorten = (s, n = 64) => s.length > n * 2 + 1 ? s.slice(0, n) + "…" + s.slice(-n) : s;

async function api(url, opts = {}) {
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({ error: "Phản hồi không hợp lệ từ máy chủ" }));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

/* ---------------- Khóa ---------------- */
const ALG_INFO = JSON.parse(document.getElementById("algInfo").textContent);

function setTab(which) {
  const use = which === "use";
  $("tabUse").classList.toggle("on", use);
  $("tabNew").classList.toggle("on", !use);
  $("tabUse").setAttribute("aria-selected", use);
  $("tabNew").setAttribute("aria-selected", !use);
  $("panelUse").hidden = !use;
  $("panelNew").hidden = use;
}

function showAlgDesc() {
  const a = ALG_INFO[$("alg").value];
  if (a) $("algDesc").textContent = `${a.name}: dựa trên bài toán ${a.problem}; ${a.note}.`;
}

function showKey() {
  const k = state.keys.find((x) => x.key_id === $("keySel").value);
  $("keyCard").hidden = !k;
  if (!k) return;
  $("keyOwner").textContent = k.owner || "(không tên)";
  $("fp").textContent = k.fingerprint;
  $("pubPem").value = k.pem;
  $("keyAlgPill").textContent = k.label;
  $("algNote").textContent = `${k.name}: bài toán khó ${k.problem}; ${k.note}. Khóa công khai ${k.spki_bytes} byte.`;
  $("certInfo").textContent = k.cert
    ? `do ${k.cert.issuer} cấp · serial ${k.cert.serial} · hiệu lực đến ${k.cert.not_after.slice(0, 10)}`
    : "(khóa này chưa có chứng chỉ)";
  $("revokeBtn").disabled = !k.cert;
  if (k.owner) $("signer").value = k.owner;   // tên người ký khớp chủ thể chứng chỉ
}

async function loadCA() {
  try {
    const ca = await api("/api/ca");
    $("caName").textContent = ca.name;
    $("caFp").textContent = ca.fingerprint.slice(0, 23) + "…";
    state.revoked = ca.revoked;
  } catch (e) { /* bỏ qua */ }
}

async function revokeCurrent() {
  const k = state.keys.find((x) => x.key_id === $("keySel").value);
  if (!k || !k.cert) return;
  await api("/api/revoke", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ serial: k.cert.serial }) });
  $("revokeBtn").textContent = `Đã thu hồi serial ${k.cert.serial}. Xác minh lại để thấy kết quả.`;
  $("revokeBtn").disabled = true;
  await loadCA();
  if (state.verBlob) doVerify();
}

async function loadKeys(selectId) {
  state.keys = await api("/api/keys");
  $("keySel").innerHTML = "";
  for (const k of state.keys) {
    const o = document.createElement("option");
    o.value = k.key_id;
    o.textContent = `${k.owner || "(không tên)"} — ${k.name} — tạo lúc ${k.created.replace("T", " ")}`;
    $("keySel").appendChild(o);
  }
  const n = state.keys.length;
  $("keyCount").textContent = n ? `(${n})` : "";
  $("noKeys").hidden = n > 0;
  $("keySel").hidden = n === 0;
  $("tabUse").disabled = n === 0;
  if (selectId) $("keySel").value = selectId;
  showKey();
  if (n === 0) setTab("new");
}

async function genKey() {
  $("genKey").disabled = true;
  const alg = $("alg").value;
  const hints = {
    "RSA-PSS": "Đang sinh 2 số nguyên tố 1024 bit bằng Miller-Rabin…",
    "DSA": "Đang sinh khóa (lần đầu phải sinh tham số p 2048 bit, q 256 bit: có thể mất 5–30 giây)…",
  };
  $("keyBusy").textContent = hints[alg] || "Đang sinh khóa và xin CA cấp chứng chỉ…";
  try {
    const owner = $("owner").value.trim() || "(không tên)";
    const k = await api("/api/keys", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ alg, owner }) });
    await loadKeys(k.key_id);
    $("keyBusy").textContent = "";
    setTab("use");
    $("keyStatus").hidden = false;
    $("keyStatus").textContent = `✓ Đã tạo khóa ${k.label} cho “${k.owner}” trong ${k.elapsed_ms} ms và chọn sẵn để ký.`;
  } catch (e) {
    $("keyBusy").textContent = "Lỗi: " + e.message;
  }
  $("genKey").disabled = false;
}

/* ---------------- Ký ---------------- */
function setSignFile(file) {
  state.file = file;
  $("signName").textContent = file.name;
  $("signMeta").textContent = fmtSize(file.size);
  $("signOut").hidden = true;
}

function addStep(listId, title, value) {
  const li = document.createElement("li");
  const d = document.createElement("div");
  const t = document.createElement("div");
  t.textContent = title;
  d.appendChild(t);
  if (value) {
    const v = document.createElement("div");
    v.className = "v";
    v.textContent = shorten(String(value));
    d.appendChild(v);
  }
  li.appendChild(d);
  $(listId).appendChild(li);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

async function doSign() {
  if (!state.file || !$("keySel").value) return;
  $("signBtn").disabled = true;
  $("signBusy").textContent = "Máy chủ đang băm và ký…";
  $("signSteps").innerHTML = "";
  const fd = new FormData();
  fd.append("file", state.file);
  fd.append("key_id", $("keySel").value);
  fd.append("signer", $("signer").value);
  fd.append("reason", $("reason").value);
  try {
    const r = await api("/api/sign", { method: "POST", body: fd });
    for (const [t, v] of r.steps) addStep("signSteps", t, v);
    state.signed = b64ToBytes(r.signed_b64);
    state.signedName = r.filename;
    state.sigJson = JSON.stringify(r.sig_json, null, 2);
    $("signOut").hidden = false;
    $("useSigned").disabled = false;
    $("useTampered").disabled = false;
    $("dlNote").textContent = r.zip_warning
      ? "Định dạng ZIP có thể báo lỗi khi mở file đã nối chữ ký. Hãy dùng chữ ký rời (.json) cho loại file này." : "";
    $("signBusy").textContent = `Xong trong ${r.elapsed_ms} ms.`;
  } catch (e) {
    $("signBusy").textContent = "Lỗi: " + e.message;
  }
  $("signBtn").disabled = false;
}

function download(name, data) {
  const url = URL.createObjectURL(new Blob([data]));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

/* ---------------- Xác minh ---------------- */
function setVerFile(name, blob) {
  state.verBlob = blob;
  state.verName = name;
  $("verName").textContent = name;
  $("verMeta").textContent = fmtSize(blob.size);
  $("verBtn").disabled = false;
  $("verOut").hidden = true;
}

const VERDICTS = {
  valid: ["ok", "Chữ ký hợp lệ", "Nội dung nguyên vẹn; danh tính người ký được xác thực qua chứng chỉ CA hoặc dấu vân tay tin cậy."],
  untrusted: ["warn", "Toàn vẹn, nhưng chưa xác thực danh tính", "Nội dung chưa bị sửa, nhưng file không có chứng chỉ hợp lệ và chưa đối chiếu dấu vân tay."],
  invalid: ["bad", "Chữ ký không hợp lệ", "Xem các dòng ✗ bên dưới: nội dung bị sửa, chữ ký sai, chứng chỉ không hợp lệ/bị thu hồi, hoặc khóa không khớp."],
  unsigned: ["bad", "Không tìm thấy chữ ký", "File này không chứa khối %DSIG-BEGIN … %DSIG-END."],
};

async function doVerify() {
  if (!state.verBlob) return;
  $("verBtn").disabled = true;
  $("verBusy").textContent = "Máy chủ đang xác minh…";
  const fd = new FormData();
  fd.append("file", state.verBlob, state.verName);
  fd.append("trusted_fp", $("expectFp").value);
  try {
    const r = await api("/api/verify", { method: "POST", body: fd });
    $("verSteps").innerHTML = "";
    $("checks").innerHTML = "";
    $("verOut").hidden = false;
    const [cls, title, sub] = VERDICTS[r.status];
    const v = $("verdict");
    v.className = "verdict " + cls;
    v.textContent = title;
    const small = document.createElement("small");
    small.textContent = sub;
    v.appendChild(small);
    for (const c of r.checks) {
      const row = document.createElement("div");
      const icon = document.createElement("span");
      icon.textContent = c.ok === true ? "✓" : c.ok === false ? "✗" : "!";
      icon.style.color = c.ok === true ? "var(--ok)" : c.ok === false ? "var(--bad)" : "var(--warn)";
      const text = document.createElement("span");
      text.textContent = c.text;
      row.append(icon, text);
      $("checks").appendChild(row);
    }
    for (const [k, val] of r.details) addStep("verSteps", k, val);
    $("verBusy").textContent = `Xong trong ${r.elapsed_ms} ms.`;
  } catch (e) {
    $("verBusy").textContent = "Lỗi: " + e.message;
  }
  $("verBtn").disabled = false;
}

function tamperedCopy() {
  const t = state.signed.slice();
  const marker = new TextEncoder().encode("\n%DSIG-BEGIN ");
  let off = t.length;
  outer: for (let i = t.length - marker.length; i >= 0; i--) {
    for (let j = 0; j < marker.length; j++) if (t[i + j] !== marker[j]) continue outer;
    off = i;
    break;
  }
  const pos = Math.floor(off / 2);
  t[pos] ^= 0x01;   // lật 1 bit trong phần nội dung đã ký
  return [pos, t];
}

/* ---------------- Sự kiện ---------------- */
function dragAndDrop(zone, cb) {
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("over");
    const f = e.dataTransfer.files[0];
    if (f) cb(f);
  });
}

const SAMPLE = `HOP DONG MAU / SAMPLE CONTRACT
So: 2026/HD-DEMO

Ben A: Cong ty ABC
Ben B: Nguyen Van A

Dieu 1. Ben B cung cap dich vu tu van an toan thong tin.
Dieu 2. Gia tri hop dong: 100.000.000 VND.
Dieu 3. Hop dong co hieu luc ke tu ngay ky.
`;

$("keySel").onchange = () => { $("keyStatus").hidden = true; showKey(); };
$("tabUse").onclick = () => setTab("use");
$("tabNew").onclick = () => setTab("new");
$("alg").onchange = showAlgDesc;
showAlgDesc();
$("revokeBtn").onclick = revokeCurrent;
$("genKey").onclick = genKey;
$("copyPem").onclick = () => navigator.clipboard.writeText($("pubPem").value).catch(() => $("pubPem").select());
$("copyFp").onclick = () => navigator.clipboard.writeText($("fp").textContent).catch(() => {});
$("sampleBtn").onclick = () => setSignFile(new File([SAMPLE], "hop-dong-mau.txt", { type: "text/plain" }));
$("signFile").onchange = (e) => e.target.files[0] && setSignFile(e.target.files[0]);
$("verFile").onchange = (e) => e.target.files[0] && setVerFile(e.target.files[0].name, e.target.files[0]);
for (const [btn, input] of [["pickBtn", "signFile"], ["pickVer", "verFile"]]) {
  $(btn).addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $(input).click(); }
  });
}
dragAndDrop($("signDrop"), setSignFile);
dragAndDrop($("verDrop"), (f) => setVerFile(f.name, f));
$("signBtn").onclick = doSign;
$("dlSigned").onclick = () => download(state.signedName, state.signed);
$("dlSigJson").onclick = () => download(state.file.name + ".sig.json", state.sigJson);
$("toVerify").onclick = () => {
  setVerFile(state.signedName, new Blob([state.signed]));
  $("xacminh").scrollIntoView({ behavior: "smooth" });
  doVerify();
};
$("useSigned").onclick = () => { setVerFile(state.signedName, new Blob([state.signed])); doVerify(); };
$("useTampered").onclick = () => {
  const [pos, t] = tamperedCopy();
  setVerFile(state.signedName.replace(".signed", ".tampered") + ` (byte ${pos} bị lật 1 bit)`, new Blob([t]));
  doVerify();
};
$("verBtn").onclick = doVerify;

/* Khởi động: có khóa, có file mẫu, đã ký và xác minh */
(async () => {
  await loadCA();
  await loadKeys();
  if (!state.keys.length) await genKey();
  $("sampleBtn").click();
  await doSign();
  if (state.signed) {
    setVerFile(state.signedName, new Blob([state.signed]));
    await doVerify();
  }
})();
