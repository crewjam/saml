// The SAML inspector. It loads the decoder (Go compiled to WebAssembly)
// and renders what it finds. Everything happens in the browser: the input
// is never sent anywhere. Output is built with textContent, never
// innerHTML, since it comes from untrusted messages.
(() => {
  const $ = (id) => document.getElementById(id);
  const input = $("input");
  const keys = $("keys");
  const output = $("output");
  const status = $("status");
  let ready = false;

  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") e.className = v;
      else e.setAttribute(k, v);
    }
    for (const c of children) {
      if (c === null || c === undefined || c === false) continue;
      e.append(c instanceof Node ? c : String(c));
    }
    return e;
  }

  const dl = (rows, cls) => {
    const d = el("dl", cls ? { class: cls } : null);
    for (const r of rows) d.append(el("dt", null, r.k), el("dd", r.cls ? { class: r.cls } : null, r.v));
    return d;
  };
  const mark = { ok: "✓", warn: "!", bad: "✗" };

  // xmlPane renders XML tokens (see inspect.XMLToken) as text nodes and
  // spans: the same markup as the server's xmlTokens.
  function xmlPane(tokens) {
    const pre = el("pre", { class: "xml" });
    for (const t of tokens) pre.append(t.k === "text" ? document.createTextNode(t.t) : el("span", { class: "x-" + t.k }, t.t));
    return pre;
  }

  // renderView builds the same markup as the server's "decoded" template,
  // from the View the decoder made for the message.
  function renderView(v, m) {
    const head = el("div", { class: "decoded-head" }, el("h2", null, v.title + " ", el("span", { class: "decoded-sub" }, v.sub || "")));
    if (v.checks && v.checks.length) {
      head.append(el("ul", { class: "checks" }, ...v.checks.map((c) => el("li", { class: c.level }, mark[c.level] + " " + c.text))));
    }
    const groups = el("div", { class: "groups" });
    for (const g of v.groups || []) {
      groups.append(el("div", null, el("h3", null, g.title), dl(g.rows.map((r) => ({ k: r.k, v: r.v, cls: r.mono ? "mono" : r.time ? "time" : "" })))));
    }
    for (const n of v.notes || []) groups.append(el("p", { class: "explain" }, n));
    const grid = el("div", { class: "decoded-grid" }, groups);
    if (v.xml && v.xml.length) {
      grid.append(el("div", { class: "minw0" },
        el("div", { class: "pane-head" }, el("h3", null, "XML"), copyButton(() => m.xml)),
        xmlPane(v.xml)));
    }
    const sec = el("section", { class: "decoded", "aria-label": "Decoded message" }, head, grid);
    // Signature details and certificates, which the View summarises.
    const more = el("div", { class: "disclosures decoded-more" });
    for (const s of m.signatures || []) {
      more.append(el("details", null, el("summary", null, "Signature of " + s.signs),
        dl([
          checkRow("Trusted certificate", s.trust),
          checkRow("Own KeyInfo certificate", s.integrity),
          { k: "Reference", v: (s.referenceURI || "(empty)") + (s.referenceMatches ? ": matches the element" : ": does not match the element"), cls: "mono" },
          { k: "Signature method", v: s.signatureMethod, cls: "mono" },
          { k: "Digest method", v: s.digestMethod, cls: "mono" },
          { k: "Canonicalization", v: s.canonicalization, cls: "mono" },
          { k: "Transforms", v: s.transforms || "", cls: "mono" },
        ].filter((r) => r.v), "dl")));
    }
    for (const c of m.certificates || []) {
      const d = el("details", null, el("summary", null, "Certificate (" + c.where + "): " + (c.subject || c.error || "") + (c.expired ? " (expired)" : "")));
      if (!c.error) {
        d.append(dl([
          { k: "Subject", v: c.subject }, { k: "Issuer", v: c.issuer },
          { k: "Valid", v: c.notBefore + " to " + c.notAfter, cls: "time" },
          { k: "Key", v: c.key }, { k: "Serial", v: c.serial, cls: "mono" },
          { k: "SHA-1", v: c.sha1, cls: "mono" }, { k: "SHA-256", v: c.sha256, cls: "mono" },
        ], "dl"), el("div", { class: "pane-head" }, el("h3", null, "PEM"), copyButton(() => c.pem)), el("pre", { class: "pane" }, c.pem));
      }
      more.append(d);
    }
    if (more.childElementCount) sec.append(more);
    return sec;
  }

  function copyButton(getText) {
    const b = el("button", { type: "button", class: "btn secondary sm" }, "Copy");
    b.addEventListener("click", () => {
      navigator.clipboard.writeText(getText()).then(() => {
        b.textContent = "Copied";
        setTimeout(() => { b.textContent = "Copy"; }, 1200);
      });
    });
    return b;
  }

  // checkRow describes a signature check, or nothing if it was not made.
  function checkRow(label, c) {
    if (!c) return { k: label, v: "" };
    return { k: label, v: c.ok ? "✓ valid, signed by " + c.by : "✗ " + c.error };
  }

  function render(res) {
    output.replaceChildren();
    if (res.error) {
      output.append(el("p", { class: "verdict bad-text decoded-error" }, "✗ " + res.error));
      return;
    }
    // What the input was, when there is more to it than the messages.
    const rows = [];
    for (const p of res.params || []) rows.push({ k: p.k, v: p.v, cls: p.k === "Warning" ? "" : "mono" });
    if (res.detached) {
      rows.push({ k: "Binding signature", v: res.detached.binding + ", " + res.detached.sigAlg, cls: "mono" });
      rows.push(res.detached.trust ? checkRow("Checked", res.detached.trust)
        : { k: "Checked", v: "Not yet: paste the signer's certificate to check it." });
    }
    for (const c of res.keys || []) rows.push({ k: "Checking with", v: c.subject + (c.expired ? " (expired)" : "") });
    if (res.keysError) rows.push({ k: "Keys", v: res.keysError });
    if (rows.length) {
      output.append(el("section", { class: "decoded-from" }, el("h2", { class: "sec-h2" }, "Decoded from " + res.input + (res.binding ? ", " + res.binding : "")), dl(rows, "dl")));
    }
    for (const m of res.messages) output.append(renderView(m.view || { title: m.type, sub: "", checks: m.error ? [{ level: "bad", text: m.error }] : [] }, m));
  }

  function decode() {
    const text = input.value;
    if (!text.trim()) {
      output.replaceChildren();
      status.textContent = ready ? "Ready." : status.textContent;
      return;
    }
    if (!ready) return;
    const t0 = performance.now();
    let res;
    try {
      res = JSON.parse(window.samlInspect(text, keys.value));
    } catch (err) {
      res = { error: "The decoder failed: " + err };
    }
    render(res);
    const n = (res.messages || []).length;
    status.textContent = res.error ? "Nothing decoded." :
      `Decoded ${n} message${n === 1 ? "" : "s"} in ${Math.round(performance.now() - t0)} ms.`;
  }

  // Start from a message given to the page: posted to it, in the URL
  // fragment (from "Copy link"), or in its own query string.
  function initialInput() {
    try {
      const posted = JSON.parse($("posted").textContent || '""');
      if (posted) return posted;
    } catch (_) { /* nothing posted */ }
    const hash = new URLSearchParams(location.hash.slice(1));
    if (hash.get("k")) {
      keys.value = hash.get("k");
      $("keys-box").open = true;
    }
    if (hash.get("m")) return hash.get("m");
    if (/[?&](SAMLRequest|SAMLResponse|SAMLart)=/.test(location.search)) return location.href;
    return "";
  }

  let timer;
  for (const box of [input, keys]) {
    box.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(decode, 250);
    });
  }
  $("inspect-form").addEventListener("submit", (e) => { e.preventDefault(); decode(); });
  $("clear").addEventListener("click", () => {
    input.value = "";
    keys.value = "";
    history.replaceState(null, "", location.pathname);
    decode();
    input.focus();
  });
  $("share").addEventListener("click", (e) => {
    // The fragment is not sent to the server when the link is opened.
    let url = location.origin + location.pathname + "#m=" + encodeURIComponent(input.value);
    if (keys.value.trim()) url += "&k=" + encodeURIComponent(keys.value);
    history.replaceState(null, "", url);
    navigator.clipboard.writeText(url).then(() => {
      e.target.textContent = "Copied";
      setTimeout(() => { e.target.textContent = "Copy link"; }, 1200);
    });
  });

  input.value = initialInput();

  window.addEventListener("saml-inspect-ready", () => {
    ready = true;
    status.textContent = "Ready.";
    decode();
  });

  if (typeof Go === "undefined") {
    status.textContent = "The decoder is not available: this server was built without it (see deploy.sh).";
    return;
  }
  const go = new Go();
  WebAssembly.instantiateStreaming(fetch("/static/parser.wasm"), go.importObject)
    .then((r) => go.run(r.instance))
    .catch((err) => { status.textContent = "Cannot load the decoder: " + err; });
})();
