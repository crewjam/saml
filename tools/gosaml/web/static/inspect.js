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

  function table(rows) {
    const t = el("table");
    for (const r of rows) t.append(el("tr", null, el("th", null, r.k), el("td", null, r.v)));
    return t;
  }

  function section(title, rows) {
    return el("div", { class: "section" }, el("h3", null, title), table(rows));
  }

  function copyButton(getText) {
    const b = el("button", { type: "button", class: "small secondary" }, "Copy");
    b.addEventListener("click", () => {
      navigator.clipboard.writeText(getText()).then(() => {
        b.textContent = "Copied";
        setTimeout(() => { b.textContent = "Copy"; }, 1200);
      });
    });
    return b;
  }

  function renderMessage(m) {
    const card = el("section", { class: "card" });
    card.append(el("div", { class: "msg-head" },
      el("h2", null, m.type),
      m.parameter ? el("span", { class: "badge" }, m.parameter) : null,
      el("span", { class: "meta" }, m.encoding + (m.namespace ? " · " + m.namespace : ""))));
    if (m.error) card.append(el("div", { class: "error-box" }, m.error));
    if (m.warnings && m.warnings.length) {
      card.append(el("ul", { class: "warnings" }, ...m.warnings.map((w) => el("li", null, w))));
    }
    if (m.sections && m.sections.length) {
      card.append(el("div", { class: "sections" }, ...m.sections.map((s) => section(s.title, s.rows))));
    }
    if (m.signatures && m.signatures.length) {
      card.append(el("h3", null, "Signatures"));
      const grid = el("div", { class: "sections" });
      for (const s of m.signatures) {
        grid.append(section("Signature of " + s.signs, [
          checkRow("Trusted certificate", s.trust),
          checkRow("Own KeyInfo certificate", s.integrity),
          { k: "Reference", v: s.referenceURI + (s.referenceMatches ? " ✓ matches" : " ✕ does not match the element") },
          { k: "Signature method", v: s.signatureMethod },
          { k: "Digest method", v: s.digestMethod },
          { k: "Canonicalization", v: s.canonicalization },
          { k: "Transforms", v: s.transforms || "" },
          { k: "Certificate in KeyInfo", v: s.hasCertificate ? "yes" : "no" },
        ].filter((r) => r.v)));
      }
      card.append(grid);
    }
    if (m.certificates && m.certificates.length) {
      card.append(el("h3", null, "Certificates"));
      for (const c of m.certificates) {
        const d = el("details", { class: "cert" + (c.expired ? " expired" : "") });
        d.append(el("summary", null, c.where + ": " + (c.subject || c.error || "") + (c.expired ? " (expired)" : "")));
        if (!c.error) {
          d.append(table([
            { k: "Subject", v: c.subject }, { k: "Issuer", v: c.issuer },
            { k: "Valid", v: c.notBefore + " to " + c.notAfter },
            { k: "Key", v: c.key }, { k: "Serial", v: c.serial },
            { k: "SHA-1", v: c.sha1 }, { k: "SHA-256", v: c.sha256 },
          ]));
          d.append(el("div", { class: "xml-head" }, el("span", null, "PEM"), copyButton(() => c.pem)), el("pre", null, c.pem));
        }
        card.append(d);
      }
    }
    if (m.xml) {
      const pre = el("pre", { class: "xml" }, m.xml);
      const d = el("details", { open: "" }, el("summary", null, "XML"),
        el("div", { class: "xml-head" }, el("span", null, "Indented for reading: the whitespace differs, so signatures will not verify against this copy."), copyButton(() => m.xml)),
        pre);
      card.append(d);
    }
    return card;
  }

  // checkRow describes a signature check, or nothing if it was not made.
  function checkRow(label, c) {
    if (!c) return { k: label, v: "" };
    return { k: label, v: c.ok ? "✓ valid, signed by " + c.by : "✕ " + c.error };
  }

  function render(res) {
    output.replaceChildren();
    if (res.error) {
      output.append(el("section", { class: "card" }, el("div", { class: "error-box" }, res.error)));
      return;
    }
    const rows = [{ k: "Input", v: res.input }];
    if (res.binding) rows.push({ k: "Binding", v: res.binding });
    for (const p of res.params || []) rows.push(p);
    const top = el("div", { class: "sections" }, section("Decoded from", rows));
    if (res.detached) {
      top.append(section("Binding signature (" + res.detached.binding + ")", [
        { k: "SigAlg", v: res.detached.sigAlg },
        res.detached.trust ? checkRow("Trusted certificate", res.detached.trust)
          : { k: "Checked", v: "not yet: paste the signer's certificate to check it" },
      ]));
    }
    if (res.keys || res.keysError) {
      const krows = (res.keys || []).map((c) => ({ k: "Certificate", v: c.subject + (c.expired ? " (expired)" : "") }));
      if (res.keysError) krows.push({ k: "Problem", v: res.keysError });
      top.append(section("Checking with", krows));
    }
    output.append(el("section", { class: "card" }, top));
    for (const m of res.messages) output.append(renderMessage(m));
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
  $("decode").addEventListener("click", decode);
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
