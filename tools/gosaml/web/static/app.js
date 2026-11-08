// Small enhancements for the server-rendered pages, which htmx boosts
// (layout.html). Everything works without either, except copying and
// live log updates. Listeners are delegated from the document, so they
// keep working on pages htmx swaps in.
(() => {
  const flashLabel = (btn, text) => {
    const old = btn.textContent;
    btn.textContent = text;
    setTimeout(() => { btn.textContent = old; }, 1200);
  };
  const copy = (btn, text) => navigator.clipboard.writeText(text).then(() => flashLabel(btn, "Copied"));

  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-copy], [data-copy-from], [data-copy-page], [data-copy-target]");
    if (btn) {
      if (btn.dataset.copy !== undefined) return copy(btn, btn.dataset.copy);
      if (btn.dataset.copyPage !== undefined) return copy(btn, location.href.split("#")[0]);
      if (btn.dataset.copyTarget) {
        const el = document.getElementById(btn.dataset.copyTarget);
        return el && copy(btn, el.value !== undefined && el.tagName === "TEXTAREA" ? el.value : el.textContent);
      }
      // data-copy-from="next-pre": the next <pre> after the button's row.
      let el = btn.parentElement;
      while (el && !(el.nextElementSibling && el.nextElementSibling.tagName === "PRE")) el = el.parentElement;
      if (el) copy(btn, el.nextElementSibling.textContent);
      return;
    }

    // Inline delete confirmation: the button is swapped for a question.
    const ask = e.target.closest("[data-ask]");
    if (ask) {
      const box = ask.closest("[data-confirm-box]");
      box.querySelector("[data-ask]").hidden = true;
      box.querySelector("[data-asking]").hidden = false;
      box.querySelector("[data-asking] [data-cancel]").focus();
      return;
    }
    const cancel = e.target.closest("[data-cancel]");
    if (cancel) {
      const box = cancel.closest("[data-confirm-box]");
      box.querySelector("[data-asking]").hidden = true;
      box.querySelector("[data-ask]").hidden = false;
      box.querySelector("[data-ask]").focus();
      return;
    }

    // data-open opens the <details> it names, such as "Add a user".
    const opener = e.target.closest("[data-open]");
    if (opener) {
      const d = document.getElementById(opener.dataset.open);
      if (d) { d.open = true; d.scrollIntoView({ block: "nearest" }); const f = d.querySelector("input:not([type=hidden]), textarea"); if (f) f.focus(); }
      return;
    }

    // Tabs: role="tab" buttons with aria-controls.
    const tab = e.target.closest('[role="tab"]');
    if (tab) {
      const list = tab.closest('[role="tablist"]');
      for (const t of list.querySelectorAll('[role="tab"]')) {
        const on = t === tab;
        t.setAttribute("aria-selected", on ? "true" : "false");
        const panel = document.getElementById(t.getAttribute("aria-controls"));
        if (panel) {
          panel.hidden = !on;
          for (const f of panel.querySelectorAll("input, textarea")) f.disabled = !on;
        }
      }
    }
  });

  // Confirmation before destructive posts: data-confirm on the form or
  // on the button that submits it. Forms are boosted by htmx, which asks
  // through htmx:confirm; forms it does not boost (the protocol ones) get
  // a plain submit event, which htmx has not already cancelled.
  const question = (form, submitter) => (submitter && submitter.dataset.confirm) || (form && form.dataset && form.dataset.confirm);
  document.addEventListener("htmx:confirm", (e) => {
    const t = e.detail.triggeringEvent;
    const msg = question(e.detail.elt.closest && e.detail.elt.closest("form"), t && t.submitter);
    if (!msg) return;
    e.preventDefault();
    if (confirm(msg)) e.detail.issueRequest(true);
  });
  document.addEventListener("submit", (e) => {
    if (e.defaultPrevented) return;
    const msg = question(e.target, e.submitter);
    if (msg && !confirm(msg)) e.preventDefault();
  });

  // The login picker's button names the chosen user.
  document.addEventListener("change", (e) => {
    if (e.target.name !== "user" || !e.target.closest("[data-login-picker]")) return;
    const label = document.querySelector("[data-login-as]");
    if (label) label.textContent = "Log in as " + e.target.value;
  });

  // Times are rendered in UTC; show them in the viewer's time zone. This
  // runs again on whatever htmx swaps in.
  const localTimes = (root) => root.querySelectorAll("time[datetime]:not([data-local])").forEach((el) => {
    const d = new Date(el.getAttribute("datetime"));
    if (isNaN(d)) return;
    el.textContent = el.dataset.date !== undefined ? d.toLocaleString() : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    if (!el.title) el.title = d.toUTCString();
    el.dataset.local = "";
  });
  localTimes(document);
  document.addEventListener("htmx:load", (e) => localTimes(e.detail.elt));

  // The Log follows its instance with htmx's SSE extension (see the "log"
  // template): the server sends each new row as HTML, which htmx adds to
  // the top of the list. What is left to do here is the Live indicator,
  // skipping rows already shown after a reconnect, and trimming the list
  // to the server's limit. The listeners are on the document because
  // boosted navigation replaces the Log along with the rest of the page.
  const liveIndicator = (on) => { const live = document.getElementById("live"); if (live) live.hidden = !on; };
  document.addEventListener("htmx:sseOpen", () => liveIndicator(true));
  document.addEventListener("htmx:sseError", () => liveIndicator(false));
  document.addEventListener("htmx:sseClose", () => liveIndicator(false));
  document.addEventListener("htmx:sseBeforeMessage", (e) => {
    const id = e.detail && e.detail.lastEventId;
    if (e.detail.type === "log" && id && document.querySelector(`#log-list li[data-id="${CSS.escape(id)}"]`)) e.preventDefault();
  });
  document.addEventListener("htmx:afterSwap", (e) => {
    const list = document.getElementById("log-list");
    if (!list || e.target !== list) return;
    const log = document.getElementById("log");
    const max = parseInt(log && log.dataset.max, 10) || 50;
    const first = list.firstElementChild;
    if (first) first.classList.add("new");
    while (list.children.length > max) list.lastElementChild.remove();
  });
})();
