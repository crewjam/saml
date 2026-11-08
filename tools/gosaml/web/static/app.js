// Small enhancements for the server-rendered pages. Everything works
// without it, except copying and live log updates.
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

  document.addEventListener("submit", (e) => {
    const msg = e.submitter && e.submitter.dataset.confirm || e.target.dataset.confirm;
    if (msg && !confirm(msg)) e.preventDefault();
  });

  // The login picker's button names the chosen user.
  const picker = document.querySelector("[data-login-picker]");
  if (picker) {
    const label = document.querySelector("[data-login-as]");
    picker.addEventListener("change", (e) => {
      if (e.target.name === "user" && label) label.textContent = "Log in as " + e.target.value;
    });
  }

  // Times are rendered in UTC; show them in the viewer's time zone.
  const localTimes = (root) => root.querySelectorAll("time[datetime]").forEach((el) => {
    const d = new Date(el.getAttribute("datetime"));
    if (isNaN(d)) return;
    el.textContent = el.dataset.date !== undefined ? d.toLocaleString() : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    el.title = d.toUTCString();
  });
  localTimes(document);

  // The Log follows its instance with htmx's SSE extension (see the "log"
  // template): the server sends each new row as HTML, which htmx adds to
  // the top of the list. What is left to do here is the Live indicator,
  // skipping rows already shown after a reconnect, trimming the list to
  // the server's limit, and showing times in the viewer's time zone.
  const log = document.getElementById("log");
  if (log) {
    const live = document.getElementById("live");
    const max = parseInt(log.dataset.max, 10) || 50;
    log.addEventListener("htmx:sseOpen", () => { live.hidden = false; });
    log.addEventListener("htmx:sseError", () => { live.hidden = true; });
    log.addEventListener("htmx:sseClose", () => { live.hidden = true; });
    log.addEventListener("htmx:sseBeforeMessage", (e) => {
      const id = e.detail && e.detail.lastEventId;
      if (e.detail.type === "log" && id && log.querySelector(`#log-list li[data-id="${CSS.escape(id)}"]`)) e.preventDefault();
    });
    log.addEventListener("htmx:afterSwap", (e) => {
      const list = document.getElementById("log-list");
      if (e.target !== list) return;
      const first = list.firstElementChild;
      if (first) { first.classList.add("new"); localTimes(first); }
      while (list.children.length > max) list.lastElementChild.remove();
    });
  }
})();
