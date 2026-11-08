// Small enhancements for the server-rendered pages: copy buttons and
// confirmations. Everything works without it.
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-copy], [data-copy-from]");
  if (!btn) return;
  let text = btn.dataset.copy;
  if (text === undefined) {
    const block = btn.parentElement.nextElementSibling;
    text = block ? block.textContent : "";
  }
  navigator.clipboard.writeText(text).then(() => {
    const old = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(() => { btn.textContent = old; }, 1200);
  });
});

document.addEventListener("submit", (e) => {
  const msg = e.target.dataset.confirm;
  if (msg && !confirm(msg)) e.preventDefault();
});

// Live log: the management pages follow their instance's log with
// Server-Sent Events, so messages appear as they are exchanged.
(() => {
  const log = document.getElementById("log");
  if (!log || !log.dataset.live || !window.EventSource) return;
  const list = log.querySelector(".events");
  const empty = log.querySelector(".empty");
  const status = document.getElementById("live");
  const max = parseInt(log.dataset.max, 10) || 50;
  const show = (text, cls) => { status.hidden = false; status.textContent = text; status.className = "live " + cls; };

  let url = log.dataset.live;
  if (log.dataset.after) url += "?after=" + encodeURIComponent(log.dataset.after);
  const source = new EventSource(url);

  source.addEventListener("ready", () => show("live", "on"));
  source.addEventListener("error", () => show("reconnecting…", "off"));
  source.addEventListener("log", (e) => {
    const { id, html } = JSON.parse(e.data);
    if (list.querySelector(`li[data-id="${id}"]`)) return;
    const t = document.createElement("template");
    t.innerHTML = html.trim(); // rendered and escaped by the server's html/template
    const li = t.content.firstElementChild;
    li.classList.add("new");
    list.prepend(li);
    empty.hidden = true;
    while (list.children.length > max) list.lastElementChild.remove();
  });
  source.addEventListener("clear", () => { list.replaceChildren(); empty.hidden = false; });
  source.addEventListener("gone", () => { source.close(); show("instance deleted", "off"); });

  // Show times in the viewer's own time zone.
  const local = (root) => root.querySelectorAll("time[datetime]").forEach((el) => {
    el.textContent = new Date(el.getAttribute("datetime")).toLocaleTimeString();
  });
  local(list);
  new MutationObserver(() => local(list)).observe(list, { childList: true });
})();
