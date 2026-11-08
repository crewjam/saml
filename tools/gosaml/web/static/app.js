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
