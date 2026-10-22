// Keeps an open console current: reload once a minute while the page is in view and the
// operator is not typing or selecting text.
(function () {
  var seconds = Number(document.body.dataset.refresh || 0);
  if (!seconds) return;
  var due = Date.now() + seconds * 1000;
  setInterval(function () {
    if (Date.now() < due || document.visibilityState !== "visible") return;
    var active = document.activeElement;
    var busy = active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA");
    var selecting = String(window.getSelection ? window.getSelection() : "") !== "";
    if (busy || selecting) {
      due = Date.now() + 15000;
      return;
    }
    window.location.reload();
  }, 5000);
})();
