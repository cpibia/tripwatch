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

// A click anywhere on an alert row shows that alert in the side panel, as its title link does.
// Buttons, links and text selections inside the row keep their own behaviour.
(function () {
  document.addEventListener("click", function (event) {
    var row = event.target.closest && event.target.closest("tr[data-href]");
    if (!row || event.target.closest("a, button, form, input")) return;
    if (String(window.getSelection ? window.getSelection() : "") !== "") return;
    window.location.href = row.dataset.href;
  });
})();

// Copy buttons copy the text of the element they name.
(function () {
  document.addEventListener("click", function (event) {
    var button = event.target.closest && event.target.closest("button[data-copy]");
    if (!button || !navigator.clipboard) return;
    var source = document.getElementById(button.dataset.copy);
    if (!source) return;
    navigator.clipboard.writeText(source.textContent.trim()).then(function () {
      var label = button.textContent;
      button.textContent = "Copiati";
      setTimeout(function () { button.textContent = label; }, 2000);
    });
  });
})();
