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
      button.textContent = "Copied";
      setTimeout(function () { button.textContent = label; }, 2000);
    });
  });
})();

// A group of alerts opens onto its rows. The groups left open survive the minute reload: the
// keys are kept for this tab only, and a storage the browser refuses just leaves them closed.
(function () {
  var storageKey = "tw-open-groups";
  function load() {
    try { return JSON.parse(sessionStorage.getItem(storageKey) || "[]"); } catch (e) { return []; }
  }
  function save(keys) {
    try { sessionStorage.setItem(storageKey, JSON.stringify(keys)); } catch (e) { /* nothing to keep */ }
  }
  function show(button, open) {
    var rows = document.getElementById(button.getAttribute("aria-controls"));
    if (!rows) return;
    rows.hidden = !open;
    button.setAttribute("aria-expanded", open ? "true" : "false");
  }
  var kept = load();
  document.querySelectorAll("button.disclose[data-group]").forEach(function (button) {
    if (kept.indexOf(button.dataset.group) >= 0) show(button, true);
  });
  document.addEventListener("click", function (event) {
    var button = event.target.closest && event.target.closest("button.disclose[data-group]");
    if (!button) return;
    var open = button.getAttribute("aria-expanded") !== "true";
    show(button, open);
    var keys = load().filter(function (k) { return k !== button.dataset.group; });
    if (open) keys.push(button.dataset.group);
    save(keys.slice(-50));
  });
})();

// "/" moves to the search box at the top, unless the operator is already typing somewhere.
(function () {
  document.addEventListener("keydown", function (event) {
    if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey) return;
    var active = document.activeElement;
    if (active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA" || active.tagName === "SELECT" || active.isContentEditable)) return;
    var box = document.getElementById("gs");
    if (!box) return;
    event.preventDefault();
    box.focus();
    box.select();
  });
})();

// Filter forms apply a choice as soon as it is made: the button stays for keyboards and for
// browsers without this script.
(function () {
  document.addEventListener("change", function (event) {
    var form = event.target.closest && event.target.closest("form[data-autosubmit]");
    if (!form || event.target.type === "search") return;
    form.requestSubmit ? form.requestSubmit() : form.submit();
  });
})();

// A filter box above a table hides the rows that do not contain what is typed.
(function () {
  document.addEventListener("input", function (event) {
    var box = event.target;
    if (!box.dataset || !box.dataset.filter) return;
    var table = document.getElementById(box.dataset.filter);
    if (!table) return;
    var text = box.value.trim().toLowerCase();
    table.querySelectorAll("tbody tr").forEach(function (row) {
      row.hidden = text !== "" && row.textContent.toLowerCase().indexOf(text) < 0;
    });
  });
})();
