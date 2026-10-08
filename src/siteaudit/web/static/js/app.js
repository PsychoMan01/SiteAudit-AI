// SiteAudit — progressive enhancement only. Every page works without JavaScript.
(function () {
  "use strict";

  // Live progress for a running audit: poll the status endpoint and update the stage list.
  var progress = document.querySelector("[data-audit-status]");
  if (progress) {
    var url = progress.getAttribute("data-audit-status");
    var items = Array.prototype.slice.call(progress.querySelectorAll("[data-stage]"));
    var live = document.querySelector("[data-live]");
    var pagesEl = document.querySelector("[data-pages]");
    var delay = 2000;

    var apply = function (stage) {
      var reached = false;
      for (var i = items.length - 1; i >= 0; i--) {
        var el = items[i];
        var name = el.getAttribute("data-stage");
        el.classList.remove("current", "done");
        if (name === stage) { el.classList.add("current"); el.setAttribute("aria-current", "step"); reached = true; continue; }
        el.removeAttribute("aria-current");
        if (reached) { el.classList.add("done"); }
      }
    };

    var poll = function () {
      fetch(url, { credentials: "same-origin", headers: { "Accept": "application/json" } })
        .then(function (r) { if (!r.ok) { throw new Error(String(r.status)); } return r.json(); })
        .then(function (data) {
          if (data.finished) { window.location.reload(); return; }
          if (data.stage) {
            apply(data.stage);
            var el = progress.querySelector('[data-stage="' + data.stage + '"]');
            if (live && el) { live.textContent = el.textContent; }
          }
          if (pagesEl && typeof data.pages === "number") { pagesEl.textContent = String(data.pages); }
          delay = 2000;
          window.setTimeout(poll, delay);
        })
        .catch(function () {
          delay = Math.min(delay * 2, 30000);
          window.setTimeout(poll, delay);
        });
    };
    window.setTimeout(poll, delay);
  }

  // Filter selects submit their form on change (the Apply button remains for keyboard/no-JS users).
  Array.prototype.forEach.call(document.querySelectorAll("[data-autosubmit] select"), function (select) {
    select.addEventListener("change", function () { select.form.submit(); });
  });

  // Confirm destructive actions.
  Array.prototype.forEach.call(document.querySelectorAll("form[data-confirm]"), function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) { event.preventDefault(); }
    });
  });
})();
