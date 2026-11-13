// Search autocomplete for any <input data-dg-assist>.
// Works by event delegation so it survives Blazor re-renders and enhanced navigation.
// Suggestions come from GET /api/v1/search/suggest?q=&pos= (scoped to the user's tenants).
(function () {
  "use strict";

  var DEBOUNCE_MS = 120;
  var state = { input: null, items: [], active: -1, start: 0, end: 0, timer: 0, seq: 0, hint: "" };
  var box = null, list = null, hintEl = null;

  function ensureBox() {
    if (box && document.body.contains(box)) return;
    box = document.createElement("div");
    box.className = "dg-assist";
    box.hidden = true;
    list = document.createElement("ul");
    list.id = "dg-assist-list";
    list.setAttribute("role", "listbox");
    hintEl = document.createElement("div");
    hintEl.className = "dg-assist-hint";
    box.appendChild(list);
    box.appendChild(hintEl);
    // mousedown, not click: keeps focus in the input.
    box.addEventListener("mousedown", function (e) {
      e.preventDefault();
      var li = e.target.closest("li[data-i]");
      if (li) accept(+li.getAttribute("data-i"));
    });
    document.body.appendChild(box);
  }

  function isAssist(el) {
    return el && el.tagName === "INPUT" && el.hasAttribute("data-dg-assist");
  }

  function position() {
    var r = state.input.getBoundingClientRect();
    box.style.left = r.left + "px";
    box.style.top = (r.bottom + 2) + "px";
    box.style.minWidth = Math.min(r.width, 520) + "px";
  }

  function hide() {
    if (box) box.hidden = true;
    state.items = [];
    state.active = -1;
    if (state.input) state.input.removeAttribute("aria-activedescendant");
    if (state.input) state.input.setAttribute("aria-expanded", "false");
  }

  function schedule(input) {
    clearTimeout(state.timer);
    state.timer = setTimeout(function () { fetchFor(input); }, DEBOUNCE_MS);
  }

  function fetchFor(input) {
    var seq = ++state.seq;
    var url = "api/v1/search/suggest?q=" + encodeURIComponent(input.value) + "&pos=" + (input.selectionStart || 0);
    fetch(url, { credentials: "same-origin", headers: { "Accept": "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data || seq !== state.seq || document.activeElement !== input) return;
        render(input, data);
      })
      .catch(function () { /* offline or signed out: no suggestions */ });
  }

  function render(input, data) {
    ensureBox();
    state.input = input;
    state.items = data.items || [];
    state.start = data.replaceStart;
    state.end = data.replaceEnd;
    state.active = state.items.length ? 0 : -1;
    state.hint = data.hint || "";

    list.textContent = "";
    state.items.forEach(function (it, i) {
      var li = document.createElement("li");
      li.id = "dg-assist-" + i;
      li.setAttribute("data-i", i);
      li.setAttribute("role", "option");
      li.className = "dg-assist-" + it.kind;
      var label = document.createElement("span");
      label.className = "dg-assist-label";
      label.textContent = it.label;
      li.appendChild(label);
      if (it.detail) {
        var d = document.createElement("span");
        d.className = "dg-assist-detail";
        d.textContent = it.detail;
        li.appendChild(d);
      }
      list.appendChild(li);
    });
    hintEl.textContent = state.hint;
    hintEl.hidden = !state.hint;

    if (!state.items.length && !state.hint) { hide(); return; }
    input.setAttribute("aria-controls", "dg-assist-list");
    input.setAttribute("aria-expanded", "true");
    position();
    box.hidden = false;
    highlight();
  }

  function highlight() {
    var lis = list.children;
    for (var i = 0; i < lis.length; i++) {
      var on = i === state.active;
      lis[i].classList.toggle("active", on);
      lis[i].setAttribute("aria-selected", on ? "true" : "false");
      if (on) lis[i].scrollIntoView({ block: "nearest" });
    }
    if (state.active >= 0) state.input.setAttribute("aria-activedescendant", "dg-assist-" + state.active);
  }

  function accept(i) {
    var it = state.items[i], input = state.input;
    if (!it || !input) return;
    var v = input.value;
    var after = v.slice(state.end);
    var insert = it.insert;
    // Don't double up a space or '=' that's already there.
    if (insert.endsWith(" ") && after.startsWith(" ")) insert = insert.slice(0, -1);
    if (insert.endsWith("=") && after.startsWith("=")) insert = insert.slice(0, -1);
    input.value = v.slice(0, state.start) + insert + after;
    var caret = state.start + insert.length;
    input.setSelectionRange(caret, caret);
    // Keep Blazor's @bind in sync, then look for what comes next (e.g. values after "field=").
    input.dispatchEvent(new Event("input", { bubbles: true }));
    hide();
    schedule(input);
  }

  document.addEventListener("input", function (e) {
    if (isAssist(e.target)) schedule(e.target);
  }, true);

  document.addEventListener("focusin", function (e) {
    if (isAssist(e.target)) schedule(e.target);
  });

  document.addEventListener("focusout", function (e) {
    if (isAssist(e.target)) { clearTimeout(state.timer); state.seq++; hide(); }
  });

  document.addEventListener("click", function (e) {
    // Cursor moved by mouse inside the box: re-evaluate the context.
    if (isAssist(e.target)) schedule(e.target);
  });

  document.addEventListener("keydown", function (e) {
    var input = e.target;
    if (!isAssist(input)) return;
    var open = box && !box.hidden && state.input === input && state.items.length > 0;

    if (e.key === " " && e.ctrlKey) { e.preventDefault(); fetchFor(input); return; }
    if (e.key === "Escape") { if (box && !box.hidden) { e.preventDefault(); hide(); } return; }
    if (!open) {
      if (e.key === "ArrowLeft" || e.key === "ArrowRight" || e.key === "Home" || e.key === "End") schedule(input);
      return;
    }
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        state.active = (state.active + 1) % state.items.length;
        highlight();
        break;
      case "ArrowUp":
        e.preventDefault();
        state.active = (state.active - 1 + state.items.length) % state.items.length;
        highlight();
        break;
      case "Tab":
        e.preventDefault();
        accept(state.active);
        break;
      case "Enter":
        // Enter picks a suggestion only after arrowing to one; otherwise it runs the search.
        if (state.navigated) { e.preventDefault(); e.stopPropagation(); accept(state.active); }
        else hide();
        break;
      case "ArrowLeft": case "ArrowRight": case "Home": case "End":
        schedule(input);
        break;
    }
    state.navigated = e.key === "ArrowDown" || e.key === "ArrowUp";
  }, true);

  window.addEventListener("resize", function () { if (box && !box.hidden) position(); });
  window.addEventListener("scroll", function () { if (box && !box.hidden) position(); }, true);
})();
