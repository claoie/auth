(function () {
  "use strict";

  // The admin page: users, access, invitations, services and the audit log,
  // through the same /v1 API apps use.

  var root = document.getElementById("app");
  if (!root) return;
  var csrfMeta = document.querySelector('meta[name="csrf-token"]');
  var csrf = csrfMeta ? csrfMeta.getAttribute("content") || "" : "";
  var services = [];
  var me = null;

  // ------------------------------------------------------------ helpers

  function el(tag, attrs) {
    var node = document.createElement(tag);
    var a = attrs || {};
    Object.keys(a).forEach(function (k) {
      var v = a[k];
      if (v === undefined || v === null || v === false) return;
      if (k === "class") node.className = v;
      else if (k === "hidden") node.hidden = !!v;
      else if (k.slice(0, 2) === "on" && typeof v === "function") node.addEventListener(k.slice(2), v);
      else if (k === "checked" || k === "value" || k === "disabled" || k === "selected") node[k] = v;
      else node.setAttribute(k, v === true ? "" : String(v));
    });
    for (var i = 2; i < arguments.length; i++) append(node, arguments[i]);
    return node;
  }

  function append(node, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) {
      child.forEach(function (c) {
        append(node, c);
      });
      return;
    }
    node.append(child instanceof Node ? child : String(child));
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  // Dates to the minute; the audit log's to the second.
  function when(iso, exact) {
    if (!iso) return "—";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    try {
      return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: exact ? "medium" : "short" });
    } catch (e) {
      return d.toLocaleString();
    }
  }

  // Inline SVG, 16×16 in the text color: the CSP loads no images.
  var SVG = "http://www.w3.org/2000/svg";
  var ICONS = {
    info: [["circle", { cx: 8, cy: 8, r: 6.25 }], ["path", { d: "M8 7.25v3.5M8 5v.25" }]],
    alert: [["path", { d: "M8 2.25 1.75 13.25h12.5L8 2.25ZM8 6.5v3M8 11.25v.25" }]],
    check: [["circle", { cx: 8, cy: 8, r: 6.25 }], ["path", { d: "m5.5 8.25 1.75 1.75 3.25-3.5" }]],
    done: [["path", { d: "m3 8.5 3.25 3.25L13 5" }]],
    back: [["path", { d: "M13 8H3M7 4 3 8l4 4" }]],
    key: [["circle", { cx: 5, cy: 11, r: 2.75 }], ["path", { d: "m7 9 6.25-6.25M11 4.75l1.75 1.75M9.5 6.25l1.25 1.25" }]],
    lock: [["rect", { x: 2.75, y: 7, width: 10.5, height: 7.25, rx: 1.5 }], ["path", { d: "M5.25 7V5.25a2.75 2.75 0 0 1 5.5 0V7" }]],
    copy: [
      ["rect", { x: 5.25, y: 5.25, width: 9, height: 9, rx: 1.5 }],
      ["path", { d: "M10.75 5.25v-2c0-.8-.7-1.5-1.5-1.5h-6c-.8 0-1.5.7-1.5 1.5v6c0 .8.7 1.5 1.5 1.5h2" }],
    ],
  };

  function icon(name) {
    var svg = document.createElementNS(SVG, "svg");
    var attrs = {
      class: "icon",
      width: "16",
      height: "16",
      viewBox: "0 0 16 16",
      fill: "none",
      stroke: "currentColor",
      "stroke-width": "1.5",
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
      "aria-hidden": "true",
      focusable: "false",
    };
    Object.keys(attrs).forEach(function (k) {
      svg.setAttribute(k, attrs[k]);
    });
    (ICONS[name] || []).forEach(function (shape) {
      var n = document.createElementNS(SVG, shape[0]);
      Object.keys(shape[1]).forEach(function (k) {
        n.setAttribute(k, String(shape[1][k]));
      });
      svg.append(n);
    });
    return svg;
  }

  function tag(text, kind) {
    return el("span", { class: kind ? "tag " + kind : "tag" }, text);
  }

  function tags(values, kind) {
    return el(
      "span",
      { class: "tags" },
      values.map(function (v) {
        return tag(v, kind);
      }),
    );
  }

  function initials(name, username) {
    var words = (name || "").trim().split(/\s+/).filter(Boolean);
    var first = function (w) {
      return Array.from(w)[0] || "";
    };
    var s = words.length ? first(words[0]) + (words.length > 1 ? first(words[words.length - 1]) : "") : first(username || "?");
    return s.toUpperCase();
  }

  function userTags(u) {
    return [u.kind === "bot" ? tag("bot") : null, u.disabled ? tag("disabled", "danger") : null];
  }

  function ApiError(status, code, description) {
    this.status = status;
    this.code = code;
    this.message = description;
  }
  ApiError.prototype = Object.create(Error.prototype);

  // `resume` marks the way back, so the page knows to carry on with the
  // change noted before leaving (signInAgain).
  function goToLogin(reauth, resume) {
    var params = new URLSearchParams({ return_to: location.pathname + (resume ? "?resume=1" : "") + location.hash });
    if (reauth) params.set("reauth", "1");
    location.assign("/login?" + params.toString());
  }

  async function api(method, path, body) {
    var init = { method: method, credentials: "same-origin", headers: { Accept: "application/json" } };
    if (method !== "GET") {
      init.headers["Content-Type"] = "application/json";
      init.headers["X-CSRF-Token"] = csrf;
      init.body = JSON.stringify(body || {});
    }
    var res = await fetch(path, init);
    var data = null;
    if (res.status !== 204) {
      try {
        data = await res.json();
      } catch (e) {
        data = null;
      }
    }
    if (res.ok) return data;
    var code = data && data.error;
    if (res.status === 401) {
      goToLogin(false);
      throw new ApiError(401, code, "Sign in first.");
    }
    // reauth_required is act's to handle: it knows which change asked.
    throw new ApiError(res.status, code, (data && data.error_description) || "The request failed (" + res.status + ").");
  }

  // ------------------------------------------ signing in again, and on

  // A change that needs a recent sign-in (§7.5) sends the browser to sign in
  // again, and the sign-in brings it back here, to the tab or user's page the
  // hash names (go). The change, a form or button marked data-resume,
  // is noted in this tab for the trip and starts again once the page is
  // back, so it carries on instead of being lost. Its form's values go with
  // it, but never a password: a form with one waits for it to be typed
  // again. It carries on only for the same person, within RESUME_MS, and
  // once: if it still needs a sign-in, it says why instead.
  var RESUME = "auth.resume";
  var RESUME_MS = 10 * 60 * 1000;
  var resuming = false;

  function fieldsOf(node) {
    if (node.tagName !== "FORM") return [];
    return Array.prototype.filter.call(node.elements, function (f) {
      return f.tagName === "INPUT" || f.tagName === "SELECT" || f.tagName === "TEXTAREA";
    });
  }

  function fieldKind(f) {
    return f.tagName + ":" + f.type + (f.type === "checkbox" ? ":" + f.value : "");
  }

  function signInAgain(trigger) {
    var noted = false;
    if (trigger && me) {
      try {
        sessionStorage.setItem(
          RESUME,
          JSON.stringify({
            page: location.pathname,
            user: me.id,
            action: trigger.getAttribute("data-resume"),
            at: Date.now(),
            fields: fieldsOf(trigger).map(function (f) {
              return [fieldKind(f), f.type === "password" ? null : f.type === "checkbox" ? f.checked : f.value];
            }),
          }),
        );
        noted = true;
      } catch (e) {
        // Without storage the page comes back as before, without the change.
      }
    }
    goToLogin(true, noted);
  }

  // The change noted before signing in again, when this load is the way back
  // from that sign-in. Taken once, so a reload doesn't start it again.
  function takeNoted() {
    var back = new URLSearchParams(location.search).has("resume");
    if (back) history.replaceState(null, "", location.pathname + location.hash);
    var saved = null;
    try {
      saved = JSON.parse(sessionStorage.getItem(RESUME) || "null");
      sessionStorage.removeItem(RESUME);
    } catch (e) {
      return null;
    }
    if (!back || !saved || saved.page !== location.pathname || typeof saved.action !== "string" || !Array.isArray(saved.fields)) return null;
    var age = Date.now() - saved.at;
    return age >= 0 && age < RESUME_MS ? saved : null;
  }

  function carryOn(saved) {
    if (!saved || !me || saved.user !== me.id) return;
    var target = Array.prototype.find.call(root.querySelectorAll("[data-resume]"), function (n) {
      return n.getAttribute("data-resume") === saved.action;
    });
    if (!target) return;
    var whole = true;
    var retype = null;
    saved.fields.forEach(function (s, i) {
      // Read the fields again each time: choosing a service redraws its scopes.
      var f = fieldsOf(target)[i];
      if (!whole || !f || fieldKind(f) !== s[0]) {
        whole = false;
        return;
      }
      if (s[1] === null) retype = retype || f;
      else if (f.type === "checkbox") f.checked = s[1];
      else {
        f.value = s[1];
        if (f.tagName === "SELECT") f.dispatchEvent(new Event("change"));
      }
    });
    if (fieldsOf(target).length !== saved.fields.length) whole = false;
    target.scrollIntoView({ block: "center" });
    if (!whole || retype) {
      (retype || fieldsOf(target)[0] || target).focus();
      return;
    }
    // A click or submit runs its handler, and so act, before it returns.
    resuming = true;
    try {
      if (target.tagName === "FORM") target.requestSubmit();
      else target.click();
    } finally {
      resuming = false;
    }
  }

  function flash(kind, message) {
    var glyph = kind === "success" ? "check" : kind === "notice" ? "info" : "alert";
    return el("p", { class: kind, role: kind === "error" ? "alert" : "status" }, icon(glyph), el("span", {}, message));
  }

  function status() {
    return el("p", { class: "error", role: "alert", hidden: true });
  }

  function say(node, message, kind) {
    node.className = kind === "ok" ? "success" : "error";
    clear(node);
    if (message) node.append(icon(kind === "ok" ? "check" : "alert"), el("span", {}, message));
    node.hidden = !message;
  }

  // Runs an action with its button disabled, and shows a failure in `out`.
  // One that needs a recent sign-in goes to sign in again, and carries on
  // after it (signInAgain).
  async function act(button, out, fn) {
    var again = resuming;
    if (out) say(out, "");
    if (button) button.disabled = true;
    try {
      await fn();
    } catch (e) {
      if (e instanceof ApiError && e.code === "reauth_required" && !again) {
        signInAgain(button && button.closest("[data-resume]"));
        return;
      }
      if (out && !(e instanceof ApiError && e.status === 401)) say(out, (e && e.message) || "That didn't work.");
    } finally {
      if (button) button.disabled = false;
    }
  }

  function secretBox(title, value) {
    var copy = el("button", { type: "button", class: "secondary sm" }, icon("copy"), "Copy");
    copy.addEventListener("click", async function () {
      clear(copy);
      try {
        await navigator.clipboard.writeText(value);
        copy.append(icon("done"), "Copied");
      } catch (e) {
        copy.append("Select the text and copy it");
      }
    });
    var box = el(
      "div",
      { class: "secret", role: "status" },
      el("strong", {}, icon("key"), title),
      el("p", { class: "hint" }, "Shown only now. Hand it over safely before you leave this page."),
      el("pre", {}, value),
    );
    var done = el("button", { type: "button", class: "secondary sm" }, "Done");
    done.addEventListener("click", function () {
      box.remove();
    });
    box.append(el("div", { class: "actions" }, copy, done));
    return box;
  }

  function options(values, selected) {
    return values.map(function (v) {
      return el("option", { value: v, selected: v === selected }, v);
    });
  }

  function serviceNamed(name) {
    return services.find(function (s) {
      return s.name === name;
    });
  }

  function table(headers, rows) {
    return el(
      "div",
      { class: "table-wrap" },
      el(
        "table",
        {},
        el(
          "thead",
          {},
          el(
            "tr",
            {},
            headers.map(function (h) {
              return el("th", { scope: "col" }, h);
            }),
          ),
        ),
        el("tbody", {}, rows),
      ),
    );
  }

  function box(title, body) {
    var b = el("div", { class: "box" }, title ? el("div", { class: "box-header" }, el("h3", { class: "box-title" }, title)) : null);
    for (var i = 1; i < arguments.length; i++) append(b, arguments[i]);
    return b;
  }

  // A danger-zone row: what the action does, and its button.
  function zoneRow(title, detail, action) {
    return el(
      "div",
      { class: "box-row" },
      el("div", { class: "row-main" }, el("div", { class: "row-title" }, title), detail ? el("p", { class: "hint" }, detail) : null),
      action,
    );
  }

  function code(value) {
    return value ? el("code", {}, value) : "—";
  }

  // --------------------------------------------------------------- tabs

  var tabs = el("nav", { class: "tabs", "aria-label": "Admin sections" });
  var view = el("div", { class: "view" });
  var TABS = [
    ["users", "Users", showUsers],
    ["invites", "Invitations", showInvites],
    ["services", "Services", showServices],
    ["audit", "Audit log", showAudit],
  ];

  // A tab, or with "users/<id>" one user: the hash says which, so a reload,
  // or signing in again on the way, comes back to it.
  function go(name) {
    var parts = (name || "").split("/");
    var tab =
      TABS.find(function (t) {
        return t[0] === parts[0];
      }) || TABS[0];
    var user = tab[0] === "users" && parts.length === 2 && parts[1] ? parts[1] : null;
    Array.prototype.forEach.call(tabs.children, function (b) {
      if (b.dataset.tab === tab[0]) b.setAttribute("aria-current", "page");
      else b.removeAttribute("aria-current");
    });
    var hash = "#" + tab[0] + (user ? "/" + user : "");
    if (location.hash !== hash) history.replaceState(null, "", hash);
    clear(view);
    return (user ? showUser(user) : tab[2]()).catch(function (e) {
      if (e instanceof ApiError && e.status === 401) return;
      view.append(flash("error", (e && e.message) || "Couldn't load this."));
    });
  }

  // Back, forward and links to #users, #audit… switch tabs too.
  window.addEventListener("hashchange", function () {
    if (services.length) go(location.hash.slice(1));
  });

  TABS.forEach(function (t) {
    var b = el("button", { type: "button", "data-tab": t[0] }, t[1]);
    b.addEventListener("click", function () {
      go(t[0]);
    });
    tabs.append(b);
  });

  // -------------------------------------------------------------- users

  async function showUsers() {
    view.append(el("h2", { class: "sr-only" }, "Users"));
    var q = el("input", { type: "search", placeholder: "Username, name or email", maxlength: "254" });
    var search = el("button", { type: "submit", class: "secondary" }, "Search");
    var out = status();
    var list = el("ul", { class: "rows" });
    var more = el("button", { type: "button", class: "secondary", hidden: true }, "More");
    var form = el("form", { class: "inline", role: "search" }, el("label", { class: "grow" }, el("span", { class: "sr-only" }, "Find"), q), search);
    var next = null;
    async function load(reset) {
      if (reset) {
        clear(list);
        next = null;
      }
      var params = new URLSearchParams({ q: q.value.trim(), limit: "50" });
      if (next) params.set("after", next);
      var data = await api("GET", "/v1/users?" + params.toString());
      data.items.forEach(function (u) {
        var open = el("button", { type: "button", class: "link" }, u.username);
        open.addEventListener("click", function () {
          go("users/" + u.id);
        });
        var detail = [u.name, u.email].filter(Boolean).join(" · ");
        list.append(
          el(
            "li",
            {},
            el(
              "div",
              { class: "row-lead" },
              el("span", { class: "avatar sm", "aria-hidden": "true" }, initials(u.name, u.username)),
              el("div", { class: "row-main" }, el("div", { class: "row-title" }, open, userTags(u)), detail ? el("p", { class: "hint" }, detail) : null),
            ),
          ),
        );
      });
      if (list.children.length === 0) list.append(el("li", { class: "blank" }, "No users found."));
      next = data.next;
      more.hidden = !next;
    }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(search, out, function () {
        return load(true);
      });
    });
    more.addEventListener("click", function () {
      act(more, out, function () {
        return load(false);
      });
    });
    view.append(createUserForm(), el("div", { class: "toolbar" }, form), out, list, el("div", { class: "actions" }, more));
    await load(true);
  }

  function createUserForm() {
    var out = status();
    var kind = el("select", {}, el("option", { value: "person" }, "Person"), el("option", { value: "bot" }, "Bot"));
    var username = el("input", { required: true, maxlength: "32", pattern: "[a-z][a-z0-9\\-]{1,30}[a-z0-9]", autocomplete: "off" });
    var name = el("input", { maxlength: "200", autocomplete: "off" });
    var email = el("input", { type: "email", maxlength: "254", required: true, autocomplete: "off" });
    var owner = el("input", { maxlength: "40", placeholder: "usr_… (default: you)", autocomplete: "off" });
    var emailLabel = el("label", {}, "Email (gets an activation link)", email);
    var ownerLabel = el("label", { hidden: true }, "Owner's user id", owner);
    kind.addEventListener("change", function () {
      var bot = kind.value === "bot";
      emailLabel.hidden = bot;
      email.required = !bot;
      ownerLabel.hidden = !bot;
    });
    var create = el("button", { type: "submit" }, "Create user");
    var form = el(
      "form",
      {},
      el("label", {}, "Kind", kind),
      el("label", {}, "Username", username),
      el("p", { class: "hint" }, "3–32 characters: a–z, 0–9 and '-'. It can never change."),
      el("label", {}, "Name", name),
      emailLabel,
      ownerLabel,
      create,
      out,
    );
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(create, out, async function () {
        var body = { username: username.value.trim(), name: name.value.trim(), kind: kind.value };
        if (kind.value === "person") body.email = email.value.trim();
        else if (owner.value.trim()) body.owner_id = owner.value.trim();
        var u = await api("POST", "/v1/users", body);
        username.value = "";
        name.value = "";
        email.value = "";
        owner.value = "";
        say(out, "Created " + u.username + (u.kind === "person" ? ". An activation link is on its way to " + u.email + "." : "."), "ok");
      });
    });
    return el("details", { class: "box" }, el("summary", {}, "Create a user"), form);
  }

  async function showUser(id) {
    clear(view);
    var back = el("button", { type: "button", class: "secondary sm" }, icon("back"), "All users");
    back.addEventListener("click", function () {
      go("users");
    });
    view.append(el("div", { class: "actions" }, back));
    var u = await api("GET", "/v1/users/" + encodeURIComponent(id));
    var out = status();
    var refresh = function () {
      return showUser(id);
    };
    var factors =
      u.kind === "person"
        ? el(
            "span",
            { class: "tags" },
            u.mfa.totp ? tag("authenticator app", "ok") : null,
            u.mfa.passkeys ? tag(u.mfa.passkeys + " passkey" + (u.mfa.passkeys === 1 ? "" : "s"), "ok") : null,
            !u.mfa.totp && !u.mfa.passkeys ? tag("none") : null,
            tag(u.mfa.recovery_codes + " recovery code" + (u.mfa.recovery_codes === 1 ? "" : "s") + " left"),
          )
        : null;
    view.append(
      el(
        "div",
        { class: "page-head" },
        el("span", { class: "avatar lg", "aria-hidden": "true" }, initials(u.name, u.username)),
        el(
          "div",
          {},
          el("h2", {}, u.username, " ", userTags(u)),
          u.name || u.email ? el("p", {}, [u.name, u.email].filter(Boolean).join(" · ")) : null,
        ),
      ),
      box(
        "Details",
        el(
          "dl",
          { class: "props" },
          el("dt", {}, "Id"),
          el("dd", {}, code(u.id)),
          el("dt", {}, "Name"),
          el("dd", {}, u.name || "—"),
          u.kind === "person" ? [el("dt", {}, "Email"), el("dd", {}, u.email || "—", u.email && !u.email_verified ? tag("not confirmed", "attention") : null)] : null,
          u.owner_id ? [el("dt", {}, "Owner"), el("dd", {}, code(u.owner_id))] : null,
          el("dt", {}, "Created"),
          el("dd", {}, when(u.created_at)),
          factors ? [el("dt", {}, "Second factors"), el("dd", {}, factors)] : null,
        ),
      ),
      out,
    );

    // Access
    var rows = u.access.map(function (a) {
      var remove = el("button", { type: "button", class: "danger sm" }, "Remove");
      remove.addEventListener("click", function () {
        if (!confirm("Remove " + u.username + "'s access to " + a.service + "?")) return;
        act(remove, out, async function () {
          await api("DELETE", "/v1/users/" + encodeURIComponent(u.id) + "/access/" + encodeURIComponent(a.service));
          await refresh();
        });
      });
      return el(
        "tr",
        {},
        el("td", {}, el("strong", {}, a.service)),
        el("td", {}, tag(a.role)),
        el("td", {}, code(a.granted_by)),
        el("td", {}, when(a.granted_at)),
        el("td", {}, remove),
      );
    });
    var svc = el(
      "select",
      {},
      options(
        services.map(function (s) {
          return s.name;
        }),
      ),
    );
    var role = el("select", {});
    function drawRoles() {
      clear(role);
      var s = serviceNamed(svc.value);
      var current = u.access.find(function (a) {
        return a.service === svc.value;
      });
      append(role, options(s ? s.roles : [], current ? current.role : undefined));
    }
    svc.addEventListener("change", drawRoles);
    drawRoles();
    var grant = el("button", { type: "submit" }, "Grant or change");
    var grantForm = el("form", { class: "inline" }, el("label", {}, "Service", svc), el("label", {}, "Role", role), grant);
    grantForm.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(grant, out, async function () {
        await api("PUT", "/v1/users/" + encodeURIComponent(u.id) + "/access/" + encodeURIComponent(svc.value), { role: role.value });
        await refresh();
      });
    });
    view.append(
      box(
        "Access",
        rows.length ? table(["Service", "Role", "Granted by", "Since", ""], rows) : el("p", { class: "box-body muted" }, "No access to any service."),
        el("div", { class: "box-footer" }, grantForm),
      ),
    );

    if (u.kind !== "person") {
      var held = u.access.map(function (a) {
        return a.service;
      });
      view.append(el("h3", {}, "App passwords"));
      await credentialPanel(view, u.id, "app-passwords", held);
      view.append(el("h3", {}, "API keys"));
      await credentialPanel(view, u.id, "api-keys", held);
    }

    // Account actions
    var zone = box(null);
    zone.className = "box danger";
    var toggle = el("button", { type: "button", class: u.disabled ? "secondary" : "danger" }, u.disabled ? "Enable" : "Disable");
    toggle.addEventListener("click", function () {
      if (!u.disabled && !confirm("Disable " + u.username + "? Their sessions, tokens, app passwords and keys stop at once.")) return;
      act(toggle, out, async function () {
        await api("PATCH", "/v1/users/" + encodeURIComponent(u.id), { disabled: !u.disabled });
        await refresh();
      });
    });
    var signout = el("button", { type: "button", class: "secondary" }, "Sign out everywhere");
    signout.addEventListener("click", function () {
      act(signout, out, async function () {
        await api("DELETE", "/v1/users/" + encodeURIComponent(u.id) + "/sessions");
        say(out, u.username + " is signed out everywhere.", "ok");
      });
    });
    var del = el("button", { type: "button", class: "danger" }, "Delete");
    del.addEventListener("click", function () {
      if (!confirm("Delete " + u.username + "? This can't be undone, and every service is told.")) return;
      act(del, out, async function () {
        await api("DELETE", "/v1/users/" + encodeURIComponent(u.id));
        go("users");
      });
    });
    zone.append(
      zoneRow(
        u.disabled ? "Enable this account" : "Disable this account",
        u.disabled ? "Lets " + u.username + " sign in again." : "Their sessions, tokens, app passwords and keys stop at once.",
        toggle,
      ),
      zoneRow("Sign out everywhere", "Ends every session " + u.username + " has.", signout),
    );

    if (u.kind === "person") {
      var sendLink = el("input", { type: "checkbox", checked: true });
      var clearMfa = el("input", { type: "checkbox" });
      var reset = el("button", { type: "submit", class: "danger" }, "Reset");
      var resetForm = el(
        "form",
        { class: "box-row" },
        el(
          "div",
          { class: "row-main" },
          el("div", { class: "row-title" }, "Reset sign-in"),
          el("p", { class: "hint" }, "Only after verifying the person out of band. This is audited and alerted."),
          el(
            "div",
            { class: "checks" },
            el("label", { class: "check" }, sendLink, "Email a password reset link"),
            el("label", { class: "check" }, clearMfa, "Clear their second factors (and sign them out)"),
          ),
        ),
        reset,
      );
      resetForm.addEventListener("submit", function (ev) {
        ev.preventDefault();
        act(reset, out, async function () {
          await api("POST", "/v1/users/" + encodeURIComponent(u.id) + "/reset", { send_link: sendLink.checked, clear_mfa: clearMfa.checked });
          await refresh();
          var o = view.querySelector("[role=alert]");
          if (o) say(o, "Done.", "ok");
        });
      });
      zone.append(resetForm);
    }
    zone.append(zoneRow("Delete this user", "This can't be undone, and every service is told.", del));
    view.append(el("h3", { class: "danger" }, "Danger zone"), zone);
  }

  async function credentialPanel(parent, userId, kind, held) {
    var isApw = kind === "app-passwords";
    var scopesField = isApw ? "app_password_scopes" : "api_key_scopes";
    var secretField = isApw ? "password" : "key";
    var base = "/v1/users/" + encodeURIComponent(userId) + "/" + kind;
    var usable = services.filter(function (s) {
      return held.indexOf(s.name) >= 0 && s[scopesField].length > 0;
    });
    var panel = el("div", { class: "box" });
    var out = status();
    var list = el("ul", { class: "rows" });
    var created = el("div", { class: "box-body" });
    var footer = el("div", { class: "box-footer" });
    panel.append(created, list, footer);
    parent.append(panel);
    async function load() {
      var data = await api("GET", base);
      clear(list);
      if (data.items.length === 0) list.append(el("li", { class: "blank" }, "None."));
      data.items.forEach(function (c) {
        var rm = el("button", { type: "button", class: "danger sm", "data-resume": kind + "-revoke:" + c.id }, "Revoke");
        rm.addEventListener("click", function () {
          if (!confirm("Revoke " + c.name + "?")) return;
          act(rm, out, async function () {
            await api("DELETE", base + "/" + encodeURIComponent(c.id));
            await load();
          });
        });
        var meta = "Last used " + when(c.last_used_at);
        if (!isApw) meta += c.expires_at ? " · expires " + when(c.expires_at) : " · no expiry";
        list.append(
          el(
            "li",
            {},
            el(
              "div",
              { class: "row-lead" },
              el("span", { class: "row-icon" }, icon(isApw ? "lock" : "key")),
              el(
                "div",
                { class: "row-main" },
                el("div", { class: "row-title" }, el("span", {}, c.name)),
                el("span", { class: "tags" }, tag(c.service, "accent"), tags(c.scopes)),
                el("p", { class: "hint" }, meta),
              ),
            ),
            rm,
          ),
        );
      });
    }
    if (usable.length === 0) {
      footer.append(el("p", { class: "hint" }, "Give this bot a role on a service that takes " + (isApw ? "app passwords" : "API keys") + " first."), out);
      return load();
    }
    var name = el("input", { required: true, maxlength: "100" });
    var svc = el(
      "select",
      {},
      options(
        usable.map(function (s) {
          return s.name;
        }),
      ),
    );
    var scopes = el("fieldset", {});
    function drawScopes() {
      clear(scopes);
      scopes.append(el("legend", {}, "Scopes"));
      var s = serviceNamed(svc.value);
      (s ? s[scopesField] : []).forEach(function (sc) {
        scopes.append(el("label", { class: "check" }, el("input", { type: "checkbox", value: sc, checked: true }), sc));
      });
    }
    svc.addEventListener("change", drawScopes);
    drawScopes();
    var expires = el("input", { type: "date" });
    var create = el("button", { type: "submit" }, isApw ? "Create app password" : "Create API key");
    var form = el(
      "form",
      { class: "narrow", "data-resume": kind },
      el("label", {}, "Name", name),
      el("label", {}, "Service", svc),
      scopes,
      isApw ? null : el("label", {}, "Expires (optional)", expires),
      create,
      out,
    );
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(create, out, async function () {
        var picked = Array.prototype.slice.call(scopes.querySelectorAll("input:checked")).map(function (i) {
          return i.value;
        });
        if (picked.length === 0) throw new Error("Choose at least one scope.");
        var body = { name: name.value.trim(), service: svc.value, scopes: picked };
        if (!isApw && expires.value) body.expires_at = expires.value + "T23:59:59Z";
        var c = await api("POST", base, body);
        name.value = "";
        clear(created);
        created.append(secretBox((isApw ? "App password" : "API key") + " for " + c.service + ": " + c.name, c[secretField]));
        await load();
      });
    });
    footer.append(form);
    return load();
  }

  // ------------------------------------------------------------ invites

  async function showInvites() {
    view.append(el("h2", { class: "sr-only" }, "Invitations"));
    var out = status();
    var open = services.filter(function (s) {
      return s.signup !== "closed";
    });
    var email = el("input", { type: "email", required: true, maxlength: "254", autocomplete: "off" });
    var svc = el(
      "select",
      {},
      options(
        open.map(function (s) {
          return s.name;
        }),
      ),
    );
    var role = el("select", {});
    function drawRoles() {
      clear(role);
      var s = serviceNamed(svc.value);
      append(role, options(s ? s.roles : [], s && s.roles[0]));
    }
    svc.addEventListener("change", drawRoles);
    drawRoles();
    var send = el("button", { type: "submit" }, "Send invitation");
    var form = el("form", { class: "inline" }, el("label", { class: "grow" }, "Email", email), el("label", {}, "Service", svc), el("label", {}, "Role", role), send, out);
    var list = el("div");
    var more = el("button", { type: "button", class: "secondary", hidden: true }, "More");
    var rows = [];
    var next = null;
    async function load(reset) {
      if (reset) {
        rows = [];
        next = null;
      }
      var params = new URLSearchParams({ limit: "50" });
      if (next) params.set("after", next);
      var data = await api("GET", "/v1/invites?" + params.toString());
      data.items.forEach(function (i) {
        var del = el("button", { type: "button", class: "danger sm" }, "Delete");
        del.addEventListener("click", function () {
          if (!confirm("Delete the invitation to " + i.email + "?")) return;
          act(del, out, async function () {
            await api("DELETE", "/v1/invites/" + encodeURIComponent(i.id));
            await load(true);
          });
        });
        rows.push(
          el(
            "tr",
            {},
            el("td", {}, i.email),
            el("td", {}, el("span", { class: "tags" }, tag(i.service, "accent"), tag(i.role))),
            el("td", {}, i.accepted_at ? [tag("accepted", "ok"), " ", el("span", { class: "muted" }, when(i.accepted_at))] : el("span", { class: "muted" }, "expires " + when(i.expires_at))),
            el("td", {}, code(i.accepted_by)),
            el("td", {}, del),
          ),
        );
      });
      next = data.next;
      more.hidden = !next;
      clear(list);
      list.append(rows.length ? table(["Email", "Access", "State", "Accepted by", ""], rows) : el("p", { class: "callout muted" }, "No invitations."));
    }
    var invite;
    if (open.length === 0) invite = el("p", { class: "notice" }, icon("info"), el("span", {}, "Every service is closed to sign-up, so none takes invitations."));
    else {
      form.addEventListener("submit", function (ev) {
        ev.preventDefault();
        act(send, out, async function () {
          var i = await api("POST", "/v1/invites", { email: email.value.trim(), service: svc.value, role: role.value });
          email.value = "";
          say(out, "Invitation " + i.id + " sent to " + i.email + ".", "ok");
          await load(true);
        });
      });
      invite = box("Invite someone", el("div", { class: "box-body" }, form));
    }
    more.addEventListener("click", function () {
      act(more, out, function () {
        return load(false);
      });
    });
    view.append(invite, el("h3", {}, "Sent"), list, el("div", { class: "actions" }, more));
    await load(true);
  }

  // ----------------------------------------------------------- services

  async function showServices() {
    view.append(el("h2", { class: "sr-only" }, "Services"), el("p", { class: "muted" }, "From the deployment's services file; it changes with a restart."));
    var grid = el("div", { class: "services-grid" });
    services.forEach(function (s) {
      var signup = s.signup === "open" ? "ok" : s.signup === "invite" ? "accent" : null;
      grid.append(
        el(
          "div",
          { class: "box" },
          el(
            "div",
            { class: "box-header" },
            el("h3", { class: "box-title" }, s.name),
            el("span", { class: "tags" }, tag("sign-up " + s.signup, signup), s.manages_own_members ? tag("manages own members") : null),
          ),
          el(
            "dl",
            { class: "props" },
            el("dt", {}, "Roles"),
            el("dd", {}, tags(s.roles), el("p", { class: "hint" }, "Lowest first.")),
            el("dt", {}, "Need MFA"),
            el("dd", {}, s.mfa_roles.length ? tags(s.mfa_roles, "attention") : "none"),
            s.default_role ? [el("dt", {}, "Default role"), el("dd", {}, tag(s.default_role))] : null,
            s.app_password_scopes.length ? [el("dt", {}, "App password scopes"), el("dd", {}, tags(s.app_password_scopes))] : null,
            s.api_key_scopes.length ? [el("dt", {}, "API key scopes"), el("dd", {}, tags(s.api_key_scopes))] : null,
            s.events_url ? [el("dt", {}, "Events"), el("dd", {}, code(s.events_url))] : null,
          ),
          s.clients.length
            ? el(
                "ul",
                { class: "rows" },
                s.clients.map(function (c) {
                  return el(
                    "li",
                    {},
                    el(
                      "div",
                      { class: "row-main" },
                      el("div", { class: "row-title" }, code(c.id), tag(c.type)),
                      c.redirect_uris.map(function (uri) {
                        return el("p", { class: "hint" }, el("code", {}, uri));
                      }),
                    ),
                  );
                }),
              )
            : null,
        ),
      );
    });
    view.append(grid);
  }

  // -------------------------------------------------------------- audit

  async function showAudit() {
    view.append(el("h2", { class: "sr-only" }, "Audit log"));
    var user = el("input", { placeholder: "usr_…", maxlength: "40", autocomplete: "off" });
    var filter = el("button", { type: "submit", class: "secondary" }, "Filter");
    var out = status();
    var form = el("form", { class: "inline" }, el("label", {}, "User id", user), filter);
    var holder = el("div");
    var more = el("button", { type: "button", class: "secondary", hidden: true }, "More");
    var rows = [];
    var next = null;
    async function load(reset) {
      if (reset) {
        rows = [];
        next = null;
      }
      var params = new URLSearchParams({ limit: "100" });
      if (user.value.trim()) params.set("user", user.value.trim());
      if (next) params.set("after", next);
      var data = await api("GET", "/v1/audit?" + params.toString());
      data.items.forEach(function (r) {
        var detail = JSON.stringify(r.detail);
        rows.push(
          el(
            "tr",
            {},
            el("td", { title: r.at }, when(r.at, true)),
            el("td", {}, el("code", {}, r.action)),
            el("td", {}, code(r.actor)),
            el("td", {}, code(r.user_id)),
            el("td", {}, r.ip || "—"),
            el("td", { class: "wrap" }, detail === "{}" ? el("span", { class: "muted" }, "—") : el("code", {}, detail)),
          ),
        );
      });
      next = data.next;
      more.hidden = !next;
      clear(holder);
      holder.append(rows.length ? table(["When", "Action", "Actor", "User", "Address", "Detail"], rows) : el("p", { class: "callout muted" }, "Nothing logged."));
    }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      act(filter, out, function () {
        return load(true);
      });
    });
    more.addEventListener("click", function () {
      act(more, out, function () {
        return load(false);
      });
    });
    view.append(el("div", { class: "toolbar" }, form), out, holder, el("div", { class: "actions" }, more));
    await load(true);
  }

  // -------------------------------------------------------------- start

  (async function start() {
    clear(root);
    root.append(
      el("div", { class: "page-head" }, el("div", {}, el("h1", {}, "Administration"), el("p", {}, "Users, their access to each service, invitations and the audit log."))),
      tabs,
      view,
    );
    var noted = takeNoted();
    try {
      // Who is signed in: a change noted before signing in again carries on
      // only for the same person.
      var loaded = await Promise.all([api("GET", "/v1/services"), api("GET", "/v1/me")]);
      services = loaded[0].items;
      me = loaded[1];
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return;
      view.append(flash("error", (e && e.message) || "Couldn't load the services."));
      return;
    }
    await go(location.hash.slice(1));
    carryOn(noted);
  })();
})();
