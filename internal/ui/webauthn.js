// zeroauthy hosted WebAuthn page script (Plan 33b spec section 5.2).
// It is the only script that runs WebAuthn on hosted pages and is inlined
// with the page's CSP nonce. It reads its options from the page's JSON
// document #za-webauthn (type application/json), runs the ceremony, and
// posts the result through the page's ordinary form #za-webauthn-form:
// "credential" carries the PublicKeyCredential JSON, "webauthn_error" only
// the name of a DOMException. It never uses fetch or any other network API.
(function () {
  "use strict";
  var doc = document.getElementById("za-webauthn");
  var form = document.getElementById("za-webauthn-form");
  if (!doc || !form) {
    return;
  }
  var cfg;
  try {
    cfg = JSON.parse(doc.textContent);
  } catch (e) {
    return;
  }
  var supported = typeof window.PublicKeyCredential === "function" &&
    !!navigator.credentials && typeof navigator.credentials.get === "function";

  function fromB64url(s) {
    var b64 = String(s).replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) {
      b64 += "=";
    }
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out.buffer;
  }

  function toB64url(buf) {
    if (!buf) {
      return null;
    }
    var bytes = new Uint8Array(buf);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function descriptors(list) {
    return (list || []).map(function (d) {
      var out = { type: d.type, id: fromB64url(d.id) };
      if (d.transports) {
        out.transports = d.transports;
      }
      return out;
    });
  }

  function requestOptions(o) {
    if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
      return PublicKeyCredential.parseRequestOptionsFromJSON(o);
    }
    var out = {};
    for (var k in o) {
      out[k] = o[k];
    }
    out.challenge = fromB64url(o.challenge);
    out.allowCredentials = descriptors(o.allowCredentials);
    return out;
  }

  function creationOptions(o) {
    if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
      return PublicKeyCredential.parseCreationOptionsFromJSON(o);
    }
    var out = {};
    for (var k in o) {
      out[k] = o[k];
    }
    out.challenge = fromB64url(o.challenge);
    out.user = { id: fromB64url(o.user.id), name: o.user.name, displayName: o.user.displayName };
    out.excludeCredentials = descriptors(o.excludeCredentials);
    return out;
  }

  // serialize is the section 4.1 JSON of a credential: toJSON where the
  // browser has it, the same members by hand otherwise.
  function serialize(cred) {
    if (typeof cred.toJSON === "function") {
      try {
        return JSON.stringify(cred.toJSON());
      } catch (e) {
        // fall through to the manual form
      }
    }
    var r = cred.response;
    var response = { clientDataJSON: toB64url(r.clientDataJSON) };
    if (r.attestationObject) {
      response.attestationObject = toB64url(r.attestationObject);
      if (typeof r.getTransports === "function") {
        response.transports = r.getTransports();
      }
    } else {
      response.authenticatorData = toB64url(r.authenticatorData);
      response.signature = toB64url(r.signature);
      response.userHandle = toB64url(r.userHandle);
    }
    var out = {
      id: cred.id,
      rawId: toB64url(cred.rawId),
      type: cred.type,
      response: response,
      clientExtensionResults: typeof cred.getClientExtensionResults === "function" ? cred.getClientExtensionResults() : {}
    };
    if (cred.authenticatorAttachment) {
      out.authenticatorAttachment = cred.authenticatorAttachment;
    }
    return JSON.stringify(out);
  }

  function field(name, value) {
    var input = form.elements.namedItem(name);
    if (input) {
      input.value = value;
    }
  }

  var sent = false;
  function post(name, value) {
    if (sent) {
      return;
    }
    sent = true;
    abortPending();
    field(name, value);
    // HTMLFormElement.submit() posts the normal form without firing submit
    // listeners; no request is made from script.
    form.submit();
  }

  function report(err) {
    post("webauthn_error", err && typeof err.name === "string" ? err.name : "UnknownError");
  }

  // pending aborts a conditional (autofill) request before any other form
  // submit or button ceremony.
  var pending = null;
  function abortPending() {
    if (pending) {
      var p = pending;
      pending = null;
      p.abort();
    }
  }
  document.addEventListener("submit", function (ev) {
    if (ev.target !== form) {
      abortPending();
    }
  }, true);

  function show(el) {
    if (el) {
      el.hidden = false;
    }
  }

  function autofill() {
    if (typeof PublicKeyCredential.isConditionalMediationAvailable !== "function" || typeof AbortController !== "function") {
      return;
    }
    PublicKeyCredential.isConditionalMediationAvailable().then(function (ok) {
      if (!ok || sent) {
        return;
      }
      var ctrl = new AbortController();
      pending = ctrl;
      navigator.credentials.get({ mediation: "conditional", publicKey: requestOptions(cfg.publicKey), signal: ctrl.signal }).then(function (cred) {
        if (pending === ctrl && cred) {
          pending = null;
          post("credential", serialize(cred));
        }
      }, function () {
        // An aborted or refused autofill request leaves the page as it is.
        if (pending === ctrl) {
          pending = null;
        }
      });
    }, function () {});
  }

  function login() {
    if (cfg.mediation === "conditional") {
      autofill();
    }
    var button = document.getElementById("za-passkey-button");
    if (!cfg.button || !button) {
      return;
    }
    show(button);
    button.addEventListener("click", function (ev) {
      ev.preventDefault();
      abortPending();
      navigator.credentials.get({ publicKey: requestOptions(cfg.publicKey) }).then(function (cred) {
        post("credential", serialize(cred));
      }, report);
    });
  }

  function create() {
    var button = document.getElementById("za-passkey-create");
    if (!button) {
      return;
    }
    if (typeof navigator.credentials.create !== "function") {
      return;
    }
    show(button);
    button.addEventListener("click", function (ev) {
      ev.preventDefault();
      navigator.credentials.create({ publicKey: creationOptions(cfg.publicKey) }).then(function (cred) {
        post("credential", serialize(cred));
      }, report);
    });
  }

  if (!supported) {
    return;
  }
  if (cfg.mode === "login") {
    login();
  } else if (cfg.mode === "create") {
    create();
  }
})();
