// zeroauthy WebAuthn MFA page script (Plan 33b). It is inlined with the
// page's CSP nonce and reads its options from the JSON data block
// <script type="application/json" id="za-webauthn">. It never calls fetch:
// every result is posted with the page's own form (state, csrf,
// hosted_revision), the credential in the hidden "credential" field and a
// browser failure as the DOMException name only in "webauthn_error".
(function () {
  "use strict";
  var data = document.getElementById("za-webauthn");
  var form = document.getElementById("za-webauthn-form");
  if (!data || !form) {
    return;
  }
  var cfg;
  try {
    cfg = JSON.parse(data.textContent);
  } catch (e) {
    return;
  }
  var PKC = window.PublicKeyCredential;

  function field(name) {
    return form.elements.namedItem(name);
  }

  function toBase64URL(buffer) {
    var bytes = new Uint8Array(buffer);
    var text = "";
    for (var i = 0; i < bytes.length; i++) {
      text += String.fromCharCode(bytes[i]);
    }
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function fromBase64URL(value) {
    var text = value.replace(/-/g, "+").replace(/_/g, "/");
    while (text.length % 4) {
      text += "=";
    }
    var raw = atob(text);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) {
      bytes[i] = raw.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function descriptors(list) {
    return (list || []).map(function (d) {
      var out = { type: d.type, id: fromBase64URL(d.id) };
      if (d.transports) {
        out.transports = d.transports;
      }
      return out;
    });
  }

  function creationOptions(o) {
    if (PKC && typeof PKC.parseCreationOptionsFromJSON === "function") {
      return PKC.parseCreationOptionsFromJSON(o);
    }
    var out = Object.assign({}, o);
    out.challenge = fromBase64URL(o.challenge);
    out.user = Object.assign({}, o.user, { id: fromBase64URL(o.user.id) });
    out.excludeCredentials = descriptors(o.excludeCredentials);
    return out;
  }

  function requestOptions(o) {
    if (PKC && typeof PKC.parseRequestOptionsFromJSON === "function") {
      return PKC.parseRequestOptionsFromJSON(o);
    }
    var out = Object.assign({}, o);
    out.challenge = fromBase64URL(o.challenge);
    out.allowCredentials = descriptors(o.allowCredentials);
    return out;
  }

  function serialize(credential) {
    var r = credential.response;
    var out = {
      id: credential.id,
      rawId: toBase64URL(credential.rawId),
      type: credential.type,
      response: { clientDataJSON: toBase64URL(r.clientDataJSON) },
      clientExtensionResults: {}
    };
    if (credential.authenticatorAttachment) {
      out.authenticatorAttachment = credential.authenticatorAttachment;
    }
    if (r.attestationObject) {
      out.response.attestationObject = toBase64URL(r.attestationObject);
      if (typeof r.getTransports === "function") {
        out.response.transports = r.getTransports();
      }
    }
    if (r.authenticatorData) {
      out.response.authenticatorData = toBase64URL(r.authenticatorData);
      out.response.signature = toBase64URL(r.signature);
      out.response.userHandle = r.userHandle ? toBase64URL(r.userHandle) : null;
    }
    return JSON.stringify(out);
  }

  function failed(err) {
    var name = "UnknownError";
    if (typeof DOMException !== "undefined" && err instanceof DOMException && typeof err.name === "string") {
      name = err.name;
    }
    field("webauthn_error").value = name;
    form.submit();
  }

  if (cfg.mode === "detect") {
    if (!PKC || !navigator.credentials) {
      form.submit();
      return;
    }
    field("webauthn").value = "yes";
    var check = typeof PKC.isUserVerifyingPlatformAuthenticatorAvailable === "function"
      ? PKC.isUserVerifyingPlatformAuthenticatorAvailable()
      : Promise.resolve(false);
    check.then(function (available) {
      if (available) {
        field("platform").value = "yes";
      }
    }, function () {}).then(function () {
      form.submit();
    });
    return;
  }

  var start = document.getElementById("za-webauthn-start");
  var status = document.getElementById("za-webauthn-status");
  if (!start) {
    return;
  }
  var busy = false;
  start.hidden = false;
  start.addEventListener("click", function () {
    if (busy) {
      return;
    }
    busy = true;
    start.disabled = true;
    if (status) {
      status.hidden = false;
    }
    var ceremony;
    try {
      ceremony = cfg.mode === "create"
        ? navigator.credentials.create({ publicKey: creationOptions(cfg.publicKey) })
        : navigator.credentials.get({ publicKey: requestOptions(cfg.publicKey) });
    } catch (err) {
      failed(err);
      return;
    }
    ceremony.then(function (credential) {
      field("credential").value = serialize(credential);
      form.submit();
    }, failed);
  });
})();
