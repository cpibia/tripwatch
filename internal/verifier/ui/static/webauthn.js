// Security keys and passkeys. A form marked data-webauthn carries a challenge the verifier made
// for this session; on submit the browser is asked for a key, and the form posts the key's
// answer as base64url fields, checked on the server. The forms stay hidden where the browser has
// no WebAuthn, so the code forms beside them remain the way in.
(function () {
  if (!window.PublicKeyCredential || !navigator.credentials) return;

  function decode(text) {
    var b64 = text.replace(/-/g, "+").replace(/_/g, "/");
    var bin = atob(b64 + "===".slice((b64.length + 3) % 4));
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function encode(buffer) {
    var bytes = new Uint8Array(buffer);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function credentials(form) {
    var list;
    try { list = JSON.parse(form.dataset.keys || "[]") || []; } catch (e) { list = []; }
    return list.map(function (k) {
      var c = { type: "public-key", id: decode(k.id) };
      if (k.transports) c.transports = k.transports;
      return c;
    });
  }

  function set(form, name, value) {
    form.querySelector('input[name="' + name + '"]').value = value;
  }

  // The prompt lives five minutes on the server; the browser gives up a little earlier.
  var timeout = 240000;

  function ask(form) {
    var challenge = decode(form.dataset.challenge);
    if (form.dataset.webauthn === "create") {
      var name = form.dataset.name;
      return navigator.credentials.create({ publicKey: {
        challenge: challenge,
        rp: { id: form.dataset.rp, name: "tripwatch" },
        user: { id: decode(form.dataset.user), name: name, displayName: name },
        // Ed25519 first, then P-256: the only two the verifier accepts.
        pubKeyCredParams: [{ type: "public-key", alg: -8 }, { type: "public-key", alg: -7 }],
        excludeCredentials: credentials(form),
        authenticatorSelection: { userVerification: "preferred", residentKey: "discouraged" },
        attestation: "none",
        timeout: timeout
      } }).then(function (cred) {
        var transports = cred.response.getTransports ? cred.response.getTransports() : [];
        set(form, "clientData", encode(cred.response.clientDataJSON));
        set(form, "attestation", encode(cred.response.attestationObject));
        set(form, "transports", transports.join(","));
      });
    }
    return navigator.credentials.get({ publicKey: {
      challenge: challenge,
      rpId: form.dataset.rp,
      allowCredentials: credentials(form),
      userVerification: "preferred",
      timeout: timeout
    } }).then(function (cred) {
      set(form, "credential", encode(cred.rawId));
      set(form, "clientData", encode(cred.response.clientDataJSON));
      set(form, "authenticatorData", encode(cred.response.authenticatorData));
      set(form, "signature", encode(cred.response.signature));
    });
  }

  document.querySelectorAll("form[data-webauthn]").forEach(function (form) {
    var error = form.querySelector("[data-webauthn-error]");
    var button = form.querySelector('button[type="submit"]');
    form.hidden = false;
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      if (error) error.hidden = true;
      button.disabled = true;
      ask(form).then(function () {
        form.submit();
      }, function (err) {
        button.disabled = false;
        if (!error) return;
        error.textContent = err && err.name === "InvalidStateError"
          ? "This key is registered already."
          : "The key did not answer: try again, or use a code.";
        error.hidden = false;
      });
    });
  });
})();
