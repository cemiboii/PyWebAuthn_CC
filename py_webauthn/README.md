# PyWebAuthn_CC


Das Projekt PyWebAuthn_CC ist eine Umsetzung, welche im Zuge der Masterarbeit mit dem Thema Einführung und Implementierung des WebAuthn-Standards entwickelt wurde. Die Basis für diese Implementierung ist das GitHub-Repo des Unternehmens [Duo Labs](https://github.com/duo-labs/py_webauthn).



---

Das Projekt wurde rein für die Nutzung einer Container-basierten Umgebung entwickelt, sodass ein Container-Tool wie [Docker](https://www.docker.com/products/docker-desktop) notwendig ist.


Das Projekt besteht daher aus:
* Docker-Container
    * Webanwendung
    * WebAuthn
    * [mkcert](https://github.com/FiloSottile/mkcert)



---

Grundsätzlich ist es mit der Webanwendung möglich, die beiden Anwendungsfälle WebAuthn-Registrierung und WebAuthn-Authentisierung nach der offiziellen W3C WebAuthn-Spezifikation <https://www.w3.org/TR/webauthn-2> durchzuführen.




---

Die getesteten Browser, welche die Webanwendung und den WebAuthn-Standard unterstützen sind folgende:
* Safari
* [Firefox](https://www.mozilla.org/de/firefox/new/)
* [Chrome](https://www.google.de/chrome/)
* [Edge](https://www.microsoft.com/de-de/edge)

# Installation
Vor der erstmaligen Nutzung wird die Installation des WebAuthn-Pakets durch folgenden Befehl empfohlen:
`pip install webauthn`

Die Webanwendung und mkcert (Erstellung Zertifikate) werden installiert und gestartet durch folgende Vorgehensweise:
1. Docker installieren
2. `cd py_webauthn/flask_demo`
3. `docker-compose up -d --build`
4. `brew install mkcert`
5. Pfad (Projektpfad) für das Root-Zertifikat exportieren: `export CAROOT="~/PyWebAuthn_CC/py_webauthn/flask_demo/rootCA"`
6. gesetzten Pfad überprüfen: `mkcert -CAROOT`
7. Zertifikat für die CA (mkcert) hinterlegen: `mkcert -instal`
8. Webanwendung über [https://localhost:5000](https://localhost:5000) aufrufen


# Funktionen

Erstellung des `PublicKeyCredentialCreationOptions`-Objekts zur Weitergabe an den WebAuthn Client und der Funktion `navigator.credentials.create`:
```python=
   make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
       challenge,
       rp_name,
       rp_id,
       user_id,
       username,
       display_name,
       registration_date)
```
Erstellung des User-Objekts:
```python=
   webauthn_user = webauthn.WebAuthnUser(
       user.id,
       user.username,
       user.display_name,
       user.registration_date,
       user.credential_id,
       user.pub_key,
       user.sign_count,
       user.rp_id)
```

Erstellung des `PublicKeyCredentialRequestOptions`-Objekts zur Weitergabe an den WebAuthn Client und der Funktion `navigator.credentials.get`:
```python=
   webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
       webauthn_user,
       challenge)
```
Überprüfung des `AuthenticatorAttestationRespons`-Objekts:

```python=
   webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
       RP_ID,
       ORIGIN,
       registration_response,
       challenge
       trust_anchor_dir,
       trusted_attestation_cert_required,
       self_attestation_permitted,
       none_attestation_permitted,
       uv_required=False)  # User Verification

   try:
       webauthn_credential = webauthn_registration_response.verify()
   except Exception as e:
       return jsonify({'fail': 'Registrierung fehlgeschlagen. Error: {}'.format(e)})
```

Überprüfung des `AuthenticatorAssertionResponse`-Objekts:

```python=
   webauthn_user = webauthn.WebAuthnUser(
       user.ukey,
       user.username,
       user.display_name,
       user.registration_date,
       user.credential_id,
       user.pub_key,
       user.sign_count,
       user.rp_id)

   webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
       webauthn_user,
       assertion_response,
       challenge,
       origin,
       uv_required=False)  # User Verification

   try:
       sign_count = webauthn_assertion_response.verify()
   except Exception as e:
       return jsonify({'fail': 'Assertion failed. Error: {}'.format(e)})

# Update counter.
user.sign_count = sign_count
```

# Sonstiges
* Bei Problemen wird empfohlen, die zum Projekt zugehörige Ausarbeitung zu lesen
* Fehlende Funktionen:
    * [Token Binding ID](https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-tokenbinding)
    * Ed25519
