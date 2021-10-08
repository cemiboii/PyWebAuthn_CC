# Folgender Code stammt vom Unternehmen Duo Security und wurde unter dem Link https://github.com/duo-labs/py_webauthn von GitHub heruntergeladen. 
# Einige Abschnitte Stammen vom Autor der Arbeit "Implementierung und Einsatz des WebAuthn-Standard".
# Um welche Abschnitte es sich dabei handelt, ist der genannten Arbeit zu entnehmen.

import os
import sys


from flask import Flask
from flask import flash
from flask import jsonify
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask_login import LoginManager
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user
from datetime import datetime


import util

from db import db
from context import webauthn
from models import User



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}'.format(
    os.path.join(os.path.dirname(os.path.abspath(__name__)), 'webauthn.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
sk = os.environ.get('FLASK_SECRET_KEY')
app.secret_key = sk if sk else os.urandom(40)
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)


RP_ID = 'localhost'
RP_NAME = 'webauthn demo localhost'
ORIGIN = 'https://localhost:5000'

# Trust anchors (trusted attestation roots) should be
# placed in TRUST_ANCHOR_DIR.
TRUST_ANCHOR_DIR = 'trusted_attestation_roots'


@login_manager.user_loader
def load_user(user_id):
    try:
        int(user_id)
    except ValueError:
        return None

    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('Startseite.html')

@app.route('/Register.html')
def register():
    return render_template('Register.html')

@app.route('/Startseite.html')
def startseite():
    return render_template('/Startseite.html')

@app.route('/About.html')
def about():
    return render_template('/About.html')

@app.route('/Login.html')
def login():
    return render_template('/Login.html')

@app.route('/webauthn_begin_activate', methods=['POST'])
def webauthn_begin_activate():
    # MakeCredentialOptions
    username = request.form.get('register_username')
    display_name = request.form.get('register_display_name')

    #Inputvalidierung Username (Pflicht) und Display Name (keine Pflicht)
    if not util.validate_username(username):
        return make_response(jsonify({'fail': 'Ungültiger Username'}), 401)
    if not util.validate_display_name(display_name):
        display_name = "-"

    if User.query.filter_by(username=username).first():
        return make_response(jsonify({'fail': 'Benutzer bereits registriert'}), 401)

    #Sitzungsvariablen werden vor dem Start einer neuen Registrierung zurückgesetzt
    session.pop('register_ukey', None)
    session.pop('register_username', None)
    session.pop('register_display_name', None)
    session.pop('challenge', None)

    session['register_username'] = username
    session['register_display_name'] = display_name


    challenge = util.generate_challenge(32)
    ukey = util.generate_ukey()
    registration_date=datetime.now().strftime('%d.%m.%Y - %H:%M:%S')
    # Entfernen des Padding aus der gespeicherten Challenge, sodass ein Byte-Vergleich 
    # mit der URL-safe-without-padding-Challenge durchgeführt werden kann, die vom Browser zurückkommt.
    # Die gepaddete Version wird dennoch an den Browser weitergeben, so dass JS 
    # die Challenge ohne große Probleme in Binary dekodieren kann.
    session['challenge'] = challenge.rstrip('=')
    session['register_ukey'] = ukey

    #Erstellung des PublicKeyCredentialCreationOptions-Objekts
    make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
        challenge, RP_NAME, RP_ID, ukey, username, display_name,
        registration_date)
    return jsonify(make_credential_options.registration_dict)


@app.route('/webauthn_begin_assertion', methods=['POST'])
def webauthn_begin_assertion():
    username = request.form.get('login_username')
    
    #Inputvalidierung Username
    if not util.validate_username(username):
        return make_response(jsonify({'fail': 'Ungültiger Username'}), 401)

    user = User.query.filter_by(username=username).first()
    
    if not user:
        return make_response(jsonify({'fail': 'Benutzer nicht registriert'}), 401)
    if not user.credential_id:
        return make_response(jsonify({'fail': 'Unbekannte Credential-ID'}), 401)

    session.pop('challenge', None)

    challenge = util.generate_challenge(32)

    # Entfernen des Padding aus der in der Session gespeicherten Sitzung
    # siehe Kommentar in webauthn_begin_activate
    session['challenge'] = challenge.rstrip('=')
    # User formatieren 
    webauthn_user = webauthn.WebAuthnUser(
        user.ukey, user.username, user.display_name, user.registration_date,
        user.credential_id, user.pub_key, user.sign_count, user.rp_id)
    # Durchführung Attestation
    webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
        webauthn_user, challenge)

    return jsonify(webauthn_assertion_options.assertion_dict)


@app.route('/verify_credential_info', methods=['POST'])
def verify_credential_info():
    challenge = session['challenge']
    username = session['register_username']
    display_name = session['register_display_name']
    ukey = session['register_ukey']


    registration_response = request.form
    trust_anchor_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), TRUST_ANCHOR_DIR)
    trusted_attestation_cert_required = True
    self_attestation_permitted = True
    none_attestation_permitted = True

    # Überprüfung des AuthenticatorAttestationRespons-Objekts
    webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
        RP_ID,
        ORIGIN,
        registration_response,
        challenge,
        trust_anchor_dir,
        trusted_attestation_cert_required,
        self_attestation_permitted,
        none_attestation_permitted,
        uv_required=False)  # User Verification

    try:
        webauthn_credential = webauthn_registration_response.verify()
    except Exception as e:
        return jsonify({'fail': 'Registrierung fehlgeschlagen. Error: {}'.format(e)})

    # Step 17
    #
    # Prüfung ob credentialID bereits registriert ist.
    # Wird die Registrierung von Credentials angefordert die bereits für einen anderen 
    # Benutzer registriert ist SOLLTE die Relying Party den Vorgang abbrechen. 
    # Alternativ kann die RP akzeptieren, dann aber die alte löschen
    credential_id_exists = User.query.filter_by(
        credential_id=webauthn_credential.credential_id).first()
    if credential_id_exists:
        return make_response(jsonify({'fail': 'Credential-ID existiert bereits'}), 401)

    existing_user = User.query.filter_by(username=username).first()
    if not existing_user:
        if sys.version_info >= (3, 0):
            webauthn_credential.credential_id = str(
                webauthn_credential.credential_id, "utf-8")
            webauthn_credential.public_key = str(
                webauthn_credential.public_key, "utf-8")
        user = User(
            ukey=ukey,
            username=username,
            display_name=display_name,
            pub_key=webauthn_credential.public_key,
            credential_id=webauthn_credential.credential_id,
            sign_count=webauthn_credential.sign_count,
            rp_id=RP_ID,
            registration_date=datetime.now().strftime('%d.%m.%Y - %H:%M:%S'))
        db.session.add(user)
        db.session.commit()
    else:
        return make_response(jsonify({'fail': 'Benutzer bereits registriert'}), 401)

    flash('Erfolgreich registriert als {}.'.format(username))
    return jsonify({'success': 'Benutzer erfolgreich registriert'})


@app.route('/verify_assertion', methods=['POST'])
def verify_assertion():
    challenge = session.get('challenge')
    assertion_response = request.form
    credential_id = assertion_response.get('id')

    user = User.query.filter_by(credential_id=credential_id).first()
    if not user:
        return make_response(jsonify({'fail': 'Benutzer nicht registriert'}), 401)
    # User formatieren 
    webauthn_user = webauthn.WebAuthnUser(
        user.ukey, user.username, user.display_name, user.registration_date,
        user.credential_id, user.pub_key, user.sign_count, user.rp_id)

    # Durchführung Assertion
    webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
        webauthn_user,
        assertion_response,
        challenge,
        ORIGIN,
        uv_required=False)  # User Verification

    try:
        sign_count = webauthn_assertion_response.verify()
    except Exception as e:
        return jsonify({'fail': 'Assertion fehlgeschlagen. Error: {}'.format(e)})

    # Update counter
    user.sign_count = sign_count
    db.session.add(user)
    db.session.commit()

    login_user(user)

    return jsonify({
        'success':
        'Erfolgreich angemeldet als {}'.format(user.username)
    })


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    #Cert und Schlüssel
    context = ('/app/flask_demo/localhost+3.pem', '/app/flask_demo/localhost+3-key.pem')
    app.run(host='0.0.0.0', ssl_context=context, debug=True)
