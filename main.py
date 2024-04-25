from flask import Flask, render_template, request, redirect, url_for, session, send_file
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import shutil
import secrets

app = Flask(__name__)
app.secret_key = "your_secret_key"


def derive_key(password):
    password = password.encode('utf-8')
    salt = b'salt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password)
    return key


def generate_iv():
    return secrets.token_bytes(16)


def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    iv = generate_iv()
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv))  # Switched back to CFB8
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as file:
        file.write(iv + ciphertext)




def decrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()

    iv = data[:16]
    ciphertext = data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv))  # Switched back to CFB8
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()


    decrypted_directory = os.path.join(app.root_path, 'downloads')
    if not os.path.exists(decrypted_directory):
        os.makedirs(decrypted_directory)


    filename = os.path.basename(file_path)


    decrypted_file_path = os.path.join(decrypted_directory, filename[:-4])

    with open(decrypted_file_path, 'wb') as file:
        file.write(plaintext)


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == '123' and password == '123':
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error=True)
    return render_template('login.html', error=False)


@app.route('/home', methods=['GET', 'POST'])
def home():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        filename = file.filename
        file_path = os.path.join('uploads', filename)
        file.save(file_path)
        key = derive_key(session.get('username'))
        encrypt_file(file_path, key)
        os.remove(file_path)
    uploaded_files = [f for f in os.listdir('uploads') if os.path.isfile(os.path.join('uploads', f))]
    return render_template('home.html', uploaded_files=uploaded_files)


@app.route('/download/<filename>')
def download(filename):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    key = derive_key(session.get('username'))
    file_path = os.path.join('uploads', filename)
    decrypted_filename = filename[:-4]
    decrypted_file_path = os.path.join('downloads', decrypted_filename)
    decrypt_file(file_path, key)
    return send_file(decrypted_file_path, as_attachment=True)

@app.route('/delete/<filename>')
def delete(filename):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    file_path = os.path.join('uploads', filename)
    os.remove(file_path)
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session['logged_in'] = False
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)



