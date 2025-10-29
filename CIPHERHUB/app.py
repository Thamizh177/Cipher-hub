from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, send_from_directory, after_this_request
from flask_mail import Mail, Message
import mysql.connector
import bcrypt
import random
import math
import os
import numpy as np
import json
import base64
from werkzeug.utils import secure_filename
from algorithms.hill_cipher.hill_encrypt import hill_cipher_encrypt
from algorithms.hill_cipher.hill_decrypt import hill_cipher_decrypt
from algorithms.caesar_cipher import caesar_encrypt, caesar_decrypt
from algorithms.rsa import RSAEncryption, RSADecryption
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from algorithms.aes.aes_encrypt import encrypt_text, encrypt_file, generate_key
from algorithms.aes.aes_decrypt import decrypt_text, decrypt_file
from werkzeug.utils import secure_filename
from algorithms.des.des_encrypt import encrypt_text, encrypt_file, generate_key
from algorithms.des.des_decrypt import decrypt_text, decrypt_file
from algorithms.hash_function.hash_functions import (
    hash_md5, hash_sha1, hash_sha256, hash_sha512, hash_sha3_256, hash_blake2b
)
from algorithms.morse_code import MorseCode

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Database connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="thamizh@0405",
    database="encryption_app"
)

# Add at the top of app.py after app creation
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

cursor = db.cursor()

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'vh11379satishverma@gmail.com'
app.config['MAIL_PASSWORD'] = 'ccyh hdjq xdfs qxsu'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

@app.route('/')
def login_page():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    identifier = request.form['identifier']  # Can be email or phone
    password = request.form['password'].encode('utf-8')

    # Query for user by email or phone
    cursor.execute("SELECT * FROM users WHERE email = %s OR phone = %s", (identifier, identifier))
    user = cursor.fetchone()

    if user:
        db_password = user[3].encode('utf-8')  # Assuming password is in the 4th column
        if bcrypt.checkpw(password, db_password):
            session['user'] = user[1]  # Assuming user name is in the 2nd column
            return redirect(url_for('home'))  # Redirect to the home page
        else:
            flash('Invalid password. Please try again.', 'danger')
            return redirect(url_for('login_page'))
    else:
        flash('Invalid email or phone number. Please try again.', 'danger')
        return redirect(url_for('login_page'))

@app.route('/home')
def home():
    if 'user' in session:
        return render_template('home.html', user=session['user'])
    else:
        return redirect(url_for('login_page'))  # Redirect to login if not logged in

@app.route('/signup', methods=['POST'])
def signup():
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    password = request.form['password'].encode('utf-8')

    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

    try:
        cursor.execute("INSERT INTO users (name, email, phone, password) VALUES (%s, %s, %s, %s)", 
                       (name, email, phone, hashed_password))
        db.commit()
        return redirect(url_for('login_page'))
    except mysql.connector.IntegrityError:
        flash('Email already exists. Please try again.', 'danger')
        return redirect(url_for('signup'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot_password.html')

    elif request.method == 'POST':
        email = request.form['email']

        # If OTP is provided, validate it
        otp = request.form.get('otp')
        if otp:
            if 'otp' in session and session['otp'] == int(otp) and session['email'] == email:
                return redirect(url_for('reset_password'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')
                return render_template('forgot_password.html', email=email, show_otp=True)

        # If OTP is not provided, generate and send OTP
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            otp = random.randint(100000, 999999)
            session['otp'] = otp
            session['email'] = email

            msg = Message('Password Reset OTP', sender='vh11379satishverma@gmail.com', recipients=[email])
            msg.body = f'Your OTP for password reset is {otp}'
            mail.send(msg)
            flash('An OTP has been sent to your email', 'success')
            return render_template('forgot_password.html', email=email, show_otp=True)
        else:
            flash('Email address not found', 'danger')
            return redirect(url_for('forgot_password'))

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'GET':
        return render_template('reset_password.html')

    elif request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('reset_password'))

        email = session.get('email')
        if email:
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
            db.commit()
            session.pop('otp', None)
            session.pop('email', None)
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login_page'))
        else:
            flash('Session expired. Please try again.', 'danger')
            return redirect(url_for('forgot_password'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have successfully logged out.', 'info')
    return redirect(url_for('login_page'))

@app.route('/hill_cipher', methods=['GET', 'POST'])
def hill_cipher():
    result = ""
    matrix_used = ""
    
    if request.method == 'POST':
        text = request.form['text']
        key_matrix = request.form['key_matrix']
        operation = request.form['operation']
        
        try:
            if not key_matrix:  # If no key matrix provided, generate a random one
                result, matrix_used = hill_cipher_encrypt(text)
            else:
                matrix_used = key_matrix
                if operation == 'encrypt':
                    result, matrix_used = hill_cipher_encrypt(text, key_matrix)
                elif operation == 'decrypt':
                    result = hill_cipher_decrypt(text, key_matrix)
        except ValueError as e:
            result = f"Error: {e}"

    return render_template('hill_cipher.html', result=result, key_matrix=matrix_used)

@app.route('/caesar', methods=['GET', 'POST'])
def caesar():
    result = None
    if request.method == 'POST':
        text = request.form['text']
        key = int(request.form['key'])
        action = request.form['action']

        if action == 'encrypt':
            result = caesar_encrypt(text, key)
        elif action == 'decrypt':
            result = caesar_decrypt(text, key)

    return render_template('caesar_cipher.html', result=result)

# Remove this route since we'll use rsa_cipher_route instead
@app.route('/rsa', methods=['GET', 'POST'])
def rsa_page():
    return render_template('rsa_cipher.html')

# Create a global RSA instance
rsa_cipher = RSAEncryption()

@app.route('/rsa_cipher', methods=['GET', 'POST'])
def rsa_cipher_route():
    result = None
    if request.method == 'POST':
        if 'text' in request.form and request.form['text']:
            # Handle text encryption
            plaintext = request.form['text']
            try:
                encrypted_text = rsa_cipher.encrypt_text(plaintext)
                result = {
                    'original_text': plaintext,
                    'encrypted_text': encrypted_text,
                    'success': True
                }
            except Exception as e:
                result = {
                    'error': str(e),
                    'success': False
                }
                flash(f'Encryption error: {str(e)}', 'error')
        
        elif 'file' in request.files:
            # Handle file encryption
            file = request.files['file']
            if file and file.filename:
                try:
                    file_data = file.read()
                    encrypted_data = rsa_cipher.encrypt_file(file_data)
                    
                    # Save encrypted file
                    encrypted_filename = f"encrypted_{file.filename}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
                    
                    with open(file_path, 'wb') as f:
                        f.write(encrypted_data)
                    
                    return send_file(
                        file_path,
                        as_attachment=True,
                        download_name=encrypted_filename
                    )
                except Exception as e:
                    result = {
                        'error': str(e),
                        'success': False
                    }
                    flash(f'File encryption error: {str(e)}', 'error')
    
    # Get public and private keys
    public_key = rsa_cipher.get_public_key()
    private_key = rsa_cipher.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    return render_template('rsa_cipher.html', 
                         result=result,
                         public_key=public_key,
                         private_key=private_key)

@app.route('/rsa_decrypt', methods=['GET', 'POST'])
def rsa_decrypt_route():
    result = None
    if request.method == 'POST':
        private_key_pem = request.form.get('private_key')
        
        try:
            # Load the private key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=default_backend()
            )
            
            # Create RSADecryption instance
            rsa_decryptor = RSADecryption(private_key)
            
            if 'encrypted_text' in request.form and request.form['encrypted_text']:
                # Handle text decryption
                encrypted_text = request.form['encrypted_text']
                try:
                    decrypted_text = rsa_decryptor.decrypt_text(encrypted_text)
                    result = {
                        'encrypted_text': encrypted_text,
                        'decrypted_text': decrypted_text,
                        'success': True
                    }
                except Exception as e:
                    result = {
                        'error': str(e),
                        'success': False
                    }
                    flash(f'Decryption error: {str(e)}', 'error')
            
            elif 'file' in request.files:
                # Handle file decryption
                file = request.files['file']
                if file and file.filename:
                    try:
                        file_data = file.read()
                        decrypted_data = rsa_decryptor.decrypt_file(file_data)
                        
                        # Create decrypted filename
                        decrypted_filename = f"decrypted_{file.filename}"
                        if decrypted_filename.startswith('encrypted_'):
                            decrypted_filename = decrypted_filename.replace('encrypted_', '')
                        
                        # Save decrypted file temporarily
                        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
                        with open(temp_path, 'wb') as f:
                            f.write(decrypted_data)
                        
                        # Send the decrypted file
                        return send_file(
                            temp_path,
                            as_attachment=True,
                            download_name=decrypted_filename
                        )
                    except Exception as e:
                        result = {
                            'error': str(e),
                            'success': False
                        }
                        flash(f'File decryption error: {str(e)}', 'error')
                        
        except Exception as e:
            flash(f'Invalid private key: {str(e)}', 'error')
            return redirect(url_for('rsa_decrypt_route'))
    
    return render_template('rsa_decrypt.html', result=result)

# Add these routes to your Flask application
@app.route('/aes', methods=['GET'])
def aes_page():
    return render_template('aes.html')

@app.route('/aes/encrypt', methods=['POST'])
def aes_encrypt_route():
    if 'user' not in session:
        return jsonify({'status': 'error', 'message': 'User not authenticated'})
    
    try:
        # Generate new key for each encryption
        key = generate_key()
        
        if 'text' in request.form:
            # Text encryption - keep as is
            text = request.form['text']
            result = encrypt_text(text, key)
            
            if result['status'] == 'success':
                # Store the key in session for later decryption
                session['aes_key'] = base64.b64encode(key).decode('utf-8')
                return jsonify(result)
            return jsonify(result)
            
        elif 'file' in request.files:
            # File encryption with automatic download
            file = request.files['file']
            if file and file.filename:
                # Ensure filename is secure
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                result = encrypt_file(filepath, key)
                if result['status'] == 'success':
                    session['aes_key'] = base64.b64encode(key).decode('utf-8')
                    session['aes_iv'] = result['iv']  # Store IV for later use
                    
                    # Clean up the original file
                    os.remove(filepath)
                    
                    # Return file for automatic download
                    encrypted_file_path = result['encrypted_file']
                    encrypted_filename = os.path.basename(encrypted_file_path)
                    
                    @after_this_request
                    def cleanup(response):
                        try:
                            # Schedule cleanup of the encrypted file after download
                            os.remove(encrypted_file_path)
                        except Exception as e:
                            app.logger.error(f"Error removing file: {e}")
                        return response
                    
                    return send_file(
                        encrypted_file_path,
                        as_attachment=True,
                        download_name=f"encrypted_{filename}"
                    )
                return jsonify(result)
        
        return jsonify({'status': 'error', 'message': 'Invalid input'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/aes/decrypt', methods=['POST'])
def aes_decrypt_route():
    if 'user' not in session:
        return jsonify({'status': 'error', 'message': 'User not authenticated'})
    
    try:
        # Retrieve key from session
        key_b64 = session.get('aes_key')
        if not key_b64:
            return jsonify({'status': 'error', 'message': 'No encryption key found'})
        
        key = base64.b64decode(key_b64)
        
        if 'encrypted_data' in request.form:
            # Text decryption - keep as is
            encrypted_data = json.loads(request.form['encrypted_data'])
            result = decrypt_text(encrypted_data, key)
            return jsonify(result)
            
        elif 'file' in request.files:
            # File decryption with automatic download
            file = request.files['file']
            if file and file.filename:
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Get IV from request or session
                iv = request.form.get('iv', session.get('aes_iv'))
                if not iv:
                    return jsonify({'status': 'error', 'message': 'Missing IV for decryption'})
                
                result = decrypt_file(filepath, key, iv)
                if result['status'] == 'success':
                    # Clean up the encrypted file
                    os.remove(filepath)
                    
                    # Return file for automatic download
                    decrypted_file_path = result['decrypted_file']
                    
                    @after_this_request
                    def cleanup(response):
                        try:
                            # Schedule cleanup of the decrypted file after download
                            os.remove(decrypted_file_path)
                        except Exception as e:
                            app.logger.error(f"Error removing file: {e}")
                        return response
                    
                    # Create a more user-friendly filename
                    original_name = filename
                    if original_name.startswith('encrypted_'):
                        original_name = original_name[10:]  # Remove 'encrypted_' prefix
                    
                    return send_file(
                        decrypted_file_path,
                        as_attachment=True,
                        download_name=f"decrypted_{original_name}"
                    )
                return jsonify(result)
                
        return jsonify({'status': 'error', 'message': 'Invalid input'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# Ensure upload folder exists
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/des')
def des():
    return render_template('des.html')

@app.route('/des/generate_key', methods=['GET'])
def des_generate_key():
    key = generate_key()
    return jsonify({'key': key.hex()})

@app.route('/des/encrypt_text', methods=['POST'])
def des_encrypt_text_route():
    if 'text' not in request.form:
        return jsonify({'error': 'No text provided'}), 400
    
    plaintext = request.form['text']
    key = request.form.get('key', None)  # Optional key
    
    try:
        result = encrypt_text(plaintext, key)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/des/decrypt_text', methods=['POST'])
def des_decrypt_text_route():
    if not all(k in request.form for k in ['ciphertext', 'iv', 'key']):
        return jsonify({'error': 'Missing required parameters'}), 400
    
    ciphertext = request.form['ciphertext']
    iv = request.form['iv']
    key = request.form['key']
    
    try:
        plaintext = decrypt_text(ciphertext, iv, key)
        return jsonify({'plaintext': plaintext})
    except Exception as e:
        return jsonify({'error': str(e), 'plaintext': f"Error: {str(e)}"}), 500

@app.route('/des/encrypt_file', methods=['POST'])
def des_encrypt_file_route():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Save the uploaded file
    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)
    
    # Encrypt the file
    key = request.form.get('key', None)  # Optional key
    output_path = os.path.join(UPLOAD_FOLDER, filename + '.enc')
    
    try:
        result = encrypt_file(file_path, output_path, key)
        # Add file path for later download
        result['output_file'] = output_path
        return jsonify(result)
    except Exception as e:
        # Clean up the temp file
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({'error': str(e)}), 500

@app.route('/des/decrypt_file', methods=['POST'])
def des_decrypt_file_route():
    if 'file' not in request.files or 'key' not in request.form:
        return jsonify({'error': 'Missing file or key'}), 400
    
    file = request.files['file']
    key = request.form['key']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Save the uploaded file
    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)
    
    # Determine output filename
    output_filename = request.form.get('output_filename')
    if not output_filename:
        # Remove .enc extension if present, or add .dec otherwise
        if filename.endswith('.enc'):
            output_filename = filename[:-4]
        else:
            output_filename = filename + '.dec'
    
    output_path = os.path.join(UPLOAD_FOLDER, output_filename)
    
    try:
        result = decrypt_file(file_path, output_path, key)
        # Check if decryption was successful
        if not result.startswith("Error"):
            return jsonify({'result': result, 'output_file': output_path})
        else:
            return jsonify({'result': result}), 500
    except Exception as e:
        return jsonify({'result': f"Error: {str(e)}"}), 500

@app.route('/des/download')
def des_download_file():
    file_path = request.args.get('file')
    if not file_path or not os.path.exists(file_path):
        return "File not found", 404
    
    # Get the filename from the path
    filename = os.path.basename(file_path)
    
    # Serve the file for download
    try:
        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return str(e), 500

# Clean up temporary files (optional)
@app.route('/des/cleanup', methods=['POST'])
def des_cleanup():
    file_path = request.form.get('file')
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return jsonify({'success': False, 'error': 'File not found'}), 404

@app.route('/cleanup', methods=['POST'])
def cleanup_files():
    if 'user' not in session:
        return jsonify({'status': 'error', 'message': 'User not authenticated'})
    
    try:
        filename = request.form.get('filename')
        if filename:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
            if os.path.exists(filepath):
                os.remove(filepath)
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# Add this route to app.py
@app.route('/hash_function', methods=['GET', 'POST'])
def hash_function():
    plaintext = ''
    algorithm = 'sha256'  # Default algorithm
    hash_result = None
    
    if request.method == 'POST':
        plaintext = request.form.get('plaintext', '')
        algorithm = request.form.get('algorithm', 'sha256')
        
        if plaintext:
            if algorithm == 'md5':
                hash_result = hash_md5(plaintext)
            elif algorithm == 'sha1':
                hash_result = hash_sha1(plaintext)
            elif algorithm == 'sha256':
                hash_result = hash_sha256(plaintext)
            elif algorithm == 'sha512':
                hash_result = hash_sha512(plaintext)
            elif algorithm == 'sha3_256':
                hash_result = hash_sha3_256(plaintext)
            elif algorithm == 'blake2b':
                hash_result = hash_blake2b(plaintext)
    
    return render_template('hash_function.html', 
                           plaintext=plaintext, 
                           algorithm=algorithm, 
                           hash_result=hash_result)


# Add this route to your Flask app
@app.route('/morse_code', methods=['GET', 'POST'])
def morse_code():
    result = None
    message = None
    
    if request.method == 'POST':
        operation = request.form.get('operation')
        message = request.form.get('message')
        
        if operation == 'encrypt':
            result = MorseCode.encrypt(message)
        else:  # decrypt
            result = MorseCode.decrypt(message)
    
    # Get the Morse code dictionary for reference display
    morse_dict = {k: v for k, v in MorseCode.MORSE_CODE_DICT.items() if k != ' '}
    
    return render_template('morse_code.html', result=result, message=message, morse_dict=morse_dict)

if __name__ == '__main__':
    app.run(debug=True)