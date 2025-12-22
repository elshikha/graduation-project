from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
import os
from functools import wraps

app = Flask(__name__)
CORS(app)

# Secret key for JWT
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'

# MongoDB connection
try:
    client = MongoClient('mongodb://localhost:27017/')
    db = client['cysent_db']
    users_collection = db['users']
    print("Connected to MongoDB successfully!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token.split(' ')[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users_collection.find_one({'email': data['email']})
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Sign Up Route
@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        
        # Validate input
        if not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({
                'success': False,
                'message': 'Username, email, and password are required!'
            }), 400
        
        # Check if user already exists
        existing_user = users_collection.find_one({
            '$or': [
                {'email': data['email']},
                {'username': data['username']}
            ]
        })
        
        if existing_user:
            if existing_user['email'] == data['email']:
                return jsonify({
                    'success': False,
                    'message': 'Email already registered!'
                }), 400
            else:
                return jsonify({
                    'success': False,
                    'message': 'Username already taken!'
                }), 400
        
        # Hash password
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        
        # Create new user
        new_user = {
            'username': data['username'],
            'email': data['email'],
            'password': hashed_password,
            'created_at': datetime.utcnow(),
            'provider': 'local'
        }
        
        users_collection.insert_one(new_user)
        
        # Generate token
        token = jwt.encode({
            'email': data['email'],
            'exp': datetime.utcnow() + timedelta(days=7)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully!',
            'token': token,
            'user': {
                'username': data['username'],
                'email': data['email']
            }
        }), 201
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

# Sign In Route
@app.route('/api/signin', methods=['POST'])
def signin():
    try:
        data = request.get_json()
        
        # Validate input
        if not data.get('identifier') or not data.get('password'):
            return jsonify({
                'success': False,
                'message': 'Email/Username and password are required!'
            }), 400
        
        # Find user by email or username
        user = users_collection.find_one({
            '$or': [
                {'email': data['identifier']},
                {'username': data['identifier']}
            ]
        })
        
        if not user:
            return jsonify({
                'success': False,
                'message': 'Invalid credentials! User not found.'
            }), 401
        
        # Check if user registered with social provider
        if user.get('provider') != 'local':
            return jsonify({
                'success': False,
                'message': f'This account is registered with {user.get("provider")}. Please use social login.'
            }), 401
        
        # Verify password
        if not check_password_hash(user['password'], data['password']):
            return jsonify({
                'success': False,
                'message': 'Invalid credentials! Incorrect password.'
            }), 401
        
        # Generate token
        token = jwt.encode({
            'email': user['email'],
            'exp': datetime.utcnow() + timedelta(days=7)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'success': True,
            'message': 'Login successful!',
            'token': token,
            'user': {
                'username': user['username'],
                'email': user['email']
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

# Social Login Route (for OAuth callbacks)
@app.route('/api/auth/social', methods=['POST'])
def social_login():
    try:
        data = request.get_json()
        
        # Validate input
        if not data.get('email') or not data.get('provider'):
            return jsonify({
                'success': False,
                'message': 'Email and provider are required!'
            }), 400
        
        # Check if user exists
        user = users_collection.find_one({'email': data['email']})
        
        if user:
            # User exists, update last login
            users_collection.update_one(
                {'email': data['email']},
                {'$set': {'last_login': datetime.utcnow()}}
            )
        else:
            # Create new user
            new_user = {
                'username': data.get('username', data['email'].split('@')[0]),
                'email': data['email'],
                'provider': data['provider'],
                'profile_picture': data.get('profile_picture'),
                'created_at': datetime.utcnow(),
                'last_login': datetime.utcnow()
            }
            users_collection.insert_one(new_user)
            user = new_user
        
        # Generate token
        token = jwt.encode({
            'email': data['email'],
            'exp': datetime.utcnow() + timedelta(days=7)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'success': True,
            'message': 'Social login successful!',
            'token': token,
            'user': {
                'username': user.get('username'),
                'email': user['email'],
                'provider': user.get('provider')
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

# Protected Route Example
@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    return jsonify({
        'success': True,
        'user': {
            'username': current_user['username'],
            'email': current_user['email'],
            'created_at': current_user['created_at'],
            'provider': current_user.get('provider', 'local')
        }
    }), 200

# File Upload and Analysis
@app.route('/api/upload-file', methods=['POST'])
@token_required
def upload_file(current_user):
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'message': 'No file provided'
            }), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({
                'success': False,
                'message': 'No file selected'
            }), 400
        
        # Read file content
        file_content = file.read()
        file_size = len(file_content)
        
        # Detect file type
        file_type = detect_file_type(file.filename, file_content)
        
        # Check if supported
        supported_types = ['PE', 'ELF', 'PDF', 'Office']
        if file_type not in supported_types:
            return jsonify({
                'success': False,
                'message': f'Unsupported file type: {file_type}',
                'file_type': file_type
            }), 400
        
        # Calculate hashes
        import hashlib
        md5_hash = hashlib.md5(file_content).hexdigest()
        sha1_hash = hashlib.sha1(file_content).hexdigest()
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        
        # Store analysis data
        analysis_data = {
            'user_email': current_user['email'],
            'filename': file.filename,
            'file_size': file_size,
            'file_type': file_type,
            'md5': md5_hash,
            'sha1': sha1_hash,
            'sha256': sha256_hash,
            'upload_date': datetime.utcnow(),
            'status': 'analyzed'
        }
        
        db['analyses'].insert_one(analysis_data)
        
        return jsonify({
            'success': True,
            'message': 'File analyzed successfully',
            'data': {
                'filename': file.filename,
                'file_size': file_size,
                'file_type': file_type,
                'hashes': {
                    'md5': md5_hash,
                    'sha1': sha1_hash,
                    'sha256': sha256_hash
                }
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

def detect_file_type(filename, content):
    """Detect file type based on filename and magic bytes"""
    filename_lower = filename.lower()
    extension = filename_lower.split('.')[-1] if '.' in filename_lower else ''
    
    # Check magic bytes (first few bytes of file)
    magic_bytes = content[:4] if len(content) >= 4 else b''
    
    # PE files (Windows executables)
    if extension in ['exe', 'dll', 'sys']:
        return 'PE'
    if magic_bytes[:2] == b'MZ':  # PE magic number
        return 'PE'
    
    # ELF files (Linux executables)
    if extension in ['elf', 'so', 'bin']:
        return 'ELF'
    if magic_bytes[:4] == b'\x7fELF':  # ELF magic number
        return 'ELF'
    
    # PDF files
    if extension == 'pdf':
        return 'PDF'
    if magic_bytes[:4] == b'%PDF':  # PDF magic number
        return 'PDF'
    
    # Office files
    if extension in ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']:
        return 'Office'
    if magic_bytes[:2] == b'PK':  # Office (OOXML) files are ZIP archives
        if extension in ['docx', 'xlsx', 'pptx']:
            return 'Office'
    if magic_bytes[:4] == b'\xd0\xcf\x11\xe0':  # Old Office format magic
        return 'Office'
    
    # Mobile apps (unsupported)
    if extension in ['apk', 'ipa']:
        return 'Mobile App'
    
    # Unknown
    return 'Unknown'

# Get user's analyses
@app.route('/api/analyses', methods=['GET'])
@token_required
def get_analyses(current_user):
    try:
        analyses = list(db['analyses'].find(
            {'user_email': current_user['email']},
            {'_id': 0}
        ).sort('upload_date', -1))
        
        return jsonify({
            'success': True,
            'analyses': analyses
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

# Health check
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'database': 'connected'
    }), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
