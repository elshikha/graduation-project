from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
import os
from functools import wraps

# Import utilities from backend folder
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))
from utils import (
    detect_file_type, 
    is_supported_type, 
    get_file_info,
    calculate_all_hashes,
    calculate_file_entropy,
    calculate_blake2b,
    get_comprehensive_file_info,
    analyze_pe_header,
    get_comprehensive_pdf_analysis,
    scan_file_hash,
    analyze_strings,
    check_urls_with_virustotal
)
from utils.virustotal_scanner import _reconcile_pdf_verdict
from utils.pdf_obfuscation_analyzer import PDFObfuscationAnalyzer
from utils.capa_analyzer import CapaAnalyzer
from backend.utils.dumpbin_analyzer import analyze_pe_structure

print("✓ PDFObfuscationAnalyzer imported successfully!")
print("✓ CapaAnalyzer imported successfully!")

app = Flask(__name__, 
            static_folder='.',
            static_url_path='')
CORS(app)

# Secret key for JWT
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['UPLOAD_FOLDER'] = 'backend/uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Create upload folder if not exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# MongoDB connection
try:
    client = MongoClient('mongodb://localhost:27017/')
    db = client['cysent_db']
    users_collection = db['users']
    analyses_collection = db['analyses']
    print("✓ Connected to MongoDB successfully!")
except Exception as e:
    print(f"✗ Error connecting to MongoDB: {e}")
    print("  App will continue but database features will not work.")

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

# ============= AUTHENTICATION ROUTES =============

@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        
        if not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({
                'success': False,
                'message': 'Username, email, and password are required!'
            }), 400
        
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
        
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        
        new_user = {
            'username': data['username'],
            'email': data['email'],
            'password': hashed_password,
            'created_at': datetime.utcnow(),
            'provider': 'local'
        }
        
        users_collection.insert_one(new_user)
        
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

@app.route('/api/signin', methods=['POST'])
def signin():
    try:
        data = request.get_json()
        
        if not data.get('identifier') or not data.get('password'):
            return jsonify({
                'success': False,
                'message': 'Email/Username and password are required!'
            }), 400
        
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
        
        if user.get('provider') != 'local':
            return jsonify({
                'success': False,
                'message': f'This account is registered with {user.get("provider")}. Please use social login.'
            }), 401
        
        if not check_password_hash(user['password'], data['password']):
            return jsonify({
                'success': False,
                'message': 'Invalid credentials! Incorrect password.'
            }), 401
        
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

# ============= FILE ANALYSIS ROUTES =============

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
        
        # Detect file type using utility
        file_info = get_file_info(file.filename, file_content)
        file_type = file_info['file_type']
        
        # Check if supported
        if not is_supported_type(file_type):
            return jsonify({
                'success': False,
                'message': f'Unsupported file type: {file_type}',
                'file_type': file_type
            }), 400
        
        # Calculate hashes using utility
        hashes = calculate_all_hashes(file_content)
        
        # Calculate entropy
        entropy = calculate_file_entropy(file_content)
        
        # Calculate BLAKE2b hash
        blake2b_hash = calculate_blake2b(file_content)
        
        # Get comprehensive file info
        file_analysis = get_comprehensive_file_info(file.filename, file_content)
        
        # Store analysis data in database
        analysis_data = {
            'user_email': current_user['email'],
            'filename': file.filename,
            'file_size': file_size,
            'file_size_kb': round(file_size / 1024, 2),
            'file_size_mb': round(file_size / (1024 * 1024), 2),
            'file_type': file_type,
            'md5': hashes['md5'],
            'sha1': hashes['sha1'],
            'sha256': hashes['sha256'],
            'sha512': hashes['sha512'],
            'blake2b': blake2b_hash,
            'entropy': entropy,
            'entropy_status': file_analysis.get('entropy_status', 'Unknown'),
            'magic_bytes': file_info['magic_bytes'],
            'upload_date': datetime.utcnow(),
            'status': 'analyzed'
        }
        
        # Save to database
        result = analyses_collection.insert_one(analysis_data)
        analysis_data['_id'] = str(result.inserted_id)
        
        # Prepare response data
        response_data = {
            'analysis_id': analysis_data['_id'],
            'filename': file.filename,
            'file_size': file_size,
            'file_size_kb': analysis_data['file_size_kb'],
            'file_size_mb': analysis_data['file_size_mb'],
            'file_type': file_type,
            'entropy': entropy,
            'entropy_status': analysis_data['entropy_status'],
            'hashes': {
                'md5': hashes['md5'],
                'sha1': hashes['sha1'],
                'sha256': hashes['sha256'],
                'sha512': hashes['sha512'],
                'blake2b': blake2b_hash
            }
        }
        
        # VirusTotal scan for all files
        try:
            vt_results = scan_file_hash(hashes['sha256'])
            if vt_results and not vt_results.get('error'):
                response_data['virustotal'] = vt_results
                analysis_data['virustotal'] = vt_results
        except Exception as vt_error:
            response_data['virustotal'] = {'error': str(vt_error), 'found': False}
        
        # Create temp file for analysis (used by strings and PE/PDF analysis)
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{hashes['sha256']}")
        try:
            with open(temp_path, 'wb') as f:
                f.write(file_content)
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error saving temp file: {str(e)}'
            }), 500
        
        # Strings analysis for all files
        try:
            print(f"Running strings analysis on: {temp_path}")
            strings_results = analyze_strings(temp_path)
            print(f"Strings results: {strings_results}")
            if strings_results and 'error' not in strings_results:
                response_data['strings_analysis'] = strings_results
                analysis_data['strings_analysis'] = strings_results
                
                # Check URLs against VirusTotal if any found
                if strings_results.get('indicators', {}).get('urls'):
                    # Get VT API key from scanner instance
                    from utils.virustotal_scanner import VTScanner
                    scanner = VTScanner()
                    vt_api_key = scanner._k  # Get the decoded key
                    
                    vt_url_results = check_urls_with_virustotal(
                        strings_results['indicators']['urls'][:5],
                        vt_api_key
                    )
                    if vt_url_results:
                        response_data['strings_analysis']['vt_url_results'] = vt_url_results
                        analysis_data['strings_analysis']['vt_url_results'] = vt_url_results
            else:
                print(f"Strings analysis error: {strings_results.get('error', 'Unknown error')}")
                response_data['strings_analysis'] = strings_results
        except Exception as strings_error:
            print(f"Exception in strings analysis: {strings_error}")
            import traceback
            traceback.print_exc()
            response_data['strings_analysis'] = {'error': str(strings_error)}
        
        # Add PE analysis for Windows executables
        if file_type == 'PE':
            try:
                pe_info = analyze_pe_header(temp_path)
                if 'error' not in pe_info:
                    response_data['pe_analysis'] = pe_info
                    analysis_data['pe_analysis'] = pe_info
            except Exception as pe_error:
                response_data['pe_analysis'] = {'error': str(pe_error)}
            
            # Add CAPA capability analysis for PE files
            try:
                print(f"Running CAPA capability analysis on: {temp_path}")
                capa_analyzer = CapaAnalyzer()
                capa_results = capa_analyzer.analyze(temp_path)
                print(f"CAPA results: {capa_results.get('success', False)}")
                
                if capa_results and capa_results.get('success'):
                    response_data['capa_analysis'] = capa_results
                    analysis_data['capa_analysis'] = capa_results
                    print(f"✓ CAPA analysis completed: {len(capa_results.get('capabilities', []))} capabilities found")
                else:
                    print(f"CAPA analysis error: {capa_results.get('error', 'Unknown error')}")
                    response_data['capa_analysis'] = capa_results
            except Exception as capa_error:
                print(f"Exception in CAPA analysis: {capa_error}")
                import traceback
                traceback.print_exc()
                response_data['capa_analysis'] = {'success': False, 'error': str(capa_error)}
            
            # Add PE Structure analysis using dumpbin
            try:
                print(f"Running dumpbin PE structure analysis on: {temp_path}")
                pe_structure = analyze_pe_structure(temp_path)
                if 'error' not in pe_structure:
                    response_data['pe_structure'] = pe_structure
                    analysis_data['pe_structure'] = pe_structure
                    print(f"✓ PE structure analysis completed")
                else:
                    print(f"PE structure analysis error: {pe_structure.get('error')}")
                    response_data['pe_structure'] = pe_structure
            except Exception as dumpbin_error:
                print(f"Exception in dumpbin analysis: {dumpbin_error}")
                import traceback
                traceback.print_exc()
                response_data['pe_structure'] = {'error': str(dumpbin_error)}
        
        # Add PDF analysis for PDF files
        elif file_type == 'PDF':
            try:
                pdf_analysis = get_comprehensive_pdf_analysis(temp_path)
                
                # Apply VT calibration if available (even if not found)
                if 'virustotal' in response_data:
                    pdf_analysis = _reconcile_pdf_verdict(response_data['virustotal'], pdf_analysis)
                
                if 'error' not in pdf_analysis:
                    response_data['pdf_analysis'] = pdf_analysis
                    analysis_data['pdf_analysis'] = pdf_analysis
            except Exception as pdf_error:
                response_data['pdf_analysis'] = {'error': str(pdf_error)}
            
            # Add PDF Obfuscation Analysis (pdfid-based)
            try:
                print(f"Running PDF obfuscation analysis on: {temp_path}")
                obfuscation_analyzer = PDFObfuscationAnalyzer()
                obfuscation_results = obfuscation_analyzer.analyze(temp_path)
                print(f"PDF obfuscation results: {obfuscation_results}")
                
                if obfuscation_results and 'error' not in obfuscation_results:
                    response_data['pdf_obfuscation'] = obfuscation_results
                    analysis_data['pdf_obfuscation'] = obfuscation_results
                else:
                    print(f"PDF obfuscation analysis error: {obfuscation_results.get('error', 'Unknown error')}")
                    response_data['pdf_obfuscation'] = obfuscation_results
            except Exception as obf_error:
                print(f"Exception in PDF obfuscation analysis: {obf_error}")
                import traceback
                traceback.print_exc()
                response_data['pdf_obfuscation'] = {'error': str(obf_error)}
        
        # Clean up temp file
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except:
            pass
        
        return jsonify({
            'success': True,
            'message': 'File analyzed successfully',
            'data': response_data
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/analyses', methods=['GET'])
@token_required
def get_analyses(current_user):
    try:
        analyses = list(analyses_collection.find(
            {'user_email': current_user['email']},
            {'_id': 0}
        ).sort('upload_date', -1).limit(50))
        
        return jsonify({
            'success': True,
            'analyses': analyses
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/get-capa-rule', methods=['POST'])
@token_required
def get_capa_rule(current_user):
    try:
        data = request.get_json()
        namespace = data.get('namespace')
        capability = data.get('capability')
        
        if not namespace or not capability:
            return jsonify({
                'success': False,
                'error': 'Missing namespace or capability'
            }), 400
        
        # Use CapaAnalyzer to get rule content
        capa_analyzer = CapaAnalyzer()
        rule_data = capa_analyzer.get_rule_content(namespace, capability)
        
        return jsonify(rule_data), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error: {str(e)}'
        }), 500

# ============= STATIC FILE ROUTES =============

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('frontend/public/img', 'favicon.ico', mimetype='image/x-icon')

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/frontend/<path:filename>')
def serve_frontend(filename):
    return send_from_directory('frontend', filename)

@app.route('/<path:filename>')
def serve_root(filename):
    return send_from_directory('.', filename)

# ============= HEALTH CHECK =============

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'database': 'connected' if client else 'disconnected'
    }), 200

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🚀 CYSENT Malware Analysis Platform")
    print("="*50)
    print(f"✓ Server starting on http://localhost:5000")
    print(f"✓ Upload folder: {app.config['UPLOAD_FOLDER']}")
    print("="*50 + "\n")
    app.run(debug=True, port=5000, host='0.0.0.0')
