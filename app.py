import os
import json
import hashlib
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from dotenv import load_dotenv
import threading
import queue
import time

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__, 
            template_folder='frontend/templates',
            static_folder='frontend/static')

# Get the absolute path for the database
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'database', 'scans.db')

# Ensure the database directory exists
os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)

# Set configuration with proper error handling
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DATABASE_PATH}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Handle MAX_CONTENT_LENGTH with default value if not set
try:
    max_content = os.getenv('MAX_CONTENT_LENGTH', '104857600')
    app.config['MAX_CONTENT_LENGTH'] = int(max_content)
except (ValueError, TypeError):
    app.config['MAX_CONTENT_LENGTH'] = 104857600  # 100MB default

# Initialize extensions
db = SQLAlchemy(app)
CORS(app)

# Import backend modules
from backend.scanner import VirusTotalScanner
from backend.threat_analyzer import ThreatAnalyzer
from backend.report_generator import ReportGenerator

# Get API key from environment
api_key = os.getenv('VIRUSTOTAL_API_KEY')
if not api_key:
    print("⚠️  WARNING: VIRUSTOTAL_API_KEY not found in environment variables!")
    print("   Please add it to your .env file")
    print("   Scanning will work in demo mode with mock data")

# Initialize scanner with API key (handle missing key)
scanner = VirusTotalScanner(api_key) if api_key else VirusTotalScanner(None)
analyzer = ThreatAnalyzer()
report_gen = ReportGenerator()

# Database Models
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), unique=True, nullable=False)
    file_size = db.Column(db.Integer)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    risk_score = db.Column(db.Integer)
    malware_family = db.Column(db.String(100))
    status = db.Column(db.String(50))
    threat_level = db.Column(db.String(20))
    detections = db.Column(db.Text)  # JSON string
    report_path = db.Column(db.String(255))
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'scan_date': self.scan_date.isoformat() if self.scan_date else None,
            'risk_score': self.risk_score,
            'malware_family': self.malware_family,
            'status': self.status,
            'threat_level': self.threat_level,
            'detections': json.loads(self.detections) if self.detections else {},
            'report_path': self.report_path
        }

# Create database tables
with app.app_context():
    try:
        db.create_all()
        print("✅ Database initialized successfully at:", DATABASE_PATH)
    except Exception as e:
        print(f"❌ Database initialization error: {str(e)}")

# Background task queue
task_queue = queue.Queue()

def background_worker():
    while True:
        try:
            task = task_queue.get(timeout=1)
            if task:
                task_type = task.get('type')
                if task_type == 'scan':
                    file_path = task.get('file_path')
                    filename = task.get('filename')
                    file_hash = task.get('file_hash')
                    
                    try:
                        # Perform scan
                        result = scanner.scan_file(file_path)
                        
                        # Analyze threat
                        analysis = analyzer.analyze(result, file_hash)
                        
                        # Generate report
                        report_path = report_gen.generate_report(analysis, filename)
                        
                        # Save to database - handle duplicate gracefully
                        with app.app_context():
                            # Check if file already exists
                            existing = ScanResult.query.filter_by(file_hash=file_hash).first()
                            if existing:
                                print(f"♻️ File {filename} already exists in database (ID: {existing.id})")
                                # Update existing record with new data
                                existing.filename = filename
                                existing.file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                                existing.risk_score = analysis.get('risk_score', 0)
                                existing.malware_family = analysis.get('malware_family', 'Unknown')
                                existing.status = analysis.get('status', 'Error')
                                existing.threat_level = analysis.get('threat_level', 'Unknown')
                                existing.detections = json.dumps(analysis.get('detections', {}))
                                existing.report_path = report_path
                                existing.scan_date = datetime.utcnow()
                                db.session.commit()
                                print(f"✅ Updated scan result for {filename}")
                            else:
                                # Create new record
                                scan_result = ScanResult(
                                    filename=filename,
                                    file_hash=file_hash,
                                    file_size=os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                                    risk_score=analysis.get('risk_score', 0),
                                    malware_family=analysis.get('malware_family', 'Unknown'),
                                    status=analysis.get('status', 'Error'),
                                    threat_level=analysis.get('threat_level', 'Unknown'),
                                    detections=json.dumps(analysis.get('detections', {})),
                                    report_path=report_path
                                )
                                db.session.add(scan_result)
                                db.session.commit()
                                print(f"✅ Scan completed for {filename}")
                        
                    except Exception as e:
                        print(f"❌ Error scanning {filename}: {str(e)}")
                        import traceback
                        traceback.print_exc()
                        
                        # Save error result with duplicate handling
                        analysis = {
                            'risk_score': 0,
                            'malware_family': 'Unknown',
                            'status': 'Error',
                            'threat_level': 'Unknown',
                            'detections': {},
                            'error': str(e)
                        }
                        report_path = report_gen.generate_report(analysis, filename)
                        
                        with app.app_context():
                            try:
                                # Check if file already exists
                                existing = ScanResult.query.filter_by(file_hash=file_hash).first()
                                if existing:
                                    # Update existing record
                                    existing.filename = filename
                                    existing.file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                                    existing.risk_score = 0
                                    existing.malware_family = 'Unknown'
                                    existing.status = 'Error'
                                    existing.threat_level = 'Unknown'
                                    existing.detections = json.dumps({'error': str(e)})
                                    existing.report_path = report_path
                                    existing.scan_date = datetime.utcnow()
                                    db.session.commit()
                                    print(f"✅ Updated error result for {filename}")
                                else:
                                    # Create new error record
                                    scan_result = ScanResult(
                                        filename=filename,
                                        file_hash=file_hash,
                                        file_size=os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                                        risk_score=0,
                                        malware_family='Unknown',
                                        status='Error',
                                        threat_level='Unknown',
                                        detections=json.dumps({'error': str(e)}),
                                        report_path=report_path
                                    )
                                    db.session.add(scan_result)
                                    db.session.commit()
                                    print(f"✅ Error result saved for {filename}")
                            except Exception as db_error:
                                print(f"❌ Database error: {str(db_error)}")
                    
                    finally:
                        # Clean up uploaded file
                        if os.path.exists(file_path):
                            try:
                                os.remove(file_path)
                                print(f"🧹 Cleaned up: {file_path}")
                            except Exception as e:
                                print(f"⚠️ Could not remove {file_path}: {str(e)}")
                        
        except queue.Empty:
            continue
        except Exception as e:
            print(f"Background worker error: {str(e)}")
            continue

# Start background worker
thread = threading.Thread(target=background_worker, daemon=True)
thread.start()

# Routes
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    try:
        total_scans = ScanResult.query.count()
        threats_detected = ScanResult.query.filter(ScanResult.status != 'Safe').count()
        high_risk = ScanResult.query.filter_by(threat_level='High').count()
        critical_risk = ScanResult.query.filter_by(threat_level='Critical').count()
        
        # Recent scans (last 10)
        recent_scans = ScanResult.query.order_by(ScanResult.scan_date.desc()).limit(10).all()
        recent_data = [scan.to_dict() for scan in recent_scans]
        
        return jsonify({
            'success': True,
            'data': {
                'total_scans': total_scans,
                'threats_detected': threats_detected,
                'high_risk': high_risk,
                'critical_risk': critical_risk,
                'recent_scans': recent_data,
                'scan_timeline': get_scan_timeline(),
                'threat_distribution': get_threat_distribution()
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def get_scan_timeline():
    # Get last 7 days of scans
    results = []
    for i in range(6, -1, -1):
        date = datetime.utcnow().date() - timedelta(days=i)
        count = ScanResult.query.filter(
            db.func.date(ScanResult.scan_date) == date.isoformat()
        ).count()
        results.append({
            'date': date.isoformat(),
            'count': count
        })
    return results

def get_threat_distribution():
    threat_levels = ['Safe', 'Low', 'Medium', 'High', 'Critical']
    distribution = []
    for level in threat_levels:
        count = ScanResult.query.filter_by(threat_level=level).count()
        distribution.append({
            'level': level,
            'count': count
        })
    return distribution

@app.route('/api/upload', methods=['POST'])
def upload_file():
    try:
        print(f"📤 Upload request received")
        
        if 'file' not in request.files:
            print("❌ No file in request")
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            print("❌ Empty filename")
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        print(f"📁 File received: {file.filename}")
        print(f"   Content-Type: {file.content_type}")
        
        # Get allowed extensions from environment or use default
        default_extensions = 'exe,dll,doc,pdf,zip,rar,jar,apk,txt,com,bat,scr,ps1,py,js,vbs,docx,xlsx,ppt,pptx,7z,gz,tar,html,css,jpg,png,gif,iso,bin,msi'
        allowed_extensions = os.getenv('ALLOWED_EXTENSIONS', default_extensions)
        allowed_list = [ext.strip().lower() for ext in allowed_extensions.split(',')]
        
        # Get file extension
        file_ext = file.filename.lower().split('.')[-1] if '.' in file.filename else ''
        
        # If no extension, try to detect from content-type
        if not file_ext or file_ext not in allowed_list:
            content_type_map = {
                'text/plain': 'txt',
                'application/pdf': 'pdf',
                'application/zip': 'zip',
                'application/x-zip-compressed': 'zip',
                'application/x-rar-compressed': 'rar',
                'application/x-7z-compressed': '7z',
                'application/java-archive': 'jar',
                'application/vnd.android.package-archive': 'apk',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
                'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
                'application/msword': 'doc',
                'application/vnd.ms-excel': 'xls',
                'application/vnd.ms-powerpoint': 'ppt',
                'image/jpeg': 'jpg',
                'image/png': 'png',
                'image/gif': 'gif',
                'text/javascript': 'js',
                'text/html': 'html',
                'text/css': 'css',
                'application/octet-stream': file_ext if file_ext else 'exe',
                'application/x-msdownload': 'exe',
                'application/x-dosexec': 'exe',
                'application/x-msi': 'msi'
            }
            
            if file.content_type in content_type_map:
                detected_ext = content_type_map[file.content_type]
                if detected_ext in allowed_list:
                    file_ext = detected_ext
                    print(f"   Detected extension from content-type: {file_ext}")
        
        if file_ext not in allowed_list:
            print(f"❌ File extension '{file_ext}' not allowed.")
            print(f"   Allowed extensions: {allowed_list}")
            return jsonify({
                'success': False, 
                'error': f'File type .{file_ext} not allowed. Allowed: {", ".join(allowed_list[:15])}'
            }), 400
        
        # Calculate file hash
        file_content = file.read()
        if len(file_content) == 0:
            print("❌ Empty file")
            return jsonify({'success': False, 'error': 'Empty file uploaded'}), 400
        
        file_hash = hashlib.sha256(file_content).hexdigest()
        print(f"🔑 File hash: {file_hash[:16]}...")
        print(f"📊 File size: {len(file_content)} bytes")
        
        # Check if file already scanned
        existing = ScanResult.query.filter_by(file_hash=file_hash).first()
        if existing:
            print(f"♻️ File already scanned (ID: {existing.id})")
            return jsonify({
                'success': True,
                'message': 'File already scanned - returning cached result',
                'scan_id': existing.id,
                'result': existing.to_dict()
            })
        
        # Save file temporarily
        filename = file.filename
        upload_dir = os.path.join(BASE_DIR, 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        temp_path = os.path.join(upload_dir, f"{file_hash}_{filename}")
        with open(temp_path, 'wb') as f:
            f.write(file_content)
        
        print(f"💾 File saved to: {temp_path}")
        
        # Queue for scanning
        task_queue.put({
            'type': 'scan',
            'file_path': temp_path,
            'filename': filename,
            'file_hash': file_hash
        })
        
        print(f"⏳ File queued for scanning")
        
        return jsonify({
            'success': True,
            'message': 'File queued for scanning',
            'file_hash': file_hash,
            'filename': filename
        })
        
    except Exception as e:
        print(f"❌ Upload error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scan/<int:scan_id>')
def get_scan_result(scan_id):
    try:
        scan = ScanResult.query.get_or_404(scan_id)
        return jsonify({
            'success': True,
            'result': scan.to_dict()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/report/<int:scan_id>')
def download_report(scan_id):
    try:
        scan = ScanResult.query.get_or_404(scan_id)
        if not scan.report_path or not os.path.exists(scan.report_path):
            return jsonify({'success': False, 'error': 'Report not found'}), 404
        
        return send_file(scan.report_path, as_attachment=True)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/delete/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    try:
        scan = ScanResult.query.get_or_404(scan_id)
        # Delete report file if exists
        if scan.report_path and os.path.exists(scan.report_path):
            os.remove(scan.report_path)
        
        db.session.delete(scan)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Scan deleted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    # Create required directories
    os.makedirs(os.path.join(BASE_DIR, 'uploads'), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, 'reports'), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, 'database'), exist_ok=True)
    
    # Get debug setting with default
    debug = os.getenv('DEBUG', 'True').lower() == 'true'
    
    # Show allowed extensions
    default_extensions = 'exe,dll,doc,pdf,zip,rar,jar,apk,txt,com,bat,scr,ps1,py,js,vbs,docx,xlsx,ppt,pptx,7z,gz,tar,html,css,jpg,png,gif,iso,bin,msi'
    allowed_extensions = os.getenv('ALLOWED_EXTENSIONS', default_extensions)
    
    print("\n" + "="*50)
    print("🔒 Sentinel AI Security Platform")
    print("="*50)
    print(f"🌐 Server running at: http://localhost:5000")
    print(f"🌐 Network access: http://0.0.0.0:5000")
    print(f"🐛 Debug mode: {debug}")
    print(f"📁 Database path: {DATABASE_PATH}")
    print(f"📂 Allowed extensions: {allowed_extensions}")
    if not api_key:
        print("⚠️  WARNING: VIRUSTOTAL_API_KEY not set - using demo mode!")
        print("   Get your free API key at: https://www.virustotal.com/gui/my-apikey")
        print("   Add it to the .env file for real scanning")
    else:
        print("✅ VirusTotal API key configured")
    print("="*50 + "\n")
    
    # Get host from environment or use default
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 5000))
    
    app.run(debug=debug, host=host, port=port)