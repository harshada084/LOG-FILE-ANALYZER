from flask import Flask, render_template, request, jsonify
import re
import os
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'temp_uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Common log patterns (expanded list)
LOG_PATTERNS = {
    'Failed Login': r'Failed password|authentication failure|invalid user',
    'Brute Force': r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
    'SQL Injection': r'SELECT.*FROM|UNION.*SELECT|1=1|DROP TABLE',
    'XSS Attempt': r'<script>|alert\(|onerror=|javascript:',
    'Port Scan': r'PORT SCAN|connection attempt to closed port',
    'Admin Access': r'root login|admin access granted',
    'File Inclusion': r'\.\./|\.\.\\',  # Path traversal
    'Command Injection': r'; rm |; ls |\| bash'
}

def analyze_logs(filepath):
    results = {
        'total_lines': 0,
        'suspicious_events': {},
        'ip_addresses': set(),
        'timeline': [],
        'error': None
    }
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                results['total_lines'] += 1
                line = line.strip()
                if not line:
                    continue
                
                timestamp = extract_timestamp(line)
                
                # Check for each pattern
                for pattern_name, pattern in LOG_PATTERNS.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        results['suspicious_events'].setdefault(pattern_name, 0)
                        results['suspicious_events'][pattern_name] += 1
                        
                        # Extract IPs for suspicious events
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            results['ip_addresses'].add(ip_match.group(1))
                
                # Add to timeline if timestamp exists
                if timestamp:
                    results['timeline'].append({
                        'time': timestamp,
                        'event': line[:150] + '...' if len(line) > 150 else line
                    })
                    
    except Exception as e:
        results['error'] = f"Error analyzing file: {str(e)}"
    
    # Convert sets to lists for JSON
    results['ip_addresses'] = list(results['ip_addresses'])[:100]  # Limit to 100 IPs
    results['timeline'] = results['timeline'][-50:]  # Last 50 events
    return results

def extract_timestamp(line):
    # Supports Apache, Nginx, Windows, and syslog formats
    patterns = [
        r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',  # Apache
        r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',    # ISO
        r'(\w{3} \d{2} \d{2}:\d{2}:\d{2})',          # Syslog
        r'(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})'     # Windows
    ]
    
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'logfile' not in request.files:
        return jsonify({'error': 'No file uploaded'})
    
    file = request.files['logfile']
    if file.filename == '':
        return jsonify({'error': 'No file selected'})
    
    try:
        filename = secure_filename(file.filename)
        if not filename.lower().endswith(('.log', '.txt')):
            return jsonify({'error': 'Only .log or .txt files allowed'})
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        analysis = analyze_logs(filepath)
        
        # Clean up
        try:
            os.remove(filepath)
        except:
            pass
            
        return jsonify(analysis)
        
    except Exception as e:
        return jsonify({'error': f'Processing error: {str(e)}'})

if __name__ == '__main__':
    app.run(debug=True)


