import sqlite3
import json
import os
from flask import Flask, render_template, request, jsonify
from detector import PhishingDetector

app = Flask(__name__)
detector = PhishingDetector()

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'phishguard.db')

def get_db_connection():
    """Establishes SQLite connection with dictionary row access."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes SQLite database schema if not present."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            input_summary TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            detected_indicators TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Initialize DB at app launch
init_db()

def save_scan_to_db(scan_type, input_summary, risk_score, risk_level, indicators):
    """Saves a scan record safely to SQLite."""
    # Ensure sensitive data is sanitized before storing
    sanitized_summary = PhishingDetector.sanitize_secrets(input_summary)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_history (scan_type, input_summary, risk_score, risk_level, detected_indicators)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        scan_type,
        sanitized_summary[:200],  # Truncate summary length
        risk_score,
        risk_level,
        json.dumps(indicators)
    ))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Renders the main dashboard HTML."""
    return render_template('index.html')

@app.route('/api/scan-url', methods=['POST'])
def api_scan_url():
    """API endpoint to analyze URLs."""
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()

    if not url:
        return jsonify({
            'success': False,
            'error': 'Please provide a valid URL string to scan.'
        }), 400

    result = detector.scan_url(url)

    if 'error' in result:
        return jsonify({
            'success': False,
            'error': result['error']
        }), 400

    # Save result to SQLite
    try:
        save_scan_to_db(
            scan_type='URL',
            input_summary=url,
            risk_score=result['risk_score'],
            risk_level=result['risk_level'],
            indicators=result['detected_indicators']
        )
    except Exception as e:
        print(f"Error saving URL scan to DB: {e}")

    return jsonify({
        'success': True,
        'data': result
    })

@app.route('/api/analyze-message', methods=['POST'])
def api_analyze_message():
    """API endpoint to analyze Email/Message text."""
    data = request.get_json(silent=True) or {}
    message = data.get('message', '').strip()

    if not message:
        return jsonify({
            'success': False,
            'error': 'Please provide message text to analyze.'
        }), 400

    result = detector.analyze_message(message)

    if 'error' in result:
        return jsonify({
            'success': False,
            'error': result['error']
        }), 400

    # Save sanitized result to SQLite
    try:
        save_scan_to_db(
            scan_type='Message',
            input_summary=result['input_summary'],
            risk_score=result['risk_score'],
            risk_level=result['risk_level'],
            indicators=result['detected_indicators']
        )
    except Exception as e:
        print(f"Error saving message scan to DB: {e}")

    return jsonify({
        'success': True,
        'data': result
    })

@app.route('/api/history', methods=['GET'])
def api_get_history():
    """API endpoint to fetch scan history."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, scan_type, input_summary, risk_score, risk_level, detected_indicators, timestamp
            FROM scan_history
            ORDER BY id DESC
            LIMIT 50
        ''')
        rows = cursor.fetchall()
        conn.close()

        history = []
        for r in rows:
            history.append({
                'id': r['id'],
                'scan_type': r['scan_type'],
                'input_summary': r['input_summary'],
                'risk_score': r['risk_score'],
                'risk_level': r['risk_level'],
                'detected_indicators': json.loads(r['detected_indicators']),
                'timestamp': r['timestamp']
            })

        return jsonify({
            'success': True,
            'count': len(history),
            'data': history
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/history', methods=['DELETE'])
def api_clear_history():
    """API endpoint to clear scan history."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM scan_history')
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Scan history cleared successfully.'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stats', methods=['GET'])
def api_get_stats():
    """API endpoint for dashboard metrics."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM scan_history')
        total_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE scan_type = 'URL'")
        url_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE scan_type = 'Message'")
        message_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Low Risk'")
        low_risk = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Suspicious'")
        suspicious = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'High Risk'")
        high_risk = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Critical'")
        critical = cursor.fetchone()[0]

        conn.close()

        return jsonify({
            'success': True,
            'stats': {
                'total_scans': total_scans,
                'url_scans': url_scans,
                'message_scans': message_scans,
                'low_risk': low_risk,
                'suspicious': suspicious,
                'high_risk': high_risk,
                'critical': critical
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    print("Starting PhishGuard Server on http://127.0.0.1:5000 ...")
    app.run(host='127.0.0.1', port=5000, debug=True)
