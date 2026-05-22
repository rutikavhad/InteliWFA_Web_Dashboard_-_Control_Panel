from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from db import get_connection
import csv
import os
import json
from datetime import datetime, timedelta,timezone
from collections import defaultdict, Counter
import time

app = Flask(__name__)
app.secret_key = '123-34-34-4'

CONFIG_FILE = 'firewall_config.json'

# Load firewall config
def load_firewall_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {
        'firewall_enabled': True,
        'blocked_ports': [22, 23, 3389, 445],  # Default blocked ports
        'allowed_ports': [80, 443, 8080, 3000, 5000]
    }

# Save firewall config
def save_firewall_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

# Read CSV data for dashboard
def get_attack_stats():
    if not os.path.exists('traffic_events.csv'):
        return {
            'total_attacks': 0,
            'attack_types': {},
            'top_ips': [],
            'requests_per_minute': []
        }

    attacks = []

    with open('traffic_events.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            if row['attack_type'] != 'NORMAL':
                attacks.append(row)

    # Attack type distribution
    attack_types = Counter(a['attack_type'] for a in attacks)

    # Top attacking IPs
    top_ips = Counter(a['client_ip'] for a in attacks).most_common(10)

    # Requests per minute (last 30 minutes)
    rpm = defaultdict(int)

    # Make now timezone-aware
    now = datetime.now(timezone.utc)

    for a in attacks:
        try:
            ts = datetime.fromisoformat(
                a['timestamp'].replace('Z', '+00:00')
            )

            if now - ts < timedelta(minutes=30):
                minute_key = ts.strftime('%H:%M')
                rpm[minute_key] += 1

        except Exception as e:
            print(f"Timestamp error: {e}")
            continue

    rpm_list = [
        {'time': k, 'count': v}
        for k, v in sorted(rpm.items())
    ]

    return {
        'total_attacks': len(attacks),
        'attack_types': dict(attack_types),
        'top_ips': [
            {'ip': ip, 'count': count}
            for ip, count in top_ips
        ],
        'requests_per_minute': rpm_list
    }

@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM admin WHERE email = %s AND password = %s", 
                   (username, password))
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if user:
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html', error=None)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    return jsonify(get_attack_stats())

@app.route('/control')
def control():
    if 'user' not in session:
        return redirect(url_for('login'))
    config = load_firewall_config()
    return render_template('control.html', config=config)

@app.route('/api/firewall/toggle', methods=['POST'])
def toggle_firewall():
    config = load_firewall_config()
    config['firewall_enabled'] = not config['firewall_enabled']
    save_firewall_config(config)
    return jsonify({'enabled': config['firewall_enabled']})

@app.route('/api/firewall/ports', methods=['POST'])
def update_ports():
    data = request.json
    config = load_firewall_config()
    
    if data['type'] == 'block':
        port = int(data['port'])
        if port not in config['blocked_ports']:
            config['blocked_ports'].append(port)
            if port in config['allowed_ports']:
                config['allowed_ports'].remove(port)
    elif data['type'] == 'allow':
        port = int(data['port'])
        if port not in config['allowed_ports']:
            config['allowed_ports'].append(port)
            if port in config['blocked_ports']:
                config['blocked_ports'].remove(port)
    elif data['type'] == 'remove_block':
        port = int(data['port'])
        if port in config['blocked_ports']:
            config['blocked_ports'].remove(port)
    elif data['type'] == 'remove_allow':
        port = int(data['port'])
        if port in config['allowed_ports']:
            config['allowed_ports'].remove(port)
    
    save_firewall_config(config)
    return jsonify({'success': True, 'config': config})



def get_attack_stats():
    if not os.path.exists('traffic_events.csv'):
        return {
            'total_attacks': 0,
            'attack_types': {},
            'top_ips': [],
            'requests_per_minute': [],
            'attacks_per_minute': [],
            'attacks_over_time': [],
            'live_traffic': []
        }
    
    attacks = []
    all_requests = []
    
    with open('traffic_events.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            all_requests.append(row)
            if row['attack_type'] != 'NORMAL':
                attacks.append(row)
    
    # Attack type distribution
    attack_types = Counter(a['attack_type'] for a in attacks)
    
    # Top attacking IPs
    top_ips = Counter(a['client_ip'] for a in attacks).most_common(10)
    
    # Attacks per minute (last 30 minutes)
    attacks_per_min = defaultdict(int)
    now = datetime.now(timezone.utc)
    
    for a in attacks:
        try:
            ts = datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00'))
            if now - ts < timedelta(minutes=30):
                minute_key = ts.strftime('%H:%M')
                attacks_per_min[minute_key] += 1
        except:
            continue
    
    attacks_per_min_list = [{'time': k, 'count': v} for k, v in sorted(attacks_per_min.items())]
    
    # Attacks over time (last 24 hours by hour)
    attacks_over_time = defaultdict(int)
    for a in attacks:
        try:
            ts = datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00'))
            if now - ts < timedelta(hours=24):
                hour_key = ts.strftime('%H:00')
                attacks_over_time[hour_key] += 1
        except:
            continue
    
    attacks_over_time_list = [{'hour': k, 'count': v} for k, v in sorted(attacks_over_time.items())]
    
    # Live traffic feed (last 20 requests, newest first)
    live_traffic = []
    for req in reversed(all_requests[-20:]):  # Last 20 requests
        try:
            ts = datetime.fromisoformat(req['timestamp'].replace('Z', '+00:00'))
            live_traffic.append({
                'client_ip': req['client_ip'],
                'method': req['method'],
                'path': req['path'],
                'attack_type': req['attack_type'],
                'timestamp': ts.strftime('%H:%M:%S')
            })
        except:
            live_traffic.append({
                'client_ip': req['client_ip'],
                'method': req['method'],
                'path': req['path'],
                'attack_type': req['attack_type'],
                'timestamp': req['timestamp'][11:19] if len(req['timestamp']) > 19 else req['timestamp']
            })
    
    return {
        'total_attacks': len(attacks),
        'attack_types': dict(attack_types),
        'top_ips': [{'ip': ip, 'count': count} for ip, count in top_ips],
        'requests_per_minute': attacks_per_min_list,  # Keep for compatibility
        'attacks_per_minute': attacks_per_min_list,
        'attacks_over_time': attacks_over_time_list,
        'live_traffic': live_traffic
    }

@app.route('/api/firewall/config', methods=['GET'])
def get_firewall_config():
    return jsonify(load_firewall_config())

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)