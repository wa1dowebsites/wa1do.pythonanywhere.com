import os
import time
import random
import secrets
import sqlite3
import base64
import json
import ipaddress
import string
import traceback

from flask import Flask, request, jsonify, send_file
import requests

# Configuration
DATABASE_PATH = '/home/XeraCompany/mysite/userdata.db'
DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooksxxxxx'
USE_REAL_TOKENS = True  # Toggle between real and mock tokens

# Initialize Flask app
app = Flask(__name__)

def init_database():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            ip TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            custom_id TEXT NOT NULL,
            create_time REAL NOT NULL
        )
    ''')
    
    # Create banned IPs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS banned_ips (
            ip TEXT PRIMARY KEY
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_database()

def generate_username():
    """Generate a random username with 'Xera+' prefix and 6 uppercase letters"""
    return 'Xera+' + ''.join(random.choices(string.ascii_uppercase, k=6))

def generate_custom_id():
    """Generate a random 17-digit custom ID"""
    return ''.join(random.choices(string.digits, k=17))

def get_client_ip():
    """Extract client IP from headers, handling proxies"""
    return request.headers.get('X-Forwarded-For', request.remote_addr)

def is_trusted_ip(ip_address):
    """Check if IP is in trusted/developer list"""
    try:
        # Owner's IP addresses
        trusted_public_ips = {'OWNER IP WAS HERE', 'OWNER IP'}
        
        if ip_address in trusted_public_ips:
            return True
        
        ip = ipaddress.ip_address(ip_address)
        
        # Check against trusted IP ranges
        if ip.version == 4:
            return (ip in ipaddress.IPv4Network('1XXXXX1.0/24') or 
                    ip in ipaddress.IPv4Network('1XXXXX8/29'))
        
        return ip in ipaddress.IPv6Network('2600:4040:303c:5b00::/64')
    
    except ValueError:
        return False

def get_or_create_user(ip):
    """Get existing user or create new one for the given IP"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Check if IP is banned
    cursor.execute('SELECT 1 FROM banned_ips WHERE ip = ?', (ip,))
    if cursor.fetchone():
        conn.close()
        return None, True
    
    # Look for existing user
    cursor.execute('SELECT username, custom_id FROM users WHERE ip = ?', (ip,))
    result = cursor.fetchone()
    
    if result:
        username, custom_id = result
    else:
        # Create new user
        if ip == '127.0.0.1':
            username = '<color=red>0x11'
        else:
            username = generate_username()
        
        custom_id = generate_custom_id()
        cursor.execute(
            'INSERT INTO users (ip, username, custom_id, create_time) VALUES (?, ?, ?, ?)',
            (ip, username, custom_id, time.time())
        )
        conn.commit()
    
    conn.close()
    return {'username': username, 'custom_id': custom_id}, False

def generate_jwt(user_id):
    """Generate a JWT token for authentication"""
    header = {'alg': 'HS256', 'typ': 'JWT'}
    now = int(time.time())
    
    payload = {
        'tid': secrets.token_hex(16),
        'uid': user_id,
        'usn': secrets.token_hex(5),
        'vrs': {
            'authID': secrets.token_hex(20),
            'clientUserAgent': 'MetaQuest 1.16.3.1138_5edcbd98',
            'deviceID': secrets.token_hex(20),
            'loginType': 'meta_quest'
        },
        'exp': now + 72000,  # 20 hours expiry
        'iat': now
    }
    
    def base64_encode(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip('=')
    
    signature = secrets.token_urlsafe(32)
    return f"{base64_encode(header)}.{base64_encode(payload)}.{signature}"

def generate_auth_tokens():
    """Generate authentication token pair"""
    user_id = secrets.token_hex(16)
    return {
        'token': generate_jwt(user_id),
        'refresh_token': generate_jwt(user_id)
    }

def generate_gameplay_loadout():
    """Generate a random gameplay loadout configuration"""
    try:
        with open('/home/XeraCompany/mysite/econ_gameplay_items.json', 'r') as f:
            data = json.load(f)
            item_ids = [item['id'] for item in data if 'id' in item]
    except Exception as e:
        print(f"Failed to load econ_gameplay_items.json: {e}")
        item_ids = [
            'item_jetpack', 'item_flaregun', 'item_dynamite', 'item_tablet',
            'item_flashlight_mega', 'item_plunger', 'item_crossbow',
            'item_revolver', 'item_shotgun', 'item_pickaxe'
        ]
    
    # Generate random item children
    children = []
    for _ in range(20):
        # 70% chance for arena pistol, otherwise random item
        if random.random() < 0.7 and 'item_arena_pistol' in item_ids:
            selected_item = 'item_arena_pistol'
        else:
            selected_item = random.choice(item_ids)
        
        children.append({
            'itemID': selected_item,
            'scaleModifier': 100,
            'colorHue': random.randint(10, 111),
            'colorSaturation': random.randint(10, 111)
        })
    
    payload = {
        'objects': [{
            'collection': 'user_inventory',
            'key': 'gameplay_loadout',
            'permission_read': 1,
            'permission_write': 1,
            'value': json.dumps({
                'version': 1,
                'back': {
                    'itemID': 'item_backpack_large_base',
                    'scaleModifier': 120,
                    'colorHue': 50,
                    'colorSaturation': 50,
                    'children': children
                }
            })
        }]
    }
    
    return payload

# Mock data responses
CLIENT_BOOTSTRAP_RESPONSE = {
    'payload': '{"updateType":"Optional","attestResult":"Valid","attestTokenExpiresAt":1820877961,"photonAppID":"xxxxxx","photonVoiceAppID":"xxxxxx","termsAcceptanceNeeded":[],"dailyMissionDateKey":"","dailyMissions":null,"dailyMissionResetTime":0,"serverTimeUnix":1720877961,"gameDataURL":"https://xeracompany.pythonanywhere.com/game-data-prod.zip}'
}

ECON_GAMEPLAY_ITEMS_RESPONSE = {
    'payload': '[{"id":"item_apple","netID":71,"name":"Apple","description":"An apple a day keeps the doctor away!","category":"Consumables","price":200,"value":7,"isLoot":true,"isPurchasable":false,"isUnique":false,"isDevOnly":false},{"id":"item_arrow","netID":103,"name":"Arrow","description":"Can be attached to the crossbow.","category":"Ammo","price":199,"value":8,"isLoot":false,"isPurchasable":true,"isUnique":false,"isDevOnly":false},{"id":"item_arrow_heart","netID":116,"name":"Heart Arrow","description":"A love-themed arrow that will have your targets seeing hearts! ","category":"Ammo","price":199,"value":8,"isLoot":false,"isPurchasable":true,"isUnique":false,"isDevOnly":false} ... ]'
}

STORAGE_RESPONSE = {
    'objects': [
        {
            'collection': 'user_avatar',
            'key': '0',
            'user_id': '2e8aace0-282d-4c3d-b9d4-6a3b3ba2c2a6',
            'value': '{"butt": "bp_butt_gorilla", "head": "bp_head_gorilla", "tail": "", "torso": "bp_torso_gorilla", "armLeft": "bp_arm_l_gorilla", "eyeLeft": "bp_eye_gorilla", "armRight": "bp_arm_r_gorilla", "eyeRight": "bp_eye_gorilla", "accessories": ["acc_fit_varsityjacket"], "primaryColor": "604170"}',
            'version': '7a326a2a4d0639a5f08e3116bb99a3bf',
            'permission_read': 2,
            'create_time': '2024-10-29T00:22:08Z',
            'update_time': '2025-04-04T03:55:19Z'
        },
        # ... (other storage objects truncated for brevity)
    ]
}

ACCOUNT_RESPONSE = {
    'user': {
        'id': '2e8aace0-282d-4c3d-b9d4-6a3b3ba2c2a6',
        'username': 'ERROR',
        'lang_tag': 'en',
        'metadata': '{}',
        'edge_count': 4,
        'create_time': '2024-08-24T07:30:12Z',
        'update_time': '2025-04-05T21:00:27Z'
    },
    'wallet': '{"stashCols": 4, "stashRows": 2, "hardCurrency": 30000000, "softCurrency": 20000000, "researchPoints": 500000}',
    'custom_id': '26344644298513663'
}

MOCK_TOKENS = {
    'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aWQiOiI3OGU0NDBiOS00NWZjLTRhODYtOTllMy02ZGM5Y2RjN2M1N2UiLCJ1aWQiOiJmM2E1NjE4YS1hMzNmLTQyMDAtYThiYS1lYjM3YzdiZmJmOWMiLCJ1c24iOiJ4ZW5pdHl5dCIsInZycyI6eyJhdXRoSUQiOiJkYTEzZjU4YzJiMjU0ZTgwYTM5YzA3YzRlNzkyNjlmOSIsImNsaWVudFVzZXJBZ2VudCI6Ik1ldGFRdWVzdCAxLjE2LjMuMTEzOF81ZWRjYmQ5OCIsImRldmljZUlEIjoiMTcyZjZjMmU3MWE5NGMwMTBjMWY2Mjk5OWJjM2QzMjEiLCJsb2dpblR5cGUiOiJtZXRhX3F1ZXN0In0sImV4cCI6MTc0NDA2MzQwNiwiaWF0IjoxNzQzOTk0MzE4fQ.nRJLbep6nCGeBTwruOunyNjDUiLxfcvpAJHl7E6n3m8',
    'refresh_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aWQiOiI3OGU0NDBiOS00NWZjLTRhODYtOTllMy02ZGM5Y2RjN2M1N2UiLCJ1aWQiOiJmM2E1NjE4YS1hMzNmLTQyMDAtYThiYS1lYjM3YzdiZmJmOWMiLCJ1c24iOiJ4ZW5pdHl5dCIsInZycyI6eyJhdXRoSUQiOiJkYTEzZjU4YzJiMjU0ZTgwYTM5YzA3YzRlNzkyNjlmOSIsImNsaWVudFVzZXJBZ2VudCI6Ik1ldGFRdWVzdCAxLjE2LjMuMTEzOF81ZWRjYmQ5OCIsImRldmljZUlEIjoiMTcyZjZjMmU3MWE5NGMwMTBjMWY2Mjk5OWJjM2QzMjEiLCJsb2dpblR5cGUiOiJtZXRhX3F1ZXN0In0sImV4cCI6MTc0NDE0NjIwNiwiaWF0IjoxNzQzOTk0MzE4fQ.f7nTHNnPrJW6oYYo54RDks1iDvntTP2yiBfpHdH-ygQ'
}

# Request logging to Discord
@app.after_request
def log_request_to_discord(response):
    """Log all requests to Discord webhook"""
    method = request.method
    url = request.url
    path = request.path
    headers = dict(request.headers)
    body = request.get_data(as_text=True)
    query_params = dict(request.args)
    status_code = response.status_code
    
    message = {
        'content': f"📡 **Request to: {path}**",
        'embeds': [{
            'title': 'Request Details',
            'fields': [
                {'name': 'Method', 'value': method, 'inline': True},
                {'name': 'Path', 'value': path, 'inline': True},
                {'name': 'Status Code', 'value': str(status_code), 'inline': True},
                {'name': 'Full URL', 'value': url, 'inline': False},
                {
                    'name': 'Query Params',
                    'value': f"```json\n{json.dumps(query_params, indent=2)}```" if query_params else '*(none)*',
                    'inline': False
                },
                {
                    'name': 'Headers',
                    'value': f"```json\n{json.dumps(headers, indent=2)}```",
                    'inline': False
                },
                {
                    'name': 'Body',
                    'value': f"```json\n{body}```" if body else '*(empty)*',
                    'inline': False
                }
            ],
            'color': 65280 if status_code < 400 else 16711680  # Green for success, Red for errors
        }]
    }
    
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=message)
    except Exception:
        pass  # Silently fail if Discord webhook fails
    
    return response

# Routes
@app.route('/v2/account/authenticate/custom', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def authenticate_custom():
    """Custom authentication endpoint"""
    # Generate a gameplay loadout (side effect)
    generate_gameplay_loadout()
    
    # Return real or mock tokens based on configuration
    return jsonify(generate_auth_tokens() if USE_REAL_TOKENS else MOCK_TOKENS)

@app.route('/v2/account1', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def account1():
    """Account endpoint (alternative)"""
    return jsonify(ACCOUNT_RESPONSE)

@app.route('/v2/rpc/purchase.avatarItems', methods=['POST'])
def purchase_avatar_items():
    """Handle avatar item purchases"""
    return jsonify({'payload': ''})

@app.route('/v2/rpc/avatar.update', methods=['POST'])
def avatar_update():
    """Handle avatar updates"""
    return jsonify({'payload': ''})

@app.route('/v2/rpc/purchase.gameplayItems', methods=['POST'])
def purchase_gameplay_items():
    """Handle gameplay item purchases"""
    return jsonify({'payload': ''})

@app.route('/game-data-prod.zip')
def serve_game_data():
    """Serve game data zip file with IP-based access control"""
    client_ip = request.remote_addr
    print(f"Request from IP: {client_ip}")
    
    # Determine which file to serve based on IP trust
    if is_trusted_ip(client_ip):
        file_name = 'Zombie.zip'  # Note: both branches use same file?
    else:
        file_name = 'Zombie.zip'
    
    file_path = os.path.join('/home/XeraCompany/mysite', file_name)
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return 'File not found', 404
    
    file_size = os.path.getsize(file_path)
    print(f"Serving {file_name}, size: {file_size} bytes")
    
    try:
        return send_file(
            file_path,
            mimetype='application/zip',
            as_attachment=False,
            download_name=file_name,
            max_age=3600
        )
    except Exception as e:
        print(f"Error serving file: {e}")
        return f"Error: {str(e)}", 500

@app.route('/v2/account', methods=['GET', 'PUT'])
def account():
    """Main account endpoint - handles user retrieval and updates"""
    if request.method == 'PUT':
        # Handle account updates
        response = jsonify({})
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Content-Type'] = 'application/json'
        response.headers['Grpc-Metadata-Content-Type'] = 'application/grpc'
        return response
    
    try:
        # Get or create user from IP
        ip = get_client_ip()
        user, is_banned = get_or_create_user(ip)
        
        if is_banned or user is None:
            print(f"[ERROR] User banned or None - IP: {ip}, banned: {is_banned}, user: {user}")
            raise Exception('User is banned or DB failed')
        
        # Set username based on trust status
        username = 'XERA COMPANY'
        if is_trusted_ip(ip):
            username = 'ALEX [HELPER]'
        
        return jsonify({
            'user': {
                'id': '2e8aace0-282d-4c3d-b9d4-6a3b3ba2c2a6',
                'username': username,
                'lang_tag': 'en',
                'metadata': json.dumps({'isDeveloper': str(is_trusted_ip(ip))}),
                'edge_count': 4,
                'create_time': '2024-08-24T07:30:12Z',
                'update_time': '2025-04-05T21:00:27Z'
            },
            'wallet': '{"stashCols": 16, "stashRows": 8, "hardCurrency": 0, "softCurrency": 20000000, "researchPoints": 69420}',
            'custom_id': user['custom_id']
        })
    
    except Exception as e:
        print(f"[FALLBACK] DB failed or user banned: {e}")
        traceback.print_exc()
        return jsonify(ACCOUNT_RESPONSE)

@app.route('/v2/account/alt2', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def account_alt2():
    """Alternative account endpoint returning storage data"""
    return jsonify(STORAGE_RESPONSE)

@app.route('/v2/account/link/device', methods=['POST'])
def link_device():
    """Handle device linking"""
    return jsonify({
        'id': secrets.token_hex(16),
        'user_id': '13b8dce4-2c8e-4945-90b6-19af0c2b0ad7',
        'linked': True,
        'create_time': '2025-01-15T18:08:45Z'
    })

@app.route('/v2/account/session/refresh', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def refresh_session():
    """Refresh authentication session"""
    return jsonify(generate_auth_tokens() if USE_REAL_TOKENS else MOCK_TOKENS)

@app.route('/v2/rpc/attest.start', methods=['POST'])
def attest_start():
    """Start attestation process"""
    return jsonify({
        'payload': json.dumps({
            'status': 'success',
            'attestResult': 'Valid',
            'message': 'Attestation validated'
        })
    })

@app.route('/v2/storage', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def storage():
    """Storage endpoint for user data"""
    if request.method == 'POST':
        try:
            data = request.get_json(force=True)
            
            if data and 'object_ids' in data:
                user_id = data['object_ids'][0].get('user_id') if data['object_ids'] else None
                
                if user_id:
                    response_objects = []
                    
                    for obj in STORAGE_RESPONSE['objects']:
                        new_obj = obj.copy()
                        new_obj['user_id'] = user_id
                        
                        # Generate fresh gameplay loadout if needed
                        if obj.get('key') == 'gameplay_loadout':
                            payload = generate_gameplay_loadout()
                            new_obj['value'] = payload['objects'][0]['value']
                        
                        response_objects.append(new_obj)
                    
                    return jsonify({'objects': response_objects})
                else:
                    return jsonify({'objects': []})
            else:
                return jsonify({'objects': []})
        
        except Exception as e:
            print(f"Storage error: {e}")
            return jsonify({'objects': []})
    
    return jsonify(STORAGE_RESPONSE)

@app.route('/v2/storage/econ_gameplay_items', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def storage_econ_gameplay_items():
    """Storage endpoint for economy/gameplay items"""
    return jsonify(ECON_GAMEPLAY_ITEMS_RESPONSE)

@app.route('/v2/rpc/mining.balance', methods=['GET'])
def mining_balance():
    """Get mining balance"""
    response_body = {
        'payload': json.dumps({
            'hardCurrency': 20000000,
            'researchPoints': 999999
        })
    }
    return jsonify(response_body), 200

@app.route('/v2/rpc/purchase.list', methods=['GET'])
def purchase_list():
    """List purchases"""
    response_body = {
        'payload': json.dumps({
            'purchases': [
                {
                    'user_id': '13b8dce4-2c8e-4945-90b6-19af0c2b0ad7',
                    'product_id': 'RESEARCH_PACK',
                    'transaction_id': '540282689176766',
                    'store': 3,
                    'purchase_time': {'seconds': 1741450711},
                    'create_time': {'seconds': 1741450837, 'nanos': 694669000},
                    'update_time': {'seconds': 1741450837, 'nanos': 694669000},
                    'refund_time': {},
                    'provider_response': json.dumps({'success': True}),
                    'environment': 2
                },
                {
                    'user_id': '13b8dce4-2c8e-4945-90b6-19af0c2b0ad7',
                    'product_id': 'G.O.A.T_BUNDLE',
                    'transaction_id': '540281232510245',
                    'store': 3,
                    'purchase_time': {'seconds': 1741450591},
                    'create_time': {'seconds': 1741450722, 'nanos': 851245000},
                    'update_time': {'seconds': 1741450722, 'nanos': 851245000},
                    'refund_time': {},
                    'provider_response': json.dumps({'success': True}),
                    'environment': 2
                }
            ]
        })
    }
    return jsonify(response_body), 200

@app.route('/v2/rpc/clientBootstrap', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def client_bootstrap():
    """Client bootstrap endpoint"""
    return jsonify(CLIENT_BOOTSTRAP_RESPONSE)

@app.route('/auth', methods=['GET', 'POST'])
def photon_auth():
    """Photon authentication endpoint"""
    auth_token = request.args.get('auth_token')
    print('🔐 Photon Auth Request Received')
    
    if auth_token:
        print(f"auth_token: {auth_token}")
        message = 'Authentication successful'
    else:
        print('⚠️ No auth_token provided')
        message = 'Authenticated without token'
    
    fake_user_id = secrets.token_hex(16)
    fake_session_id = secrets.token_hex(12)
    
    return jsonify({
        'ResultCode': 1,
        'Message': message,
        'UserId': fake_user_id,
        'SessionID': fake_session_id,
        'Authenticated': True
    }), 200

@app.route('/debug', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def debug_endpoint():
    """Debug endpoint that forwards request details to Discord"""
    method = request.method
    url = request.url
    headers = dict(request.headers)
    body = request.get_data(as_text=True)
    
    message = {
        'content': '📡 **/debug request received**',
        'embeds': [{
            'title': 'Request Info',
            'fields': [
                {'name': 'Method', 'value': method, 'inline': True},
                {'name': 'URL', 'value': url, 'inline': False},
                {
                    'name': 'Headers',
                    'value': f"```json\n{json.dumps(headers, indent=2)}```",
                    'inline': False
                },
                {
                    'name': 'Body',
                    'value': f"```json\n{body}```" if body else '*(empty)*',
                    'inline': False
                }
            ],
            'color': 65484  # Some blue color
        }]
    }
    
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=message)
    except Exception as e:
        return f"Failed to send to Discord: {e}", 500
    
    return 'Sent debug to discord', 200

# Alias for compatibility
app_alias = app

if __name__ == '__main__':
    app.run(debug=False)
