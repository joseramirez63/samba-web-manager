from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from functools import wraps
import json
import subprocess
import os
import secrets
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import shutil
import logging
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['VERSION'] = '1.3.0'

DATA_DIR = '/opt/samba-manager/data'
CONFIG_FILE = '/etc/samba-manager/config.env'
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
SHARES_FILE = os.path.join(DATA_DIR, 'shares.json')
PERMISSIONS_FILE = os.path.join(DATA_DIR, 'permissions.json')
LOGS_FILE = os.path.join(DATA_DIR, 'logs.json')

# Editable file extensions
EDITABLE_EXTENSIONS = {'.txt', '.py', '.sh', '.conf', '.cfg', '.ini', '.json', '.xml', '.yaml', '.yml',
                       '.md', '.log', '.html', '.css', '.js', '.php', '.sql', '.env', '.htaccess'}

MIN_PASSWORD_LENGTH = 8


def load_secret_key():
    """Load SECRET_KEY from config file, environment variable, or generate a temporary one."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('SECRET_KEY='):
                    return line.split('=', 1)[1].strip().strip('"').strip("'")
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    # Fallback: generate a random key (sessions won't persist across restarts)
    logging.warning('SECRET_KEY not found in %s or environment. Using a temporary random key.', CONFIG_FILE)
    return secrets.token_hex(32)


app.secret_key = load_secret_key()

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri='memory://'
)

os.makedirs(DATA_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(DATA_DIR, 'app.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def load_json(filepath, default=None):
    if default is None:
        default = {}
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return default

def save_json(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

def add_log(action, user, details=''):
    logs = load_json(LOGS_FILE, [])
    logs.append({
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'user': user,
        'details': details
    })
    if len(logs) > 1000:
        logs = logs[-1000:]
    save_json(LOGS_FILE, logs)
    logging.info(f"{user} - {action} - {details}")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Sesión requerida'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Sesión requerida'}), 401
        if not session.get('is_admin', False):
            return jsonify({'error': 'Se requieren permisos de administrador'}), 403
        return f(*args, **kwargs)
    return decorated_function

def get_file_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

def get_disk_usage(path):
    try:
        stat = os.statvfs(path)
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bfree * stat.f_frsize
        used = total - free
        return {
            'total': get_file_size(total),
            'used': get_file_size(used),
            'free': get_file_size(free),
            'percent': round((used / total) * 100, 1) if total > 0 else 0
        }
    except:
        return None

def run_command(cmd):
    """Run a command and return the result."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr
    except FileNotFoundError:
        return False, 'Command not found'

def validate_share_name(name):
    """Validate share name — spaces and special characters are not allowed."""
    if not name:
        return False, 'Share name cannot be empty'
    if ' ' in name:
        return False, 'Share name cannot contain spaces'
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return False, 'Share name can only contain letters, numbers, hyphens and underscores'
    return True, ''

def update_smb_conf():
    shares = load_json(SHARES_FILE, {})
    permissions = load_json(PERMISSIONS_FILE, {})

    conf_content = """[global]
   workgroup = WORKGROUP
   server string = Samba Server
   server role = standalone server
   security = user
   map to guest = never
   dns proxy = no
   min protocol = SMB2
   wins support = yes

"""

    for share_name, share_data in shares.items():
        path = share_data['path']

        valid_users = []
        write_users = []

        for username, perm in permissions.get(share_name, {}).items():
            if perm in ('read', 'write'):
                valid_users.append(username)
            if perm == 'write':
                write_users.append(username)

        conf_content += f"""[{share_name}]
   path = {path}
   browseable = yes
   read only = yes
   guest ok = no
   create mask = 0664
   directory mask = 0775
   force user = nobody
   force group = nogroup
   valid users = {' '.join(valid_users) if valid_users else '@nobody'}
   write list = {' '.join(write_users)}

"""

    try:
        with open('/etc/samba/smb.conf', 'w') as f:
            f.write(conf_content)
    except PermissionError:
        process = subprocess.Popen(['/usr/bin/sudo', '/usr/bin/tee', '/etc/samba/smb.conf'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, stderr = process.communicate(input=conf_content.encode())
        if process.returncode != 0:
            logging.error('Failed to write smb.conf via sudo tee: %s', stderr.decode())

def restart_samba():
    run_command(['/usr/bin/sudo', '/usr/bin/systemctl', 'restart', 'smbd'])

@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', version=app.config['VERSION'])
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    return render_template('login.html', version=app.config['VERSION'])

@app.route('/api/login', methods=['POST'])
@limiter.limit('10 per minute')
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    users = load_json(USERS_FILE, {})
    
    if username in users and check_password_hash(users[username]['password'], password):
        session['username'] = username
        session['is_admin'] = users[username].get('is_admin', False)
        add_log('Login', username, 'Successful login')
        return jsonify({
            'message': 'Login successful',
            'is_admin': session['is_admin'],
            'username': username,
            'force_password_change': users[username].get('force_password_change', False)
        }), 200
    
    add_log('Login', username or 'Unknown', 'Failed login attempt')
    return jsonify({'error': 'Incorrect username or password'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    username = session.get('username', 'Unknown')
    add_log('Logout', username, 'Session closed')
    session.clear()
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/api/me', methods=['GET'])
@login_required
def get_me():
    return jsonify({
        'username': session.get('username'),
        'is_admin': session.get('is_admin', False)
    }), 200

@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if not old_password or not new_password:
        return jsonify({'error': 'Old and new password are required'}), 400

    if len(new_password) < MIN_PASSWORD_LENGTH:
        return jsonify({'error': f'Password must be at least {MIN_PASSWORD_LENGTH} characters long'}), 400
    
    users = load_json(USERS_FILE, {})
    username = session['username']
    
    if not check_password_hash(users[username]['password'], old_password):
        return jsonify({'error': 'Old password is incorrect'}), 401
    
    users[username]['password'] = generate_password_hash(new_password)
    save_json(USERS_FILE, users)
    
    process = subprocess.Popen(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-a', username], 
                              stdin=subprocess.PIPE, 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
    process.communicate(input=f'{new_password}\n{new_password}\n'.encode())
    run_command(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-e', username])
    
    add_log('Password Change', username, 'Password changed successfully')
    return jsonify({'message': 'Password changed successfully'}), 200

@app.route('/api/force-change-password', methods=['POST'])
@login_required
def force_change_password():
    """Endpoint for forced password change on first login."""
    data = request.json
    new_password = data.get('new_password')

    if not new_password or len(new_password) < MIN_PASSWORD_LENGTH:
        return jsonify({'error': f'Password must be at least {MIN_PASSWORD_LENGTH} characters long'}), 400

    users = load_json(USERS_FILE, {})
    username = session['username']

    if not users[username].get('force_password_change', False):
        return jsonify({'error': 'Password change is not required'}), 400

    users[username]['password'] = generate_password_hash(new_password)
    users[username]['force_password_change'] = False
    save_json(USERS_FILE, users)

    process = subprocess.Popen(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-a', username],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    process.communicate(input=f'{new_password}\n{new_password}\n'.encode())
    run_command(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-e', username])

    add_log('Password Change', username, 'Password changed on first login')
    return jsonify({'message': 'Password updated successfully'}), 200

@app.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    users = load_json(USERS_FILE, {})
    user_list = []
    for username, user_data in users.items():
        user_list.append({
            'username': username,
            'is_admin': user_data.get('is_admin', False),
            'created': user_data.get('created', '')
        })
    return jsonify(user_list), 200

@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    is_admin = data.get('is_admin', False)
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    if len(password) < MIN_PASSWORD_LENGTH:
        return jsonify({'error': f'Password must be at least {MIN_PASSWORD_LENGTH} characters long'}), 400
    
    users = load_json(USERS_FILE, {})
    
    if username in users:
        return jsonify({'error': 'This user already exists'}), 400
    
    users[username] = {
        'password': generate_password_hash(password),
        'is_admin': is_admin,
        'created': datetime.now().isoformat()
    }
    save_json(USERS_FILE, users)
    
    run_command(['/usr/bin/sudo', '/usr/sbin/useradd', '-M', '-s', '/sbin/nologin', username])
    
    process = subprocess.Popen(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-a', username], 
                              stdin=subprocess.PIPE, 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
    process.communicate(input=f'{password}\n{password}\n'.encode())
    run_command(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-e', username])
    
    add_log('User Created', session['username'], f'User {username} created')
    return jsonify({'message': 'User created'}), 201

@app.route('/api/users/<username>/password', methods=['POST'])
@admin_required
def change_user_password(username):
    data = request.json
    new_password = data.get('new_password')
    
    if not new_password:
        return jsonify({'error': 'New password is required'}), 400

    if len(new_password) < MIN_PASSWORD_LENGTH:
        return jsonify({'error': f'Password must be at least {MIN_PASSWORD_LENGTH} characters long'}), 400
    
    users = load_json(USERS_FILE, {})
    
    if username not in users:
        return jsonify({'error': 'User not found'}), 404
    
    users[username]['password'] = generate_password_hash(new_password)
    save_json(USERS_FILE, users)
    
    process = subprocess.Popen(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-a', username], 
                              stdin=subprocess.PIPE, 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
    process.communicate(input=f'{new_password}\n{new_password}\n'.encode())
    run_command(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-e', username])
    
    add_log('Password Change (Admin)', session['username'], f'Password of {username} changed')
    return jsonify({'message': 'Password changed'}), 200

@app.route('/api/users/<username>', methods=['DELETE'])
@admin_required
def delete_user(username):
    if username == 'admin':
        return jsonify({'error': 'The admin user cannot be deleted'}), 400
    
    users = load_json(USERS_FILE, {})
    
    if username not in users:
        return jsonify({'error': 'User not found'}), 404
    
    del users[username]
    save_json(USERS_FILE, users)
    
    permissions = load_json(PERMISSIONS_FILE, {})
    for share_name in permissions:
        if username in permissions[share_name]:
            del permissions[share_name][username]
    save_json(PERMISSIONS_FILE, permissions)
    
    run_command(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-x', username])
    run_command(['/usr/bin/sudo', '/usr/sbin/userdel', username])
    
    update_smb_conf()
    restart_samba()
    
    add_log('User Deleted', session['username'], f'User {username} deleted')
    return jsonify({'message': 'User deleted'}), 200

@app.route('/api/shares', methods=['GET'])
@login_required
def get_shares():
    shares = load_json(SHARES_FILE, {})
    share_list = []
    for share_name, share_data in shares.items():
        share_list.append({
            'name': share_name,
            'path': share_data['path'],
            'created': share_data.get('created', '')
        })
    return jsonify(share_list), 200

@app.route('/api/directories', methods=['GET'])
@admin_required
def get_directories():
    path = request.args.get('path', '/')
    
    try:
        items = []
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            if os.path.isdir(item_path):
                try:
                    has_children = len([x for x in os.listdir(item_path) if os.path.isdir(os.path.join(item_path, x))]) > 0
                except:
                    has_children = False
                items.append({
                    'name': item,
                    'path': item_path,
                    'has_children': has_children
                })
        items.sort(key=lambda x: x['name'].lower())
        return jsonify(items), 200
    except PermissionError:
        return jsonify([]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/shares', methods=['POST'])
@admin_required
def create_share():
    data = request.json
    share_name = data.get('name')
    path = data.get('path')
    
    if not share_name or not path:
        return jsonify({'error': 'Name and path are required'}), 400
    
    valid, error_msg = validate_share_name(share_name)
    if not valid:
        return jsonify({'error': error_msg}), 400
    
    shares = load_json(SHARES_FILE, {})
    
    if share_name in shares:
        return jsonify({'error': 'This share already exists'}), 400
    
    if not os.path.exists(path):
        run_command(['/usr/bin/sudo', '/usr/bin/mkdir', '-p', path])
    # Always apply ownership and mode so that existing directories also have
    # the correct permissions for the 'force user = nobody' Samba configuration.
    run_command(['/usr/bin/sudo', '/usr/bin/chown', '-R', 'nobody:nogroup', path])
    run_command(['/usr/bin/sudo', '/usr/bin/chmod', '-R', '775', path])
    
    shares[share_name] = {
        'path': path,
        'created': datetime.now().isoformat()
    }
    
    save_json(SHARES_FILE, shares)
    update_smb_conf()
    restart_samba()
    
    add_log('Share Created', session['username'], f'Share {share_name} created')
    return jsonify({'message': 'Share created'}), 201

@app.route('/api/shares/<share_name>', methods=['PUT'])
@admin_required
def update_share(share_name):
    data = request.json
    new_name = data.get('new_name')
    new_path = data.get('new_path')
    
    if not new_name:
        return jsonify({'error': 'New name is required'}), 400
    
    valid, error_msg = validate_share_name(new_name)
    if not valid:
        return jsonify({'error': error_msg}), 400
    
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Share not found'}), 404
    
    if new_name != share_name and new_name in shares:
        return jsonify({'error': 'A share with this name already exists'}), 400
    
    share_data = shares[share_name]
    if new_path:
        share_data['path'] = new_path
    
    if new_name != share_name:
        shares[new_name] = share_data
        del shares[share_name]
        
        permissions = load_json(PERMISSIONS_FILE, {})
        if share_name in permissions:
            permissions[new_name] = permissions[share_name]
            del permissions[share_name]
            save_json(PERMISSIONS_FILE, permissions)
    else:
        shares[share_name] = share_data
    
    save_json(SHARES_FILE, shares)
    update_smb_conf()
    restart_samba()
    
    add_log('Share Updated', session['username'], f'Share {share_name} updated')
    return jsonify({'message': 'Share updated'}), 200

@app.route('/api/shares/<share_name>', methods=['DELETE'])
@admin_required
def delete_share(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Share not found'}), 404
    
    del shares[share_name]
    save_json(SHARES_FILE, shares)
    
    permissions = load_json(PERMISSIONS_FILE, {})
    if share_name in permissions:
        del permissions[share_name]
    save_json(PERMISSIONS_FILE, permissions)
    
    update_smb_conf()
    restart_samba()
    
    add_log('Share Deleted', session['username'], f'Share {share_name} deleted')
    return jsonify({'message': 'Share deleted'}), 200

@app.route('/api/permissions', methods=['GET'])
@login_required
def get_permissions():
    permissions = load_json(PERMISSIONS_FILE, {})
    return jsonify(permissions), 200

@app.route('/api/permissions', methods=['POST'])
@admin_required
def set_permission():
    data = request.json
    share_name = data.get('share')
    username = data.get('user')
    permission = data.get('permission')
    
    if not share_name or not username or not permission:
        return jsonify({'error': 'Share, user and permission are required'}), 400
    
    shares = load_json(SHARES_FILE, {})
    users = load_json(USERS_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Share not found'}), 404
    
    if username not in users:
        return jsonify({'error': 'User not found'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    
    if share_name not in permissions:
        permissions[share_name] = {}
    
    if permission == 'none':
        if username in permissions[share_name]:
            del permissions[share_name][username]
    else:
        permissions[share_name][username] = permission
    
    save_json(PERMISSIONS_FILE, permissions)
    update_smb_conf()
    restart_samba()
    
    add_log('Permission Set', session['username'], f'{permission} permission set for {username} on {share_name}')
    return jsonify({'message': 'Permission set'}), 200

@app.route('/api/my-shares', methods=['GET'])
@login_required
def get_my_shares():
    username = session['username']
    is_admin = session.get('is_admin', False)
    permissions = load_json(PERMISSIONS_FILE, {})
    shares = load_json(SHARES_FILE, {})
    
    my_shares = []
    for share_name, share_data in shares.items():
        if is_admin:
            # Admin can see all shares
            my_shares.append({
                'name': share_name,
                'path': share_data['path'],
                'permission': 'write'  # Admin always has write access
            })
        elif username in permissions.get(share_name, {}):
            my_shares.append({
                'name': share_name,
                'path': share_data['path'],
                'permission': permissions[share_name][username]
            })
    
    return jsonify(my_shares), 200

@app.route('/api/files/<share_name>', methods=['GET'])
@login_required
def list_files(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Share not found'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    user_perm = permissions.get(share_name, {}).get(session['username'])
    
    if not user_perm and not session.get('is_admin'):
        return jsonify({'error': 'You do not have access to this share'}), 403
    
    path = shares[share_name]['path']
    subpath = request.args.get('path', '')
    full_path = os.path.join(path, subpath)
    
    if not os.path.abspath(full_path).startswith(os.path.abspath(path)):
        return jsonify({'error': 'Invalid path'}), 400
    
    if not os.path.exists(full_path):
        return jsonify({'error': 'Directory not found'}), 404
    
    files = []
    try:
        for item in os.listdir(full_path):
            item_path = os.path.join(full_path, item)
            stat = os.stat(item_path)
            
            _, ext = os.path.splitext(item)
            is_editable = ext.lower() in EDITABLE_EXTENSIONS and os.path.isfile(item_path)
            
            files.append({
                'name': item,
                'type': 'directory' if os.path.isdir(item_path) else 'file',
                'size': get_file_size(stat.st_size) if os.path.isfile(item_path) else '-',
                'size_bytes': stat.st_size if os.path.isfile(item_path) else 0,
                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'editable': is_editable
            })
    except PermissionError:
        return jsonify({'error': 'Cannot read directory'}), 403
    
    files.sort(key=lambda x: (x['type'] != 'directory', x['name'].lower()))
    
    return jsonify({
        'files': files,
        'current_path': subpath,
        'can_write': user_perm == 'write' or session.get('is_admin')
    }), 200

@app.route('/api/files/<share_name>/read', methods=['POST'])
@login_required
def read_file(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Share not found'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    user_perm = permissions.get(share_name, {}).get(session['username'])
    
    if not user_perm and not session.get('is_admin'):
        return jsonify({'error': 'You do not have access to this share'}), 403
    
    data = request.json
    file_path = data.get('path', '')
    
    path = shares[share_name]['path']
    full_path = os.path.join(path, file_path)
    
    if not os.path.abspath(full_path).startswith(os.path.abspath(path)):
        return jsonify({'error': 'Invalid path'}), 400
    
    if not os.path.exists(full_path):
        return jsonify({'error': 'File not found'}), 404
    
    if os.path.isdir(full_path):
        return jsonify({'error': 'Cannot read a directory'}), 400
    
    # File size limit: max 1 MB
    if os.path.getsize(full_path) > 1024 * 1024:
        return jsonify({'error': 'File too large (max 1 MB)'}), 400
    
    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        add_log('File Read', session['username'], f'{share_name}/{file_path} read')
        return jsonify({'content': content}), 200
    except UnicodeDecodeError:
        return jsonify({'error': 'File is not in text format'}), 400
    except Exception as e:
        logging.error('Error reading file %s/%s: %s', share_name, file_path, e)
        return jsonify({'error': 'Cannot read file'}), 500

@app.route('/api/files/<share_name>/write', methods=['POST'])
@login_required
def write_file(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Share not found'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    user_perm = permissions.get(share_name, {}).get(session['username'])
    
    if user_perm != 'write' and not session.get('is_admin'):
        return jsonify({'error': 'You do not have write permission'}), 403
    
    data = request.json
    file_path = data.get('path', '')
    content = data.get('content', '')
    
    path = shares[share_name]['path']
    full_path = os.path.join(path, file_path)
    
    if not os.path.abspath(full_path).startswith(os.path.abspath(path)):
        return jsonify({'error': 'Invalid path'}), 400
    
    try:
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        safe_path = os.path.realpath(full_path)
        os.chmod(safe_path, 0o664)
        run_command(['/usr/bin/sudo', '/usr/bin/chown', 'nobody:nogroup', safe_path])
        
        add_log('File Written', session['username'], f'{share_name}/{file_path} saved')
        return jsonify({'message': 'File saved'}), 200
    except Exception as e:
        logging.error('Error writing file %s/%s: %s', share_name, file_path, e)
        return jsonify({'error': 'Cannot save file'}), 500

@app.route('/api/files/<share_name>/download', methods=['GET'])
@login_required
def download_file(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Share not found'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    user_perm = permissions.get(share_name, {}).get(session['username'])
    
    if not user_perm and not session.get('is_admin'):
        return jsonify({'error': 'You do not have access to this share'}), 403
    
    path = shares[share_name]['path']
    file_path = request.args.get('path', '')
    full_path = os.path.join(path, file_path)
    
    if not os.path.abspath(full_path).startswith(os.path.abspath(path)):
        return jsonify({'error': 'Invalid path'}), 400
    
    if not os.path.exists(full_path):
        return jsonify({'error': 'File not found'}), 404
    
    if os.path.isdir(full_path):
        return jsonify({'error': 'Cannot download a directory'}), 400
    
    add_log('File Downloaded', session['username'], f'{share_name}/{file_path} downloaded')
    return send_file(full_path, as_attachment=True, download_name=os.path.basename(full_path))

@app.route('/api/files/<share_name>/upload', methods=['POST'])
@login_required
def upload_file(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Share not found'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    user_perm = permissions.get(share_name, {}).get(session['username'])
    
    if user_perm != 'write' and not session.get('is_admin'):
        return jsonify({'error': 'You do not have write permission'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    path = shares[share_name]['path']
    subpath = request.form.get('path', '')
    full_path = os.path.join(path, subpath)
    
    if not os.path.abspath(full_path).startswith(os.path.abspath(path)):
        return jsonify({'error': 'Invalid path'}), 400
    
    if not os.path.exists(full_path):
        return jsonify({'error': 'Directory not found'}), 404
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(full_path, filename)
    
    try:
        file.save(file_path)
        safe_file_path = os.path.realpath(file_path)
        os.chmod(safe_file_path, 0o664)
        run_command(['/usr/bin/sudo', '/usr/bin/chown', 'nobody:nogroup', safe_file_path])
    except Exception as e:
        logging.error('Error uploading file to %s/%s: %s', share_name, subpath, e)
        return jsonify({'error': 'Cannot upload file'}), 500
    
    add_log('File Uploaded', session['username'], f'{share_name}/{subpath}/{filename} uploaded')
    return jsonify({'message': 'File uploaded', 'filename': filename}), 201

@app.route('/api/files/<share_name>/delete', methods=['POST'])
@login_required
def delete_file(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Share not found'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    user_perm = permissions.get(share_name, {}).get(session['username'])
    
    if user_perm != 'write' and not session.get('is_admin'):
        return jsonify({'error': 'You do not have delete permission'}), 403
    
    data = request.json
    file_path = data.get('path', '')
    
    path = shares[share_name]['path']
    full_path = os.path.join(path, file_path)
    
    if not os.path.abspath(full_path).startswith(os.path.abspath(path)):
        return jsonify({'error': 'Invalid path'}), 400
    
    if not os.path.exists(full_path):
        return jsonify({'error': 'File or folder not found'}), 404
    
    try:
        if os.path.isdir(full_path):
            shutil.rmtree(full_path)
        else:
            os.remove(full_path)
    except Exception as e:
        logging.error('Error deleting %s/%s: %s', share_name, file_path, e)
        return jsonify({'error': 'Cannot delete'}), 500
    
    add_log('File Deleted', session['username'], f'{share_name}/{file_path} deleted')
    return jsonify({'message': 'Deleted'}), 200

@app.route('/api/files/<share_name>/mkdir', methods=['POST'])
@login_required
def create_folder(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Share not found'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    user_perm = permissions.get(share_name, {}).get(session['username'])
    
    if user_perm != 'write' and not session.get('is_admin'):
        return jsonify({'error': 'You do not have write permission'}), 403
    
    data = request.json
    folder_name = data.get('name', '')
    current_path = data.get('path', '')
    
    if not folder_name:
        return jsonify({'error': 'Folder name is required'}), 400
    
    path = shares[share_name]['path']
    full_path = os.path.join(path, current_path, secure_filename(folder_name))
    
    if not os.path.abspath(full_path).startswith(os.path.abspath(path)):
        return jsonify({'error': 'Invalid path'}), 400
    
    if os.path.exists(full_path):
        return jsonify({'error': 'A folder with this name already exists'}), 400
    
    try:
        os.makedirs(full_path, mode=0o775)
        safe_folder_path = os.path.realpath(full_path)
        run_command(['/usr/bin/sudo', '/usr/bin/chown', 'nobody:nogroup', safe_folder_path])
    except Exception as e:
        logging.error('Error creating folder %s/%s/%s: %s', share_name, current_path, folder_name, e)
        return jsonify({'error': 'Cannot create folder'}), 500
    
    add_log('Folder Created', session['username'], f'{share_name}/{current_path}/{folder_name} created')
    return jsonify({'message': 'Folder created'}), 201

@app.route('/api/status', methods=['GET'])
@login_required
def get_status():
    try:
        result = subprocess.run(['/usr/bin/systemctl', 'is-active', 'smbd'],
                                capture_output=True, text=True)
        samba_status = result.stdout.strip()
    except Exception:
        samba_status = 'unknown'

    wsdd_status = 'not_installed'
    for wsdd_service in ('wsdd2', 'wsdd'):
        try:
            result = subprocess.run(['/usr/bin/systemctl', 'is-active', wsdd_service],
                                    capture_output=True, text=True)
            status_out = result.stdout.strip()
            if status_out in ('active', 'inactive', 'failed'):
                wsdd_status = status_out
                break
        except Exception:
            pass

    shares = load_json(SHARES_FILE, {})
    disk_info = {}
    for share_name, share_data in shares.items():
        usage = get_disk_usage(share_data['path'])
        if usage:
            disk_info[share_name] = usage

    return jsonify({
        'samba': samba_status,
        'wsdd': wsdd_status,
        'users_count': len(load_json(USERS_FILE, {})),
        'shares_count': len(load_json(SHARES_FILE, {})),
        'disk_usage': disk_info
    }), 200

@app.route('/api/logs', methods=['GET'])
@admin_required
def get_logs():
    logs = load_json(LOGS_FILE, [])
    limit = int(request.args.get('limit', 100))
    return jsonify(logs[-limit:]), 200

def init_admin():
    users = load_json(USERS_FILE, {})
    if 'admin' not in users:
        users['admin'] = {
            'password': generate_password_hash('admin123'),
            'is_admin': True,
            'created': datetime.now().isoformat(),
            'force_password_change': True
        }
        save_json(USERS_FILE, users)
        print('Admin user created: admin / admin123')
        print('⚠️  Please change the default password on first login!')

if __name__ == '__main__':
    init_admin()
    app.run(host='0.0.0.0', port=5000, debug=False)
