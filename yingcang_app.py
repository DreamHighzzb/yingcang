# -*- coding: utf-8 -*-
"""盈仓 · 进销存管理系统 - Flask 后端（MySQL + 只读分享 + 安全加固版）"""
import os
import time
import secrets
from functools import wraps

import pymysql
from pymysql.cursors import DictCursor

from flask import Flask, request, jsonify, session, g, send_from_directory
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ==================== 密钥：优先环境变量，其次本地文件持久化 ====================
def _load_or_create_secret_key():
    env = os.environ.get('YINGCANG_SECRET_KEY')
    if env and len(env) >= 32:
        return env
    path = os.path.join(BASE_DIR, '.yingcang_secret')
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                key = f.read().strip()
            if len(key) >= 32:
                return key
        key = secrets.token_hex(32)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(key)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        print('🔑 已生成新的 secret_key 并保存到 %s（请勿提交到 Git）' % path)
        return key
    except Exception as e:
        print('⚠️ 无法持久化 secret_key：%s，本次使用临时密钥（重启后登录失效）' % e)
        return secrets.token_hex(32)

# ==================== HTTPS 检测 ====================
CERT_FILE = os.environ.get('YINGCANG_CERT', os.path.join(BASE_DIR, 'cert.pem'))
KEY_FILE  = os.environ.get('YINGCANG_KEY',  os.path.join(BASE_DIR, 'key.pem'))
USE_HTTPS = os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)

# ==================== Flask 应用 ====================
app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = _load_or_create_secret_key()

app.config.update(
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=USE_HTTPS,
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
    JSON_SORT_KEYS=False,
)
try:
    app.json.ensure_ascii = False
except Exception:
    pass

# ==================== CORS ====================
CORS(app, supports_credentials=True, origins=[
    r'https?://localhost(:\d+)?',
    r'https?://127\.0\.0\.1(:\d+)?',
    r'https?://192\.168\.\d{1,3}\.\d{1,3}(:\d+)?',
    r'https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?',
    r'https?://172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(:\d+)?',
])

# ==================== 安全响应头 ====================
@app.after_request
def _add_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'same-origin'
    resp.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    if request.is_secure:
        resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return resp

# ==================== 数据库配置 ====================
DB_CONFIG = {
    'host':     os.environ.get('YINGCANG_DB_HOST', '127.0.0.1'),
    'port': int(os.environ.get('YINGCANG_DB_PORT', '3306')),
    'user':     os.environ.get('YINGCANG_DB_USER', 'root'),
    'password': os.environ.get('YINGCANG_DB_PASS', 'zzb123'),
    'database': os.environ.get('YINGCANG_DB_NAME', 'game'),
    'charset': 'utf8mb4',
    'autocommit': False,
    'cursorclass': DictCursor,
    'init_command': "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
}

# ==================== 数据库连接 ====================
def get_db():
    if 'db' not in g:
        g.conn = pymysql.connect(**DB_CONFIG)
        g.db = g.conn.cursor()
    return g.db

@app.teardown_appcontext
def close_db(exception):
    conn = g.pop('conn', None)
    if conn is not None:
        try:
            conn.rollback()
        except Exception:
            pass
        conn.close()

def _column_exists(cur, table, column):
    cur.execute("""
        SELECT COUNT(*) AS c FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s
    """, (table, column))
    row = cur.fetchone()
    return bool(row and row.get('c'))

def init_db():
    cfg = dict(DB_CONFIG)
    dbname = cfg.pop('database')
    cfg.pop('cursorclass', None)
    cfg.pop('init_command', None)
    cfg['autocommit'] = True
    cfg['charset'] = 'utf8mb4'

    conn = pymysql.connect(**cfg)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "CREATE DATABASE IF NOT EXISTS `%s` "
                "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci" % dbname
            )
            cur.execute("USE `%s`" % dbname)
            cur.execute(
                "ALTER DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci" % dbname
            )
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id            INT AUTO_INCREMENT PRIMARY KEY,
                    username      VARCHAR(64)  NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at    BIGINT       NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS products (
                    id         INT AUTO_INCREMENT PRIMARY KEY,
                    user_id    INT           NOT NULL,
                    name       VARCHAR(128)  NOT NULL,
                    unit       VARCHAR(32)   NOT NULL DEFAULT '',
                    min_stock  DOUBLE        NOT NULL DEFAULT 0,
                    created_at BIGINT        NOT NULL,
                    updated_at BIGINT        NOT NULL,
                    KEY idx_products_user (user_id),
                    KEY idx_products_name (name)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS inbound_records (
                    id         INT AUTO_INCREMENT PRIMARY KEY,
                    user_id    INT          NOT NULL,
                    product_id INT          NOT NULL,
                    quantity   DOUBLE       NOT NULL,
                    price      DOUBLE       NOT NULL DEFAULT 0,
                    remark     VARCHAR(255) NOT NULL DEFAULT '',
                    created_at BIGINT       NOT NULL,
                    KEY idx_in_user (user_id),
                    KEY idx_in_product (product_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS outbound_records (
                    id         INT AUTO_INCREMENT PRIMARY KEY,
                    user_id    INT          NOT NULL,
                    product_id INT          NOT NULL,
                    quantity   DOUBLE       NOT NULL,
                    price      DOUBLE       NOT NULL DEFAULT 0,
                    remark     VARCHAR(255) NOT NULL DEFAULT '',
                    created_at BIGINT       NOT NULL,
                    KEY idx_out_user (user_id),
                    KEY idx_out_product (product_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS shares (
                    id          INT AUTO_INCREMENT PRIMARY KEY,
                    token       VARCHAR(64) NOT NULL UNIQUE,
                    user_id     INT         NOT NULL,
                    enabled     TINYINT     NOT NULL DEFAULT 1,
                    expire_at   BIGINT      NOT NULL DEFAULT 0,
                    visit_count INT         NOT NULL DEFAULT 0,
                    last_visit  BIGINT      NOT NULL DEFAULT 0,
                    created_at  BIGINT      NOT NULL,
                    KEY idx_shares_user (user_id),
                    KEY idx_shares_token (token)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            # 兼容旧库
            for tbl in ('inbound_records', 'outbound_records'):
                if not _column_exists(cur, tbl, 'price'):
                    try:
                        cur.execute(
                            "ALTER TABLE `%s` ADD COLUMN price DOUBLE NOT NULL DEFAULT 0 AFTER quantity" % tbl
                        )
                        print('🔧 已为表 %s 添加 price 字段' % tbl)
                    except Exception as e:
                        print('⚠️ 为表 %s 添加 price 字段失败：%s' % (tbl, e))

            if _column_exists(cur, 'products', 'price'):
                try:
                    cur.execute("ALTER TABLE `products` DROP COLUMN price")
                    print('🔧 已从表 products 删除 price 字段')
                except Exception as e:
                    print('⚠️ 删除 products.price 失败：%s' % e)

            if _column_exists(cur, 'products', 'stock'):
                try:
                    cur.execute("ALTER TABLE `products` DROP COLUMN stock")
                    print('🔧 已从表 products 删除 stock 字段（库存改为按流水实时汇总）')
                except Exception as e:
                    print('⚠️ 删除 products.stock 失败：%s' % e)

            for tbl in ('users', 'products', 'inbound_records', 'outbound_records', 'shares'):
                try:
                    cur.execute(
                        "ALTER TABLE `%s` CONVERT TO CHARACTER SET utf8mb4 "
                        "COLLATE utf8mb4_unicode_ci" % tbl
                    )
                except Exception as e:
                    print('⚠️ 转换表 %s 失败：%s' % (tbl, e))
    finally:
        conn.close()

# ==================== 通用工具 ====================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        return f(*args, **kwargs)
    return decorated

def to_float(v, default=0.0):
    try:
        if v is None or v == '':
            return default
        return float(v)
    except (TypeError, ValueError):
        return default

def generate_share_token():
    return secrets.token_hex(16)

def share_to_dict(row):
    base = request.host_url.rstrip('/')
    token = row['token']
    return {
        'id': row['id'],
        'token': token,
        'enabled': bool(row['enabled']),
        'expireAt': int(row['expire_at'] or 0),
        'visitCount': int(row['visit_count'] or 0),
        'lastVisit': int(row['last_visit'] or 0),
        'createdAt': int(row['created_at'] or 0),
        'url': '%s/?share=%s' % (base, token),
    }

# 库存：入库合计 - 出库合计（固定文本，不含 %s 占位符）
_STOCK_SQL = """
    COALESCE((SELECT SUM(i.quantity) FROM inbound_records i
              WHERE i.product_id = p.id AND i.user_id = p.user_id), 0)
    -
    COALESCE((SELECT SUM(o.quantity) FROM outbound_records o
              WHERE o.product_id = p.id AND o.user_id = p.user_id), 0)
"""

def get_product_stock(db, user_id, product_id):
    db.execute("""
        SELECT
          COALESCE((SELECT SUM(quantity) FROM inbound_records
                    WHERE product_id=%s AND user_id=%s), 0)
          -
          COALESCE((SELECT SUM(quantity) FROM outbound_records
                    WHERE product_id=%s AND user_id=%s), 0)
          AS stock
    """, (product_id, user_id, product_id, user_id))
    row = db.fetchone()
    return to_float(row['stock'], 0.0) if row else 0.0

# ==================== 登录/注册限流 ====================
_LOGIN_FAILS = {}
_MAX_FAILS = 5
_LOCKOUT_SECONDS = 300

def _client_ip():
    return request.remote_addr or 'unknown'

def _check_login_rate(ip):
    now = time.time()
    rec = _LOGIN_FAILS.get(ip)
    if not rec or rec['reset_at'] < now:
        return True
    return rec['count'] < _MAX_FAILS

def _record_login_fail(ip):
    now = time.time()
    rec = _LOGIN_FAILS.get(ip)
    if not rec or rec['reset_at'] < now:
        _LOGIN_FAILS[ip] = {'count': 1, 'reset_at': now + _LOCKOUT_SECONDS}
    else:
        rec['count'] += 1

def _clear_login_fail(ip):
    _LOGIN_FAILS.pop(ip, None)

@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return e
    app.logger.exception('未处理异常')
    return jsonify({'error': '服务器内部错误，请稍后重试'}), 500

@app.route('/')
def index():
    return send_from_directory('.', 'zdq.html')

# ==================== 认证 ====================
@app.route('/api/auth/register', methods=['POST'])
def auth_register():
    ip = _client_ip()
    if not _check_login_rate(ip):
        return jsonify({'error': '操作过于频繁，请 5 分钟后再试'}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': '请求数据无效'}), 400

    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if len(username) < 2 or len(username) > 20:
        return jsonify({'error': '用户名长度需为 2-20 个字符'}), 400
    if not all(c.isalnum() or c == '_' or '\u4e00' <= c <= '\u9fff' for c in username):
        return jsonify({'error': '用户名只能包含中文、字母、数字和下划线'}), 400
    if len(password) < 6:
        return jsonify({'error': '密码长度至少 6 位'}), 400

    db = get_db()
    db.execute('SELECT id FROM users WHERE username=%s', (username,))
    if db.fetchone():
        return jsonify({'error': '用户名已存在'}), 409

    now = int(time.time() * 1000)
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    db.execute(
        'INSERT INTO users (username, password_hash, created_at) VALUES (%s, %s, %s)',
        (username, password_hash, now)
    )
    g.conn.commit()
    new_id = db.lastrowid

    session.clear()
    session['user_id'] = new_id
    session['username'] = username
    return jsonify({'id': new_id, 'username': username}), 201

@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    ip = _client_ip()
    if not _check_login_rate(ip):
        return jsonify({'error': '尝试次数过多，请 5 分钟后再试'}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': '请求数据无效'}), 400

    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    if not username or not password:
        return jsonify({'error': '请输入用户名和密码'}), 400

    db = get_db()
    db.execute('SELECT * FROM users WHERE username=%s', (username,))
    user = db.fetchone()

    if not user or not check_password_hash(user['password_hash'], password):
        _record_login_fail(ip)
        return jsonify({'error': '用户名或密码错误'}), 401

    _clear_login_fail(ip)
    session.clear()
    session['user_id'] = user['id']
    session['username'] = user['username']
    return jsonify({'id': user['id'], 'username': user['username']})

@app.route('/api/auth/me', methods=['GET'])
def auth_me():
    if 'user_id' not in session:
        return jsonify({'error': '未登录'}), 401
    return jsonify({'id': session['user_id'], 'username': session['username']})

@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    session.clear()
    return jsonify({'message': '已退出'})

# ==================== 商品 ====================
@app.route('/api/products', methods=['GET'])
@login_required
def get_products():
    db = get_db()
    sql = (
        "SELECT p.id, p.name, p.unit, p.min_stock AS minStock, "
        "p.created_at, p.updated_at, (" + _STOCK_SQL + ") AS stock "
        "FROM products p WHERE p.user_id=%s ORDER BY p.id DESC"
    )
    db.execute(sql, (session['user_id'],))
    return jsonify(db.fetchall())

@app.route('/api/products', methods=['POST'])
@login_required
def create_product():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': '商品名称不能为空'}), 400

    unit = (data.get('unit') or '').strip()
    min_stock = to_float(data.get('minStock'), 0.0)
    if min_stock < 0:
        return jsonify({'error': '最低库存不能为负数'}), 400

    db = get_db()
    db.execute('SELECT id FROM products WHERE user_id=%s AND name=%s',
               (session['user_id'], name))
    if db.fetchone():
        return jsonify({'error': '已存在同名商品'}), 409

    now = int(time.time() * 1000)
    db.execute("""
        INSERT INTO products (user_id, name, unit, min_stock, created_at, updated_at)
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (session['user_id'], name, unit, min_stock, now, now))
    g.conn.commit()
    return jsonify({
        'id': db.lastrowid, 'name': name, 'unit': unit,
        'stock': 0, 'minStock': min_stock
    }), 201

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@login_required
def update_product(product_id):
    data = request.get_json(silent=True) or {}
    db = get_db()
    db.execute('SELECT * FROM products WHERE id=%s AND user_id=%s',
               (product_id, session['user_id']))
    product = db.fetchone()
    if not product:
        return jsonify({'error': '商品不存在'}), 404

    name = (data.get('name') or '').strip() or product['name']
    unit = data.get('unit')
    unit = product['unit'] if unit is None else str(unit).strip()
    min_stock = to_float(data.get('minStock'), product['min_stock'])
    if min_stock < 0:
        return jsonify({'error': '最低库存不能为负数'}), 400

    if name != product['name']:
        db.execute('SELECT id FROM products WHERE user_id=%s AND name=%s AND id<>%s',
                   (session['user_id'], name, product_id))
        if db.fetchone():
            return jsonify({'error': '已存在同名商品'}), 409

    now = int(time.time() * 1000)
    db.execute("""
        UPDATE products
        SET name=%s, unit=%s, min_stock=%s, updated_at=%s
        WHERE id=%s AND user_id=%s
    """, (name, unit, min_stock, now, product_id, session['user_id']))
    g.conn.commit()
    stock = get_product_stock(db, session['user_id'], product_id)
    return jsonify({'id': product_id, 'name': name, 'unit': unit,
                    'stock': stock, 'minStock': min_stock})

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@login_required
def delete_product(product_id):
    db = get_db()
    db.execute('SELECT id FROM products WHERE id=%s AND user_id=%s',
               (product_id, session['user_id']))
    if not db.fetchone():
        return jsonify({'error': '商品不存在'}), 404

    db.execute('DELETE FROM inbound_records  WHERE product_id=%s AND user_id=%s',
               (product_id, session['user_id']))
    db.execute('DELETE FROM outbound_records WHERE product_id=%s AND user_id=%s',
               (product_id, session['user_id']))
    db.execute('DELETE FROM products WHERE id=%s AND user_id=%s',
               (product_id, session['user_id']))
    g.conn.commit()
    return jsonify({'message': '已删除'})

# ==================== 一键清空 ====================
@app.route('/api/clear/products', methods=['POST'])
@login_required
def clear_products():
    """清空当前用户的全部商品，连带其入库/出库记录"""
    db = get_db()
    uid = session['user_id']
    try:
        db.execute('SELECT COUNT(*) AS c FROM products WHERE user_id=%s', (uid,))
        n_products = int((db.fetchone() or {}).get('c') or 0)

        db.execute('SELECT COUNT(*) AS c FROM inbound_records WHERE user_id=%s', (uid,))
        n_in = int((db.fetchone() or {}).get('c') or 0)

        db.execute('SELECT COUNT(*) AS c FROM outbound_records WHERE user_id=%s', (uid,))
        n_out = int((db.fetchone() or {}).get('c') or 0)

        db.execute('DELETE FROM inbound_records  WHERE user_id=%s', (uid,))
        db.execute('DELETE FROM outbound_records WHERE user_id=%s', (uid,))
        db.execute('DELETE FROM products         WHERE user_id=%s', (uid,))
        g.conn.commit()
        return jsonify({
            'message': '已清空',
            'products': n_products,
            'inbound': n_in,
            'outbound': n_out
        })
    except Exception:
        g.conn.rollback()
        raise

@app.route('/api/clear/inbound', methods=['POST'])
@login_required
def clear_inbound_records():
    """清空当前用户的全部入库记录"""
    db = get_db()
    uid = session['user_id']
    try:
        db.execute('SELECT COUNT(*) AS c FROM inbound_records WHERE user_id=%s', (uid,))
        n = int((db.fetchone() or {}).get('c') or 0)
        db.execute('DELETE FROM inbound_records WHERE user_id=%s', (uid,))
        g.conn.commit()
        return jsonify({'message': '已清空入库记录', 'deleted': n})
    except Exception:
        g.conn.rollback()
        raise

@app.route('/api/clear/outbound', methods=['POST'])
@login_required
def clear_outbound_records():
    """清空当前用户的全部出库记录"""
    db = get_db()
    uid = session['user_id']
    try:
        db.execute('SELECT COUNT(*) AS c FROM outbound_records WHERE user_id=%s', (uid,))
        n = int((db.fetchone() or {}).get('c') or 0)
        db.execute('DELETE FROM outbound_records WHERE user_id=%s', (uid,))
        g.conn.commit()
        return jsonify({'message': '已清空出库记录', 'deleted': n})
    except Exception:
        g.conn.rollback()
        raise

# ==================== 入库 / 出库 ====================
@app.route('/api/inbound', methods=['POST'])
@login_required
def create_inbound():
    data = request.get_json(silent=True) or {}
    product_id = data.get('productId')
    quantity = to_float(data.get('quantity'), 0.0)
    remark = str(data.get('remark') or '')
    price = to_float(data.get('price'), 0.0)
    if not product_id or quantity <= 0:
        return jsonify({'error': '参数无效'}), 400

    db = get_db()
    db.execute('SELECT id FROM products WHERE id=%s AND user_id=%s',
               (product_id, session['user_id']))
    if not db.fetchone():
        return jsonify({'error': '商品不存在'}), 404

    now = int(time.time() * 1000)
    db.execute("""
        INSERT INTO inbound_records (user_id, product_id, quantity, price, remark, created_at)
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (session['user_id'], product_id, quantity, price, remark, now))
    g.conn.commit()
    return jsonify({
        'message': '入库成功', 'id': db.lastrowid, 'productId': product_id,
        'quantity': quantity, 'price': price, 'remark': remark, 'time': now,
        'stock': get_product_stock(db, session['user_id'], product_id)
    }), 201

@app.route('/api/outbound', methods=['POST'])
@login_required
def create_outbound():
    data = request.get_json(silent=True) or {}
    product_id = data.get('productId')
    quantity = to_float(data.get('quantity'), 0.0)
    remark = str(data.get('remark') or '')
    price = to_float(data.get('price'), 0.0)
    if not product_id or quantity <= 0:
        return jsonify({'error': '参数无效'}), 400

    db = get_db()
    db.execute('SELECT id FROM products WHERE id=%s AND user_id=%s',
               (product_id, session['user_id']))
    if not db.fetchone():
        return jsonify({'error': '商品不存在'}), 404

    current_stock = get_product_stock(db, session['user_id'], product_id)
    if current_stock < quantity:
        return jsonify({'error': '库存不足'}), 400

    now = int(time.time() * 1000)
    db.execute("""
        INSERT INTO outbound_records (user_id, product_id, quantity, price, remark, created_at)
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (session['user_id'], product_id, quantity, price, remark, now))
    g.conn.commit()
    return jsonify({
        'message': '出库成功', 'id': db.lastrowid, 'productId': product_id,
        'quantity': quantity, 'price': price, 'remark': remark, 'time': now,
        'stock': get_product_stock(db, session['user_id'], product_id)
    }), 201

# ==================== 记录查询（LIMIT 10000） ====================
@app.route('/api/records/inbound', methods=['GET'])
@login_required
def get_inbound_records():
    db = get_db()
    db.execute("""
        SELECT r.id, r.product_id AS productId, r.quantity, r.price, r.remark,
               r.created_at AS time, p.name AS productName, p.unit AS productUnit
        FROM inbound_records r
        LEFT JOIN products p ON r.product_id = p.id
        WHERE r.user_id = %s ORDER BY r.id DESC LIMIT 10000
    """, (session['user_id'],))
    return jsonify(db.fetchall())

@app.route('/api/records/outbound', methods=['GET'])
@login_required
def get_outbound_records():
    db = get_db()
    db.execute("""
        SELECT r.id, r.product_id AS productId, r.quantity, r.price, r.remark,
               r.created_at AS time, p.name AS productName, p.unit AS productUnit
        FROM outbound_records r
        LEFT JOIN products p ON r.product_id = p.id
        WHERE r.user_id = %s ORDER BY r.id DESC LIMIT 10000
    """, (session['user_id'],))
    return jsonify(db.fetchall())

@app.route('/api/records/inbound/<int:record_id>', methods=['DELETE'])
@login_required
def delete_inbound_record(record_id):
    db = get_db()
    db.execute('SELECT id FROM inbound_records WHERE id=%s AND user_id=%s',
               (record_id, session['user_id']))
    if not db.fetchone():
        return jsonify({'error': '记录不存在'}), 404
    db.execute('DELETE FROM inbound_records WHERE id=%s AND user_id=%s',
               (record_id, session['user_id']))
    g.conn.commit()
    return jsonify({'message': '已删除'})

@app.route('/api/records/outbound/<int:record_id>', methods=['DELETE'])
@login_required
def delete_outbound_record(record_id):
    db = get_db()
    db.execute('SELECT id FROM outbound_records WHERE id=%s AND user_id=%s',
               (record_id, session['user_id']))
    if not db.fetchone():
        return jsonify({'error': '记录不存在'}), 404
    db.execute('DELETE FROM outbound_records WHERE id=%s AND user_id=%s',
               (record_id, session['user_id']))
    g.conn.commit()
    return jsonify({'message': '已删除'})

# ==================== 分享管理 ====================
@app.route('/api/shares', methods=['POST'])
@login_required
def create_share():
    data = request.get_json(silent=True) or {}
    try:
        days = int(data.get('expireDays') or 0)
    except (TypeError, ValueError):
        days = 0
    if days < 0:
        days = 0

    now = int(time.time() * 1000)
    expire_at = 0 if days == 0 else now + days * 24 * 3600 * 1000

    db = get_db()
    token = generate_share_token()
    for _ in range(5):
        db.execute('SELECT id FROM shares WHERE token=%s', (token,))
        if not db.fetchone():
            break
        token = generate_share_token()

    db.execute("""
        INSERT INTO shares (token, user_id, enabled, expire_at, visit_count, last_visit, created_at)
        VALUES (%s,%s,1,%s,0,0,%s)
    """, (token, session['user_id'], expire_at, now))
    g.conn.commit()
    sid = db.lastrowid
    return jsonify(share_to_dict({
        'id': sid, 'token': token, 'user_id': session['user_id'],
        'enabled': 1, 'expire_at': expire_at, 'visit_count': 0,
        'last_visit': 0, 'created_at': now
    })), 201

@app.route('/api/shares', methods=['GET'])
@login_required
def list_shares():
    db = get_db()
    db.execute("""
        SELECT id, token, user_id, enabled, expire_at, visit_count, last_visit, created_at
        FROM shares WHERE user_id=%s ORDER BY id DESC
    """, (session['user_id'],))
    return jsonify([share_to_dict(r) for r in db.fetchall()])

@app.route('/api/shares/<int:share_id>', methods=['PUT'])
@login_required
def update_share(share_id):
    data = request.get_json(silent=True) or {}
    db = get_db()
    db.execute('SELECT * FROM shares WHERE id=%s AND user_id=%s',
               (share_id, session['user_id']))
    row = db.fetchone()
    if not row:
        return jsonify({'error': '分享不存在'}), 404
    if 'enabled' in data:
        enabled = 1 if data.get('enabled') else 0
        db.execute('UPDATE shares SET enabled=%s WHERE id=%s AND user_id=%s',
                   (enabled, share_id, session['user_id']))
        g.conn.commit()
        row['enabled'] = enabled
    return jsonify(share_to_dict(row))

@app.route('/api/shares/<int:share_id>', methods=['DELETE'])
@login_required
def delete_share(share_id):
    db = get_db()
    db.execute('SELECT id FROM shares WHERE id=%s AND user_id=%s',
               (share_id, session['user_id']))
    if not db.fetchone():
        return jsonify({'error': '分享不存在'}), 404
    db.execute('DELETE FROM shares WHERE id=%s AND user_id=%s',
               (share_id, session['user_id']))
    g.conn.commit()
    return jsonify({'message': '已删除'})

# ==================== 公开只读访问（LIMIT 10000） ====================
_SHARE_HITS = {}
_SHARE_LIMIT = 120
_SHARE_WINDOW = 60

def _check_share_rate(ip):
    now = time.time()
    rec = _SHARE_HITS.get(ip)
    if not rec or rec['reset_at'] < now:
        _SHARE_HITS[ip] = {'count': 1, 'reset_at': now + _SHARE_WINDOW}
        return True
    rec['count'] += 1
    return rec['count'] <= _SHARE_LIMIT

@app.route('/api/share/<token>', methods=['GET'])
def get_shared_data(token):
    ip = _client_ip()
    if not _check_share_rate(ip):
        return jsonify({'error': '访问过于频繁，请稍后再试'}), 429

    if not token or len(token) > 64 or not all(c in '0123456789abcdef' for c in token.lower()):
        return jsonify({'error': '分享链接无效'}), 404

    db = get_db()
    db.execute("""
        SELECT s.id, s.token, s.user_id, s.enabled, s.expire_at,
               s.visit_count, s.last_visit, s.created_at,
               u.username AS owner_name
        FROM shares s
        LEFT JOIN users u ON s.user_id = u.id
        WHERE s.token=%s
    """, (token,))
    row = db.fetchone()
    if not row:
        return jsonify({'error': '分享链接无效或已被删除'}), 404
    if not row['enabled']:
        return jsonify({'error': '分享链接已被关闭'}), 403

    now = int(time.time() * 1000)
    expire_at = int(row['expire_at'] or 0)
    if expire_at and expire_at < now:
        return jsonify({'error': '分享链接已过期'}), 403

    owner_id = row['user_id']
    db.execute('UPDATE shares SET visit_count = visit_count + 1, last_visit=%s WHERE id=%s',
               (now, row['id']))
    g.conn.commit()

    sql = (
        "SELECT p.id, p.name, p.unit, p.min_stock AS minStock, "
        "(" + _STOCK_SQL + ") AS stock "
        "FROM products p WHERE p.user_id=%s ORDER BY p.id DESC"
    )
    db.execute(sql, (owner_id,))
    products = db.fetchall()

    db.execute("""
        SELECT r.id, r.product_id AS productId, r.quantity, r.price, r.remark,
               r.created_at AS time, p.name AS productName, p.unit AS productUnit
        FROM inbound_records r
        LEFT JOIN products p ON r.product_id = p.id
        WHERE r.user_id = %s ORDER BY r.id DESC LIMIT 10000
    """, (owner_id,))
    inbound = db.fetchall()

    db.execute("""
        SELECT r.id, r.product_id AS productId, r.quantity, r.price, r.remark,
               r.created_at AS time, p.name AS productName, p.unit AS productUnit
        FROM outbound_records r
        LEFT JOIN products p ON r.product_id = p.id
        WHERE r.user_id = %s ORDER BY r.id DESC LIMIT 10000
    """, (owner_id,))
    outbound = db.fetchall()

    return jsonify({
        'owner': {'username': row['owner_name'] or '未知用户'},
        'expireAt': expire_at,
        'products': products,
        'inboundRecords': inbound,
        'outboundRecords': outbound,
        'readonly': True,
    })

# ==================== 批量导入 ====================
@app.route('/api/import', methods=['POST'])
@login_required
def import_data():
    data = request.get_json(silent=True) or {}
    products = data.get('products') or []
    inbound = data.get('inbound') or []
    outbound = data.get('outbound') or []

    if len(products) + len(inbound) + len(outbound) > 20000:
        return jsonify({'error': '单次导入行数过多（上限 20000）'}), 413

    db = get_db()
    uid = session['user_id']
    now = int(time.time() * 1000)
    added = updated = skipped = 0
    in_count = out_count = 0
    warnings = []

    def find_product(name):
        db.execute('SELECT * FROM products WHERE user_id=%s AND name=%s', (uid, name))
        return db.fetchone()

    def ensure_product(name, unit='个'):
        p = find_product(name)
        if p:
            return p
        db.execute("""
            INSERT INTO products (user_id, name, unit, min_stock, created_at, updated_at)
            VALUES (%s,%s,%s,0,%s,%s)
        """, (uid, name, unit, now, now))
        return {'id': db.lastrowid, 'name': name, 'unit': unit, 'min_stock': 0.0}

    try:
        # ---------- 商品 ----------
        for p in products:
            name = str(p.get('name') or '').strip()[:128]
            if not name:
                skipped += 1
                continue
            unit = str(p.get('unit') or '').strip()[:32]
            existing = find_product(name)
            if existing:
                new_unit = unit or existing['unit']
                new_min = existing['min_stock'] if p.get('minStock') is None else max(0.0, to_float(p.get('minStock'), existing['min_stock']))
                db.execute("""
                    UPDATE products SET unit=%s, min_stock=%s, updated_at=%s
                    WHERE id=%s AND user_id=%s
                """, (new_unit, new_min, now, existing['id'], uid))
                updated += 1
            else:
                db.execute("""
                    INSERT INTO products (user_id, name, unit, min_stock, created_at, updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s)
                """, (uid, name, unit or '个',
                      max(0.0, to_float(p.get('minStock'), 0.0)), now, now))
                added += 1

        # ---------- 入库 ----------
        for r in inbound:
            name = str(r.get('name') or r.get('productName') or '').strip()[:128]
            qty = to_float(r.get('quantity'), 0.0)
            if not name or qty <= 0:
                skipped += 1
                continue
            prod = ensure_product(name, '个')
            ts = int(to_float(r.get('time'), now)) or now
            rec_price = to_float(r.get('price'), 0.0)
            db.execute("""
                INSERT INTO inbound_records (user_id, product_id, quantity, price, remark, created_at)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (uid, prod['id'], qty, rec_price, str(r.get('remark') or '')[:255], ts))
            in_count += 1

        # ---------- 出库（已去掉库存不足判断，允许负库存） ----------
        for r in outbound:
            name = str(r.get('name') or r.get('productName') or '').strip()[:128]
            qty = to_float(r.get('quantity'), 0.0)
            if not name or qty <= 0:
                skipped += 1
                continue
            prod = ensure_product(name, '个')
            ts = int(to_float(r.get('time'), now)) or now
            rec_price = to_float(r.get('price'), 0.0)
            db.execute("""
                INSERT INTO outbound_records (user_id, product_id, quantity, price, remark, created_at)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (uid, prod['id'], qty, rec_price, str(r.get('remark') or '')[:255], ts))
            out_count += 1

        g.conn.commit()
    except Exception:
        g.conn.rollback()
        raise

    return jsonify({
        'added': added, 'updated': updated, 'skipped': skipped,
        'inbound': in_count, 'outbound': out_count, 'warnings': warnings
    })

# ==================== 启动 ====================
try:
    init_db()
    print('✅ 数据库初始化完成')
except Exception as _e:
    print('⚠️ 数据库初始化失败：%s' % _e)

if __name__ == '__main__':
    if USE_HTTPS:
        print('🔒 已启用 HTTPS（证书：%s）' % CERT_FILE)
        app.run(host='0.0.0.0', port=5000, ssl_context=(CERT_FILE, KEY_FILE), debug=False)
    else:
        print('=' * 60)
        print('⚠️  当前以 HTTP 启动，密码和 Cookie 均为明文传输！')
        print('    如需在局域网/公网使用，请务必启用 HTTPS：')
        print('    1) 生成自签名证书：')
        print('       openssl req -x509 -newkey rsa:4096 -nodes \\')
        print('         -keyout key.pem -out cert.pem -days 365 \\')
        print('         -subj "/CN=127.0.0.1"')
        print('    2) 重启本服务，会自动识别 cert.pem / key.pem')
        print('=' * 60)
        app.run(host='127.0.0.1', port=5000, debug=False)
