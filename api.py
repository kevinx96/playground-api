import os
import psycopg2
import json
from flask import Flask, jsonify, request
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt
from psycopg2.extras import RealDictCursor, execute_batch
import decimal
import jwt
from functools import wraps
import requests
import threading
import firebase_admin # [NEW] 导入 Firebase Admin
from firebase_admin import credentials, messaging # [NEW] 导入 credentials 和 messaging

# --- 配置 ---
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'my_dev_secret_key_please_change_me')

DATABASE_URL = os.environ.get('DATABASE_URL')
IMAGE_BASE_URL = os.environ.get('IMAGE_BASE_URL') 
FCM_PROJECT_ID = os.environ.get('FCM_PROJECT_ID') # [NEW] V1 需要
SERVICE_ACCOUNT_FILE = '/etc/secrets/service-account.json' # [NEW] Render Secret File 路径

if not IMAGE_BASE_URL:
    print("警告: 'IMAGE_BASE_URL' 环境变量未设置。HLS 和图片 URL 可能不正确。")
    IMAGE_BASE_URL = "https://subdistichously-polliniferous-ileen.ngrok-free.dev" 

bcrypt = Bcrypt(app)

# --- [NEW] 初始化 Firebase Admin SDK ---
try:
    if os.path.exists(SERVICE_ACCOUNT_FILE):
        cred = credentials.Certificate(SERVICE_ACCOUNT_FILE)
        firebase_admin.initialize_app(cred)
        print("Firebase Admin SDK 初始化成功。")
    else:
        # 这是一个关键错误，因为 Render Secret File [cite:`Firebase_FCM_V1_Guide.md`] 应该存在
        print("严重错误: 未找到 'service-account.json'。FCM 通知将无法发送。")
except Exception as e:
    # 避免因重复初始化而崩溃 (例如在本地调试时)
    if 'already exists' in str(e):
        print("Firebase Admin SDK 已初始化。")
    else:
        print(f"Firebase Admin SDK 初始化失败: {e}")
# --- 结束 Firebase 初始化 ---


# --- 数据库辅助函数 ---
def get_db_connection():
    """建立数据库连接"""
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL 环境变量未设置。")
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except psycopg2.OperationalError as e:
        print(f"数据库连接失败: {e}")
        raise

# --- [MODIFIED] FCM V1 通知功能 ---
def _send_fcm_notification_v1(event_id, equipment_type, risk_type):
    """
    (在单独的线程中运行) 查询所有设备令牌并使用 Firebase Admin SDK (V1) 发送通知。
    """
    if not firebase_admin._DEFAULT_APP:
        print("Firebase Admin SDK 未初始化，跳过通知。")
        return

    conn = None
    cursor = None
    try:
        # 在新线程中，必须创建新的数据库连接
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("SELECT device_token FROM user_devices")
        rows = cursor.fetchall()
        device_tokens = [row['device_token'] for row in rows]

        if not device_tokens:
            print("没有注册用于通知的设备。")
            return
        
        # 将内部 risk_type 转换为用户友好的中文
        risk_text = "危险行为" if risk_type == 'abnormal' else "普通事件"

        # 1. 创建通知体 (Notification)
        notification = messaging.Notification(
            title="⚠️ 游乐场安全警报",
            body=f"在 [{equipment_type}] 检测到新的 [{risk_text}]。"
        )
        
        # 2. 创建数据负载 (Data Payload)
        data_payload = {
            "click_action": "FLUTTER_NOTIFICATION_CLICK",
            "event_id": str(event_id)
        }

        # 3. 创建多播消息 (MulticastMessage)
        message = messaging.MulticastMessage(
            tokens=device_tokens,
            notification=notification,
            data=data_payload,
            # [NEW] 设置 Android 特定的高优先级
            android=messaging.AndroidConfig(
                priority="high",
                notification=messaging.AndroidNotification(
                    sound="default"
                )
            ),
            # [NEW] 设置 Apple 特定的优先级
            apns=messaging.APNSConfig(
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(
                        sound="default",
                        content_available=True
                    )
                ),
                headers={"apns-priority": "10"}
            )
        )

        # 4. 发送消息
        response = messaging.send_multicast(message)
        
        print(f"FCM V1 响应: 成功 {response.success_count} 条, 失败 {response.failure_count} 条。")
        if response.failure_count > 0:
            for i, resp in enumerate(response.responses):
                if not resp.success:
                    print(f"  - 失败令牌: {device_tokens[i]}, 错误: {resp.exception}")

    
    except (Exception, psycopg2.DatabaseError) as error:
        print(f"FCM 线程中出错: {error}")
    finally:
        # 确保在新线程中关闭连接
        if cursor: cursor.close()
        if conn: conn.close()

def start_fcm_notification_thread(event_id, equipment_type, risk_type):
    """
    启动一个新线程来发送 FCM V1 通知。
    """
    thread = threading.Thread(
        target=_send_fcm_notification_v1, # [MODIFIED] 调用 V1 函数
        args=(event_id, equipment_type, risk_type)
    )
    thread.daemon = True
    thread.start()
# --- 结束 FCM 功能 ---


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat() + 'Z'
        if isinstance(obj, decimal.Decimal):
            return float(obj)
        return super(CustomJSONEncoder, self).default(obj)
app.json_encoder = CustomJSONEncoder


# --- 认证装饰器 ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({"success": False, "message": "无效的认证 Token 格式"}), 401
        
        if not token:
            return jsonify({"success": False, "message": "未提供认证 Token"}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token 已过期"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "无效的 Token"}), 401
        
        return f(current_user_id, *args, **kwargs)

    return decorated


# --- API Endpoints ---

@app.route('/', methods=['GET'])
def home():
    """根路径，返回欢迎信息"""
    return jsonify({
        "message": "安全摄像头项目 API 服务器",
        "status": "运行中",
        "streaming_base_url": IMAGE_BASE_URL
    })

# --- 认证 Endpoints ---

@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    full_name = data.get('full_name')
    role = data.get('role', 'teacher')

    if not username or not password or not email or not full_name:
        return jsonify({"success": False, "message": "缺少必需字段"}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
        if cursor.fetchone():
            return jsonify({"success": False, "message": "用户名或邮箱已存在"}), 409

        sql = """
        INSERT INTO users (username, password_hash, email, full_name, role, created_at)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id;
        """
        cursor.execute(sql, (username, password_hash, email, full_name, role, datetime.now()))
        user_id = cursor.fetchone()[0]
        conn.commit()

        return jsonify({"success": True, "message": "注册成功", "user_id": user_id}), 201

    except (Exception, psycopg2.DatabaseError) as error:
        if conn: conn.rollback()
        print(f"数据库错误 (Register): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if 'cursor' in locals() and cursor:
                cursor.close()
            conn.close()

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"success": False, "message": "缺少用户名或密码"}), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        sql = "SELECT id, username, password_hash, full_name, email, role FROM users WHERE username = %s"
        cursor.execute(sql, (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user['password_hash'], password):
            token = jwt.encode({
                'user_id': user['id'],
                'username': user['username'],
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            
            user.pop('password_hash')
            
            return jsonify({
                "success": True, 
                "message": "登录成功", 
                "token": token,
                "user": user
            })
        else:
            return jsonify({"success": False, "message": "用户名或密码错误"}), 401

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"数据库错误 (Login): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if 'cursor' in locals() and cursor:
                cursor.close()
            conn.close()

# ユーザー情報更新エンドポイント
@app.route('/api/account/update', methods=['PUT'])
@token_required
def update_account(current_user_id):
    """
    (无变化) 账号更新
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "数据未提供"}), 400

    current_username = data.get('username')
    current_email = data.get('email')
    new_username = data.get('new_username')
    new_password = data.get('new_password')

    if not current_username or not current_email:
        return jsonify({"success": False, "message": "当前用户名和邮箱是必需的"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("SELECT username, email FROM users WHERE id = %s", (current_user_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"success": False, "message": "用户未找到"}), 404

        if user['username'] != current_username or user['email'] != current_email:
            return jsonify({"success": False, "message": "当前信息不匹配"}), 401

        update_fields = []
        params = []

        if new_username and new_username != user['username']:
            cursor.execute("SELECT id FROM users WHERE username = %s AND id != %s", (new_username, current_user_id))
            if cursor.fetchone():
                return jsonify({"success": False, "message": "该用户名已被使用"}), 409
            
            update_fields.append("username = %s")
            params.append(new_username)

        if new_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            update_fields.append("password_hash = %s")
            params.append(hashed_password)

        if not update_fields:
            return jsonify({"success": False, "message": "没有要更新的新信息"}), 400

        sql_update = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s"
        params.append(current_user_id)
        
        cursor.execute(sql_update, tuple(params))
        conn.commit()

        return jsonify({"success": True, "message": "更新成功"}), 200

    except (Exception, psycopg2.DatabaseError) as error:
        if conn: conn.rollback()
        print(f"数据库错误 (Update Account): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if cursor: cursor.close()
            conn.close()


# [NEW] 注册 FCM 设备令牌的端点
@app.route('/api/account/register-device', methods=['POST'])
@token_required
def register_device(current_user_id):
    """
    接收并存储 Flutter App 发送的 FCM 设备令牌。
    """
    data = request.get_json()
    device_token = data.get('device_token')
    if not device_token:
        return jsonify({"success": False, "message": "device_token is required"}), 400
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 使用 UPSERT 逻辑:
        # 如果 device_token 冲突 (已存在), 则更新 user_id
        sql_upsert = """
        INSERT INTO user_devices (user_id, device_token, created_at)
        VALUES (%s, %s, NOW())
        ON CONFLICT (device_token) DO UPDATE SET
            user_id = EXCLUDED.user_id,
            created_at = NOW();
        """
        cursor.execute(sql_upsert, (current_user_id, device_token))
        conn.commit()
        
        print(f"设备令牌已注册/更新，用户 ID: {current_user_id}")
        return jsonify({"success": True, "message": "Device registered successfully"}), 201

    except (Exception, psycopg2.DatabaseError) as error:
        if conn: conn.rollback()
        print(f"数据库错误 (Register Device): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if cursor: cursor.close()
            conn.close()


# --- 摄像头 Endpoints ---

@app.route('/api/cameras/register', methods=['POST'])
def register_camera():
    """
    (无变化) 摄像头 UPSERT 逻辑
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "No data provided"}), 400

    # 你的脚本 [cite:`live_analysis_v2.py`] 应该发送 'camera_id_logical'
    logical_id = data.get('camera_id_logical', 1) 
    cam_name = data.get('name', 'Default Camera')
    hls_filename = data.get('hls_filename')

    if not hls_filename:
        return jsonify({"success": False, "message": "hls_filename is required"}), 400
    
    if not IMAGE_BASE_URL or "default-please-set-me" in IMAGE_BASE_URL:
         print("严重错误: IMAGE_BASE_URL 环境变量未在 Render 上正确设置。")
         return jsonify({"success": False, "message": "服务器配置错误: IMAGE_BASE_URL not set"}), 500

    stream_url = IMAGE_BASE_URL.rstrip('/') + '/' + hls_filename.lstrip('/')
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        sql_upsert = """
        INSERT INTO cameras (id, name, stream_url, status, is_active)
        VALUES (%s, %s, %s, 'online', true)
        ON CONFLICT (id) DO UPDATE SET
            name = EXCLUDED.name,
            stream_url = EXCLUDED.stream_url,
            status = 'online',
            is_active = true;
        """
        
        cursor.execute(sql_upsert, (logical_id, cam_name, stream_url))
        
        conn.commit()

        print(f"Camera {logical_id} was successfully registered/updated with URL: {stream_url}")
        return jsonify({"success": True, "message": f"Camera {logical_id} registered/updated."}), 201

    except (Exception, psycopg2.DatabaseError) as error:
        if conn: conn.rollback()
        print(f"数据库错误 (Register Camera): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if cursor: cursor.close()
            conn.close()

@app.route('/api/cameras', methods=['GET'])
@token_required
def get_cameras(current_user_id):
    """ (无变化) """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("SELECT id, name, status FROM cameras WHERE is_active = true ORDER BY name ASC")
        cameras = cursor.fetchall()
        
        return jsonify({"success": True, "data": cameras})
        
    except (Exception, psycopg2.DatabaseError) as error:
        print(f"数据库错误 (Get Cameras): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if 'cursor' in locals() and cursor:
                cursor.close()
            conn.close()

@app.route('/api/cameras/<int:camera_id>/stream', methods=['GET'])
@token_required
def get_camera_stream(current_user_id, camera_id):
    """ (无变化) """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("SELECT stream_url FROM cameras WHERE id = %s AND is_active = true", (camera_id,))
        camera = cursor.fetchone()
        
        if camera and camera['stream_url']:
            return jsonify({"success": True, "stream_url": camera['stream_url']})
        elif camera:
            return jsonify({"success": False, "message": "该摄像头未配置串流地址"}), 404
        else:
            return jsonify({"success": False, "message": "未找到指定的摄像头"}), 404
        
    except (Exception, psycopg2.DatabaseError) as error:
        print(f"数据库错误 (Get Stream): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if 'cursor' in locals() and cursor:
                cursor.close()
            conn.close()


# --- 事件 (Events) Endpoints ---

@app.route('/api/event/submit', methods=['POST'])
def add_event():
    """
    [MODIFIED] 触发 FCM 通知的逻辑已更新为 V1。
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "未提供输入数据"}), 400

    # --- 1. 解析和验证来自 AI 脚本的数据 ---
    camera_id = data.get('camera_id') # 应该是 1
    equipment_type = data.get('equipment_type')
    timestamp_str = data.get('timestamp')
    risk_type = data.get('risk_type')
    score = data.get('score')
    image_filename = data.get('image_filename') # 单个文件名
    deductions_list = data.get('deductions', [])
    
    # 你的脚本 [cite:`live_analysis_v2.py`] 只发送单个 filename 和 deductions
    images_data_list = [{
        "filename": image_filename,
        "score": score,
        "deductions": deductions_list
    }] if image_filename else []


    if not all([camera_id is not None, equipment_type, timestamp_str, risk_type, score is not None]):
        missing = [f for f in ['camera_id', 'equipment_type', 'timestamp', 'risk_type', 'score'] if data.get(f) is None]
        return jsonify({"success": False, "message": f"缺少必需字段: {', '.join(missing)}"}), 400
    
    if risk_type not in ["normal", "abnormal"]:
        return jsonify({"success": False, "message": "无效的 risk_type 值"}), 400
    
    if not images_data_list:
        return jsonify({"success": False, "message": "未提供 image_filename"}), 400

    try:
        event_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except ValueError:
        try:
             event_time = datetime.strptime(timestamp_str.split('.')[0], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return jsonify({"success": False, "message": "无效的时间戳格式"}), 400

    # --- 2. 准备新数据（用于插入或更新） ---
    new_image_count = len(images_data_list)
    request_lowest_score = score
    request_deductions_set = set(deductions_list)
    thumbnail_filename = image_filename
    
    icon_url = None
    if thumbnail_filename:
        icon_url = IMAGE_BASE_URL.rstrip('/') + '/' + thumbnail_filename.lstrip('/')

    request_deductions_json = json.dumps(list(request_deductions_set))

    # --- 3. 查找或创建事件（事务） ---
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        minute_start = event_time.replace(second=0, microsecond=0)
        minute_end = minute_start + timedelta(minutes=1)

        sql_find = """
        SELECT id, score, deductions, image_count 
        FROM events 
        WHERE equipment_type = %s 
          AND event_time >= %s 
          AND event_time < %s 
          AND risk_type = %s 
        LIMIT 1 FOR UPDATE;
        """
        cursor.execute(sql_find, (equipment_type, minute_start, minute_end, risk_type))
        existing_event = cursor.fetchone()
        
        event_id_to_use = None

        if existing_event:
            # --- 3a. 合并到现有事件 ---
            print(f"Merging into existing event_id: {existing_event['id']}")
            event_id_to_use = existing_event['id']
            
            total_image_count = existing_event['image_count'] + new_image_count
            final_score = min(existing_event['score'], request_lowest_score)
            
            existing_deductions = existing_event['deductions'] or []
            final_deductions_set = set(existing_deductions) | request_deductions_set
            final_deductions_json = json.dumps(list(final_deductions_set))

            sql_update = """
            UPDATE events 
            SET image_count = %s, score = %s, deductions = %s, status = 'new'
            WHERE id = %s;
            """
            cursor.execute(sql_update, (total_image_count, final_score, final_deductions_json, event_id_to_use))
            
        else:
            # --- 3b. 创建新事件 ---
            print("Creating new event.")
            sql_event = """
            INSERT INTO events (camera_id, equipment_type, event_time, risk_type, score, image_filename, icon_url, image_count, status, deductions)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;
            """
            cursor.execute(sql_event, (
                camera_id, equipment_type, event_time, risk_type, 
                request_lowest_score,
                thumbnail_filename,
                icon_url,
                new_image_count,
                'new', 
                request_deductions_json
            ))
            event_id_to_use = cursor.fetchone()['id']

            # [MODIFIED] 触发 V1 通知
            if risk_type == 'abnormal':
                print(f"新的 'abnormal' 事件 (ID: {event_id_to_use}) 已创建。触发 FCM V1 通知。")
                start_fcm_notification_thread(event_id_to_use, equipment_type, risk_type)

        # --- 4. 插入图片详情（对合并或新建都执行） ---
        image_url_prefix = IMAGE_BASE_URL.rstrip('/')
        image_records = []
        
        for i, img_data in enumerate(images_data_list):
            img_time = event_time + timedelta(seconds=i) 
            img_url = image_url_prefix + "/" + img_data.get("filename", f"event_{event_id_to_use}_{i}.jpg").lstrip('/')
            img_score = img_data.get("score", score)
            img_deductions = json.dumps(img_data.get("deductions", []))

            image_records.append((event_id_to_use, img_url, img_time, img_score, img_deductions))

        sql_images = """
        INSERT INTO event_images (event_id, image_url, "timestamp", score, deduction_items)
        VALUES (%s, %s, %s, %s, %s);
        """
        execute_batch(cursor, sql_images, image_records)

        # --- 5. 提交事务 ---
        conn.commit()

        return jsonify({"success": True, "message": "事件成功处理", "event_id": event_id_to_use}), 201

    except (Exception, psycopg2.DatabaseError) as error:
        if conn: conn.rollback()
        print(f"数据库错误 (Add Event): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if cursor: cursor.close()
            conn.close()

# --- 其他 Endpoints (无变化) ---

@app.route('/api/events', methods=['GET'])
@token_required
def get_events(current_user_id):
    """ (无变化) """
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        offset = (page - 1) * limit
    except ValueError:
        return jsonify({"success": False, "message": "无效的分页参数"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        base_url = IMAGE_BASE_URL.rstrip('/')
        
        sql_data = """
        SELECT 
            id, 
            camera_id, 
            equipment_type, 
            event_time, 
            risk_type, 
            score, 
            CASE 
                WHEN image_filename IS NOT NULL THEN %s || '/' || image_filename
                ELSE NULL
            END AS image_url,
            CASE 
                WHEN image_filename IS NOT NULL THEN %s || '/' || image_filename
                ELSE NULL
            END AS icon_url,
            status
        FROM events
        """
        sql_count = "SELECT COUNT(*) FROM events"
        
        conditions = ["risk_type = 'abnormal'"]
        params = [base_url, base_url] 
        
        if start_date_str:
            conditions.append("event_time >= %s")
            params.append(start_date_str)
        
        if end_date_str:
            conditions.append("event_time <= %s")
            params.append(end_date_str + " 23:59:59")
        
        if conditions:
            sql_data += " WHERE " + " AND ".join(conditions)
            sql_count += " WHERE " + " AND ".join(conditions[0:])
        
        sql_data += " ORDER BY event_time DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        cursor.execute(sql_data, tuple(params))
        events = cursor.fetchall()

        count_params = [p for p in params[2:] if p not in [limit, offset]]
        cursor.execute(sql_count, tuple(count_params))
        total_events = cursor.fetchone()['count']

        return jsonify({
            "success": True,
            "data": events,
            "pagination": {
                "currentPage": page,
                "pageSize": limit,
                "totalItems": total_events,
                "totalPages": (total_events + limit - 1) // limit if limit > 0 else 0
            }
        })

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"数据库错误 (Get Events): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if cursor: cursor.close()
            conn.close()

@app.route('/api/events/<int:event_id>', methods=['GET'])
@token_required
def get_event_detail(current_user_id, event_id):
    """ (无变化) """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        base_url = IMAGE_BASE_URL.rstrip('/')

        sql_event = """
        SELECT 
            id, 
            camera_id, 
            equipment_type AS category, 
            score, 
            event_time AS timestamp,
            CASE 
                WHEN image_filename IS NOT NULL THEN %s || '/' || image_filename
                ELSE NULL
            END AS icon_url
        FROM events
        WHERE id = %s;
        """
        cursor.execute(sql_event, (base_url, event_id))
        event_detail = cursor.fetchone()

        if not event_detail:
            return jsonify({"success": False, "message": "未找到指定 ID 的事件"}), 404

        event_detail = dict(event_detail)

        sql_images = """
        SELECT 
            id AS image_id, 
            image_url, 
            "timestamp", 
            COALESCE(score, 0) AS score,
            COALESCE(deduction_items, '[]'::jsonb) AS deduction_items
        FROM event_images
        WHERE event_id = %s
        ORDER BY "timestamp" ASC;
        """
        cursor.execute(sql_images, (event_id,))
        images = cursor.fetchall()

        processed_images = []
        for img in images:
            img_dict = dict(img)
            
            deductions = img_dict.get('deduction_items')
            if not isinstance(deductions, list):
                img_dict['deduction_items'] = []
            
            if isinstance(img_dict.get('timestamp'), datetime):
                img_dict['timestamp'] = img_dict['timestamp'].isoformat()
            
            processed_images.append(img_dict)

        event_detail['images'] = processed_images
        event_detail['image_count'] = len(processed_images)
        
        if isinstance(event_detail.get('timestamp'), datetime):
            event_detail['timestamp'] = event_detail['timestamp'].isoformat()

        return jsonify({"success": True, "data": event_detail})

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"数据库错误 (Get Event Detail): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if cursor: cursor.close()
            conn.close()

@app.route('/api/feedback', methods=['POST'])
@token_required
def add_feedback(current_user_id):
    """ (无变化) """
    data = request.get_json()
    image_id = data.get('image_id')
    reason = data.get('reason')
    notes = data.get('notes')

    if not image_id or not reason:
        return jsonify({"success": False, "message": "缺少必需字段 (image_id, reason)"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        sql = """
        INSERT INTO feedback (image_id, user_id, reason, notes, feedback_time)
        VALUES (%s, %s, %s, %s, %s) RETURNING id;
        """
        cursor.execute(sql, (
            image_id, current_user_id, reason, notes, datetime.now()
        ))
        feedback_id = cursor.fetchone()[0]
        
        cursor.execute("UPDATE event_images SET has_feedback = true WHERE id = %s", (image_id,))
        
        conn.commit()

        return jsonify({"success": True, "message": "フィードバックが正常に送信されました。", "feedback_id": feedback_id}), 201

    except (Exception, psycopg2.DatabaseError) as error:
        if conn: conn.rollback()
        print(f"数据库错误 (Feedback): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if cursor: cursor.close()
            conn.close()

@app.route('/api/reports', methods=['GET'])
@token_required
def get_periodic_report(current_user_id):
    """ (无变化) """
    report_type = request.args.get('type', 'monthly')
    
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        sql = """
        SELECT summary_data 
        FROM reports
        WHERE report_type = %s
        ORDER BY "year" DESC, "month" DESC, created_at DESC
        LIMIT 1;
        """
        cursor.execute(sql, (report_type,))
        report = cursor.fetchone()
        
        if report and report['summary_data']:
            report_data = report['summary_data']
            
            if not isinstance(report_data, dict):
                 report_data = json.loads(report_data)
                 
            report_data["success"] = True
            report_data["report_type"] = report_type
            
            return jsonify(report_data)
        else:
            return jsonify({"success": False, "message": "未找到可用的定期报告"}), 404

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"数据库错误 (Get Report): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if 'cursor' in locals() and cursor:
                cursor.close()
            conn.close()


# --- 启动服务器 ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"--- Flask API サーバーをポート {port} で起動します ---")
    print(f"Listening on 0.0.0.0:{port}")

    is_production = 'RENDER' in os.environ
    
    if is_production:
        print("--- Waitress サーバー (Production) を使用します ---")
        from waitress import serve
        serve(app, host='0.0.0.0', port=port)
    else:
        print("--- Flask 开发サーバー (Debug) を使用します ---")
        app.run(host='0.0.0.0', port=port, debug=True)