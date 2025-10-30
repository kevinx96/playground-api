import os
import psycopg2
import json
from flask import Flask, jsonify, request
from datetime import datetime, timedelta # [MODIFIED] 导入 timedelta
from flask_bcrypt import Bcrypt # [SECURITY] 导入 Bcrypt
from psycopg2.extras import RealDictCursor # [IMPROVEMENT] 导入 RealDictCursor
import decimal # [FIX] 用于处理 Decimal 类型
import jwt # [SECURITY] 导入 JWT 用于 Token
from functools import wraps # [SECURITY] 导入 wraps 用于装饰器

# --- 配置 ---
app = Flask(__name__)

# [SECURITY] 设置一个安全的密钥，用于 JWT 签名。请在环境变量中替换它！
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'my_dev_secret_key_please_change_me')

# 从 Render 提供的环境变量获取数据库连接 URL
DATABASE_URL = os.environ.get('DATABASE_URL')
# DATABASE_URL = "postgresql://..." # 本地测试时取消注释
IMAGE_BASE_URL = os.environ.get('IMAGE_BASE_URL', 'https://subdistichously-polliniferous-ileen.ngrok-free.dev')
bcrypt = Bcrypt(app) # [SECURITY] 初始化 Bcrypt

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

# [FIX] 自定义 JSON 编码器，用于处理 datetime 和 decimal
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat() + 'Z' # 转换为 ISO 格式字符串
        if isinstance(obj, decimal.Decimal):
            return float(obj) # 转换为 float
        return super(CustomJSONEncoder, self).default(obj)
app.json_encoder = CustomJSONEncoder


# --- 认证装饰器 ---
def token_required(f):
    """
    [SECURITY] 检查请求 Header 中是否包含有效 Token 的装饰器
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                # 格式应为 "Bearer <token>"
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({"success": False, "message": "无效的认证 Token 格式"}), 401
        
        if not token:
            return jsonify({"success": False, "message": "未提供认证 Token"}), 401

        try:
            # 验证 JWT Token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token 已过期"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "无效的 Token"}), 401
        
        # 将用户信息传递给被装饰的函数
        return f(current_user_id, *args, **kwargs)

    return decorated


# --- API Endpoints ---

@app.route('/', methods=['GET'])
def home():
    """根路径，返回欢迎信息"""
    return jsonify({
        "message": "安全摄像头项目 API 服务器",
        "status": "运行中"
    })

# --- 认证 Endpoints ---

@app.route('/api/auth/register', methods=['POST'])
def register_user():
    """
    [SECURITY UPGRADE] 使用 Bcrypt 哈希密码的用户注册
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    full_name = data.get('full_name')
    role = data.get('role', 'teacher') # 默认角色

    if not username or not password or not email or not full_name:
        return jsonify({"success": False, "message": "缺少必需字段"}), 400

    # [SECURITY] 生成密码哈希值
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
    """
    [SECURITY UPGRADE] 使用 Bcrypt 校验密码并返回 JWT Token
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"success": False, "message": "缺少用户名或密码"}), 400

    conn = None
    try:
        conn = get_db_connection()
        # [IMPROVEMENT] 使用 RealDictCursor 以字典形式返回结果
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        sql = "SELECT id, username, password_hash, full_name, email, role FROM users WHERE username = %s"
        cursor.execute(sql, (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user['password_hash'], password):
            # 密码正确
            # [SECURITY] 生成 JWT Token
            token = jwt.encode({
                'user_id': user['id'],
                'username': user['username'],
                'exp': datetime.utcnow() + timedelta(hours=24) # 24小时后过期
            }, app.config['SECRET_KEY'], algorithm="HS256")
            
            # 从返回的 user 字典中移除密码哈希
            user.pop('password_hash')
            
            return jsonify({
                "success": True, 
                "message": "登录成功", 
                "token": token,
                "user": user # 返回用户信息
            })
        else:
            # 用户名或密码错误
            return jsonify({"success": False, "message": "用户名或密码错误"}), 401

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"数据库错误 (Login): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if 'cursor' in locals() and cursor:
                cursor.close()
            conn.close()

# --- 摄像头 Endpoints ---

@app.route('/api/cameras', methods=['GET'])
@token_required
def get_cameras(current_user_id):
    """
    [MODIFIED] 获取摄像头列表 (已移除占位逻辑)
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # [MODIFIED] 真实的数据库查询。
        # 假设 `cameras` 表中已添加 `status` 列
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
    """
    [NEW ENDPOINT] 获取单个摄像头的视频流 URL (根据计划书)
    """
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

@app.route('/api/events', methods=['POST'])
def add_event():
    """
    接收来自本地分析脚本的危险事件数据 (来自用户提供的 api.py)
    """
    # TODO: 考虑为这个端点添加一个 API 密钥或 IP 白名单，防止公网滥用
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "未提供输入数据"}), 400

    # --- 从 AI 脚本获取数据 ---
    camera_id = data.get('camera_id', 0)
    equipment_type = data.get('equipment_type')
    timestamp_str = data.get('timestamp')
    risk_type = data.get('risk_type') # "abnormal" 或 "normal"
    score = data.get('score') # 整个事件的（例如最低）分数
    image_filename = data.get('image_filename') # 缩略图
    deductions_list = data.get('deductions', []) # 整个事件的扣分项
    
    # [IMPORTANT] AI 脚本必须提供每张图片的详细信息
    # 这是支持App详情页功能的关键
    # 计划书 1.1 节提到了 "5枚"，但JSON示例中没有
    # 我们假设 AI 脚本会发送一个 `images_data` 列表
    # 格式: [ { "filename": "img_01.jpg", "score": 40, "deductions": ["..."] }, ... ]
    images_data_list = data.get('images_data', [])
    
    # 兼容旧格式：如果只提供了 image_filename
    if image_filename and not images_data_list:
        images_data_list = [{
            "filename": image_filename,
            "score": score,
            "deductions": deductions_list
        }]

    if not all([equipment_type, timestamp_str, risk_type, score is not None]):
        missing = [f for f in ['equipment_type', 'timestamp', 'risk_type', 'score'] if not data.get(f)]
        return jsonify({"success": False, "message": f"缺少必需字段: {', '.join(missing)}"}), 400
    
    if risk_type not in ["normal", "abnormal"]:
        return jsonify({"success": False, "message": "无效的 risk_type 值"}), 400

    try:
        event_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except ValueError:
        try:
             event_time = datetime.strptime(timestamp_str.split('.')[0], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return jsonify({"success": False, "message": "无效的时间戳格式"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        deductions_json = json.dumps(deductions_list)
        image_count = len(images_data_list)
        
        # 步骤 1: 插入主 event 记录
        sql_event = """
        INSERT INTO events (camera_id, equipment_type, event_time, risk_type, score, image_filename, image_count, status, deductions)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;
        """
        cursor.execute(sql_event, (
            camera_id, equipment_type, event_time, risk_type, score,
            image_filename, image_count, 'new', deductions_json
        ))
        event_id = cursor.fetchone()[0]
        
        # 步骤 2: 插入关联的图片 (根据计划书的 `event_images` 表)
        if image_count > 0:
            # TODO: 这里的 `image_url_prefix` 应根据您的文件存储策略修改
            # [MODIFIED] 使用在文件顶部定义的 IMAGE_BASE_URL
            image_url_prefix = IMAGE_BASE_URL
            
            image_records = []
            for i, img_data in enumerate(images_data_list):
                img_time = event_time + timedelta(seconds=i - int(image_count / 2)) # 模拟时间
                img_url = image_url_prefix +"/"+ img_data.get("filename", f"event_{event_id}_{i}.jpg")
                img_score = img_data.get("score", score) # 使用单张图片分数，否则回退到事件分数
                img_deductions = json.dumps(img_data.get("deductions", [])) # 使用单张图片扣分项

                # 假设 event_images 表结构 (event_id, image_url, timestamp, score, deduction_items)
                # [MODIFIED] 插入我们建议的新字段 score 和 deductions
                image_records.append((event_id, img_url, img_time, img_score, img_deductions))

            sql_images = """
            INSERT INTO event_images (event_id, image_url, "timestamp", score, deduction_items)
            VALUES (%s, %s, %s, %s, %s);
            """
            # [IMPROVEMENT] 使用 executemany 进行批量插入
            from psycopg2.extras import execute_batch
            execute_batch(cursor, sql_images, image_records)

        conn.commit()

        if risk_type == "abnormal":
            print(f"事件 {event_id} ({equipment_type}) 已记录为 abnormal，可以触发警报。")
        else:
            print(f"事件 {event_id} ({equipment_type}) 已记录为 normal。")

        return jsonify({"success": True, "message": "事件成功添加", "event_id": event_id}), 201

    except (Exception, psycopg2.DatabaseError) as error:
        if conn: conn.rollback()
        print(f"数据库错误 (Add Event): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if cursor: cursor.close()
            conn.close()

@app.route('/api/events', methods=['GET'])
@token_required
def get_events(current_user_id):
    """
    [MODIFIED] 获取事件历史记录，增加了日期筛选功能 (已连接DB)
    """
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        start_date_str = request.args.get('start_date') # YYYY-MM-DD
        end_date_str = request.args.get('end_date') # YYYY-MM-DD
        offset = (page - 1) * limit
    except ValueError:
        return jsonify({"success": False, "message": "无效的分页参数"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor) # 使用 RealDictCursor

        # 构建基础查询
        # [MODIFIED] 字段名 `image_filename` 映射为 `thumbnail_url` 以匹配App需求
        sql_data = """
        SELECT id, camera_id, equipment_type, event_time, risk_type, score, image_filename AS thumbnail_url, status
        FROM events
        """
        sql_count = "SELECT COUNT(*) FROM events"
        
        # 添加筛选条件
        conditions = ["risk_type = 'abnormal'"] # 默认只显示 "abnormal"
        params = []
        
        if start_date_str:
            conditions.append("event_time >= %s")
            params.append(start_date_str)
        
        if end_date_str:
            # 包含当天，所以查询到 23:59:59
            conditions.append("event_time <= %s")
            params.append(end_date_str + " 23:59:59")
        
        if conditions:
            sql_data += " WHERE " + " AND ".join(conditions)
            sql_count += " WHERE " + " AND ".join(conditions)
        
        # 添加排序和分页
        sql_data += " ORDER BY event_time DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        # 执行数据查询
        cursor.execute(sql_data, tuple(params))
        events = cursor.fetchall()

        # 执行总数查询 (移除分页参数)
        cursor.execute(sql_count, tuple(params[:-2])) # 移除 limit 和 offset
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
    """
    [UPGRADED ENDPOINT] 获取单个事件的详细信息，并包含所有关联的图片 (已连接DB)
    """
    print(f"🔵 API: Fetching event detail for event_id: {event_id}")
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # 步骤 1: 获取主事件信息
        sql_event = """
        SELECT 
            id, 
            camera_id, 
            equipment_type AS category, 
            score, 
            event_time AS timestamp
        FROM events
        WHERE id = %s;
        """
        cursor.execute(sql_event, (event_id,))
        event_detail = cursor.fetchone()

        print(f"📄 Event detail: {event_detail}")

        if not event_detail:
            print(f"❌ Event {event_id} not found")
            return jsonify({"success": False, "message": "未找到指定 ID 的事件"}), 404

        # 转换为普通字典
        event_detail = dict(event_detail)

        # 步骤 2: 获取所有关联的图片信息
        # [FIX] 修改 COALESCE 的类型为 jsonb
        sql_images = """
        SELECT 
            id AS image_id, 
            image_url, 
            timestamp, 
            COALESCE(score, 0) AS score,
            COALESCE(deduction_items, '[]'::jsonb) AS deduction_items
        FROM event_images
        WHERE event_id = %s
        ORDER BY timestamp ASC;
        """
        cursor.execute(sql_images, (event_id,))
        images = cursor.fetchall()

        print(f"📸 Found {len(images)} images")

        # 转换图片数据
        processed_images = []
        for img in images:
            img_dict = dict(img)
            
            # JSONB 类型会被 psycopg2 自动转换为 Python list/dict
            # 但还是做一下安全检查
            deductions = img_dict.get('deduction_items')
            if not isinstance(deductions, list):
                img_dict['deduction_items'] = []
            
            # 确保 timestamp 是 ISO 格式字符串
            if isinstance(img_dict.get('timestamp'), datetime):
                img_dict['timestamp'] = img_dict['timestamp'].isoformat()
            
            processed_images.append(img_dict)

        # 步骤 3: 组合响应
        event_detail['images'] = processed_images
        event_detail['image_count'] = len(processed_images)
        
        # 确保主 timestamp 也是 ISO 格式
        if isinstance(event_detail.get('timestamp'), datetime):
            event_detail['timestamp'] = event_detail['timestamp'].isoformat()

        print(f"✅ Returning {len(processed_images)} images")

        return jsonify({"success": True, "data": event_detail})

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"❌ Database error: {error}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if conn:
            if cursor: cursor.close()
            conn.close()

# --- 反馈 (Feedback) Endpoints ---

@app.route('/api/feedback', methods=['POST'])
@token_required
def add_feedback(current_user_id):
    """
    [NEW ENDPOINT] 接收来自 App 的误检测报告 (已连接DB)
    """
    data = request.get_json()
    event_id = data.get('event_id')
    image_id = data.get('image_id')
    reason = data.get('reason') # [NEW] 从 App 接收
    notes = data.get('notes')

    if not event_id or not image_id or not reason:
        return jsonify({"success": False, "message": "缺少必需字段 (event_id, image_id, reason)"}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # [MODIFIED] 假设 feedback 表已添加 `reason` 列
        sql = """
        INSERT INTO feedback (event_id, image_id, user_id, reason, notes, feedback_time)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id;
        """
        cursor.execute(sql, (
            event_id, image_id, current_user_id, reason, notes, datetime.now()
        ))
        feedback_id = cursor.fetchone()[0]
        
        # (可选) 更新 event_images 表中的状态
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

# --- 定期报告 (Reports) Endpoints ---

@app.route('/api/reports', methods=['GET'])
@token_required
def get_periodic_report(current_user_id):
    """
    [MODIFIED] 获取定期报告数据 (已连接DB)
    """
    report_type = request.args.get('type', 'monthly')
    
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # [MODIFIED] 真实的数据库查询
        # 假设 `reports` 表由一个单独的脚本预先计算并填充
        # 我们只获取 App 需要的最新一份报告
        # `summary_data` 列必须存储 `api_specification.md` 中定义的完整 JSON 结构
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
            # `summary_data` 已经是 JSON (或 psycopg2 自动转换的 dict)
            # 我们需要确保它符合App所需的完整结构
            report_data = report['summary_data']
            
            # 确保 `success` 和 `report_type` 字段存在
            if not isinstance(report_data, dict):
                 report_data = json.loads(report_data)
                 
            report_data["success"] = True
            report_data["report_type"] = report_type
            
            return jsonify(report_data)
        else:
            # 如果数据库中没有，返回一个空的或默认的结构
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

    
    # 检查是否在 Render.com 环境中 (Render 会设置 RENDER 环境变量)
    is_production = 'RENDER' in os.environ
    
    if is_production:
        print("--- Waitress サーバー (Production) を使用します ---")
        from waitress import serve
        serve(app, host='0.0.0.0', port=port)
    else:
        print("--- Flask 開発サーバー (Debug) を使用します ---")
        # 本地开发时，debug=True 可以提供热重载和更详细的错误
        app.run(host='0.0.0.0', port=port, debug=True)