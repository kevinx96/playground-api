import os
import psycopg2
from flask import Flask, jsonify, request, g
from datetime import datetime
import json
from flask_bcrypt import Bcrypt # [FIX] 导入 Bcrypt
import jwt # [FIX] 导入 jwt
from functools import wraps # [FIX] 导入 wraps

# --- 配置 ---
app = Flask(__name__)
bcrypt = Bcrypt(app) # [FIX] 初始化 Bcrypt

# [FIX] 设置 JWT 密钥
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'my_very_secret_development_key_12345')

# [NEW] 定义您的 Ngrok 图片服务器基础 URL
# 请注意: ngrok 免费版的 URL 每次重启都会改变，您需要在这里更新它
IMAGE_BASE_URL = os.environ.get('IMAGE_BASE_URL', 'https://subdistichously-polliniferous-ileen.ngrok-free.dev')

# 从 Render 提供的环境变量获取数据库连接 URL
DATABASE_URL = os.environ.get('DATABASE_URL')
# (本地测试 URL 已注释掉)
# DATABASE_URL = "postgresql://..."


# --- 数据库辅助函数 ---
def get_db_connection():
    """建立数据库连接并将其存储在 Flask 的 g 对象中"""
    if 'db' not in g:
        if not DATABASE_URL:
            raise ValueError("DATABASE_URL environment variable not set.")
        try:
            g.db = psycopg2.connect(DATABASE_URL)
        except psycopg2.OperationalError as e:
            print(f"数据库连接失败: {e}")
            raise
    return g.db

@app.teardown_appcontext
def close_db_connection(exception):
    """在应用上下文结束时关闭数据库连接"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

# --- 认证辅助函数 ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            # 格式: "Bearer <token>"
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({"success": False, "message": "无效的认证 Token 格式"}), 401
        
        if not token:
            return jsonify({"success": False, "message": "缺少认证 Token"}), 401

        try:
            # 验证 Token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            # [FIX] 将用户信息存储在 g 中，以便后续端点使用
            g.current_user_id = data['user_id']
            g.current_user_role = data.get('role', 'user') # 假设 role 存在
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token 已过期"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Token 无效"}), 401
        
        return f(*args, **kwargs)
    return decorated

# --- API Endpoints ---

@app.route('/', methods=['GET'])
def home():
    """根路径，用于健康检查"""
    return jsonify({"message": "安全摄像头项目 API 服务器", "status": "运行中"})

# --- 1. 认证 (Auth) ---
@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.get_json()
    if not data or not all(k in data for k in ('username', 'password', 'email', 'full_name')):
        return jsonify({"success": False, "message": "缺少必要的注册信息"}), 400

    username = data['username']
    email = data['email']
    full_name = data['full_name']
    
    # [FIX] 使用 bcrypt 哈希密码
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    # [FIX] 默认角色为 'user'
    role = data.get('role', 'user') 
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 检查用户名或邮箱是否已存在
        cursor.execute("SELECT user_id FROM users WHERE username = %s OR email = %s", (username, email))
        if cursor.fetchone():
            return jsonify({"success": False, "message": "用户名或邮箱已存在"}), 409

        # 插入新用户
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, email, full_name, role)
            VALUES (%s, %s, %s, %s, %s) RETURNING user_id;
            """,
            (username, hashed_password, email, full_name, role)
        )
        user_id = cursor.fetchone()[0]
        conn.commit()
        
        return jsonify({"success": True, "message": "注册成功", "user_id": user_id}), 201

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"数据库错误 (Register): {error}")
        if conn:
            conn.rollback() # 出错时回滚
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"success": False, "message": "缺少用户名或密码"}), 400

    username = data['username']
    password = data['password']
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        # [FIX] 查询时返回所有需要的用户信息
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, username, password_hash, email, full_name, role, created_at FROM users WHERE username = %s", (username,))
        user_row = cursor.fetchone()

        if user_row:
            user = {
                "user_id": user_row[0],
                "username": user_row[1],
                "password_hash": user_row[2],
                "email": user_row[3],
                "full_name": user_row[4],
                "role": user_row[5],
                "created_at": user_row[6].isoformat() # 转换为 ISO 格式字符串
            }
            
            # [FIX] 验证哈希密码
            if bcrypt.check_password_hash(user['password_hash'], password):
                # 密码正确, 生成 JWT Token
                token = jwt.encode({
                    'user_id': user['user_id'],
                    'role': user['role'],
                    'exp': datetime.utcnow() + datetime.timedelta(days=1) # Token 有效期 1 天
                }, app.config['SECRET_KEY'], algorithm="HS256")

                # 从返回的用户信息中移除密码哈希
                del user['password_hash']
                
                return jsonify({
                    "success": True, 
                    "message": "登录成功", 
                    "token": token,
                    "user": user # [FIX] 返回用户信息
                })
        
        # 用户名不存在或密码错误
        return jsonify({"success": False, "message": "用户名或密码错误"}), 401

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"数据库错误 (Login): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if cursor:
            cursor.close()

# --- 2. 摄像头 (Cameras) ---
@app.route('/api/cameras', methods=['GET'])
@token_required
def get_cameras():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # [FIX] 从数据库查询摄像头列表 (假设表为 cameras)
        cursor.execute("SELECT camera_id, name, rtsp_url, status FROM cameras ORDER BY name")
        cameras = cursor.fetchall()
        
        camera_list = [
            {
                "id": row[0],
                "name": row[1],
                "rtsp_url": row[2], # 实际流地址，App 可能需要
                "status": row[3]  # e.g., 'online', 'offline' (由 AI 脚本更新)
            } for row in cameras
        ]
        
        return jsonify({"success": True, "data": camera_list})

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"数据库错误 (Get Cameras): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if cursor:
            cursor.close()

# --- 3. 事件 (Events) ---
@app.route('/api/events', methods=['GET'])
@token_required
def get_events():
    # ... (分页和日期筛选逻辑) ...
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    start_date = request.args.get('start_date', None, type=str)
    end_date = request.args.get('end_date', None, type=str)
    offset = (page - 1) * limit
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query_params = []
        where_clauses = []
        
        if start_date:
            where_clauses.append("e.event_time >= %s")
            query_params.append(start_date)
        
        if end_date:
            # 使结束日期包含当天
            where_clauses.append("e.event_time <= %s::date + interval '1 day' - interval '1 second'")
            query_params.append(end_date)
            
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        
        # --- 获取总数 ---
        cursor.execute(f"SELECT COUNT(*) FROM events e {where_sql}", tuple(query_params))
        total_records = cursor.fetchone()[0]
        total_pages = (total_records + limit - 1) // limit

        # --- 获取分页数据 ---
        # [FIX] 确保查询了缩略图文件名 (image_filename)
        query = f"""
            SELECT 
                e.event_id, e.camera_id, e.equipment_type, e.score, 
                e.event_time, e.status, e.image_filename
            FROM events e
            {where_sql}
            ORDER BY e.event_time DESC
            LIMIT %s OFFSET %s;
        """
        cursor.execute(query, tuple(query_params + [limit, offset]))
        events = cursor.fetchall()
        
        # [MODIFIED] 使用 IMAGE_BASE_URL 构建完整的 URL
        base_url = IMAGE_BASE_URL.rstrip('/')
        
        event_list = [
            {
                "id": row[0],
                "camera_id": row[1],
                "equipment_type": row[2],
                "score": row[3],
                "event_time": row[4].isoformat(),
                "status": row[5],
                # [MODIFIED] 构造完整的缩略图 URL
                "thumbnail_url": f"{base_url}/static/thumbnails/{row[6]}" if row[6] else None 
            } for row in events
        ]
        
        pagination_info = {
            "current_page": page,
            "total_pages": total_pages,
            "total_records": total_records,
            "limit": limit
        }
        
        return jsonify({"success": True, "pagination": pagination_info, "data": event_list})

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"数据库错误 (Get Events): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/events/<int:event_id>', methods=['GET'])
@token_required
def get_event_detail(event_id):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. 获取主事件信息
        cursor.execute(
            """
            SELECT e.event_id, e.camera_id, e.equipment_type, e.score, e.event_time, COUNT(ei.image_id) as image_count
            FROM events e
            LEFT JOIN event_images ei ON e.event_id = ei.event_id
            WHERE e.event_id = %s
            GROUP BY e.event_id;
            """, (event_id,)
        )
        event_row = cursor.fetchone()
        
        if not event_row:
            return jsonify({"success": False, "message": "未找到指定 ID 的事件"}), 404

        # 2. 获取关联的图片信息
        cursor.execute(
            """
            SELECT image_id, image_filename, event_time, score, deduction_items
            FROM event_images
            WHERE event_id = %s
            ORDER BY event_time;
            """, (event_id,)
        )
        images = cursor.fetchall()
        
        # [MODIFIED] 使用 IMAGE_BASE_URL 构建完整的 URL
        base_url = IMAGE_BASE_URL.rstrip('/')
        
        image_list = [
            {
                "image_id": img_row[0],
                # [MODIFIED] 构造完整的图片 URL
                "image_url": f"{base_url}/static/images/{img_row[1]}",
                "timestamp": img_row[2].isoformat(),
                "score": img_row[3],
                "deduction_items": img_row[4] if img_row[4] else [] # 处理 null
            } for img_row in images
        ]
        
        event_detail = {
            "id": event_row[0],
            "camera_id": event_row[1],
            "category": event_row[2], # App 期望 'category'
            "score": event_row[3],
            "timestamp": event_row[4].isoformat(),
            "image_count": event_row[5],
            "images": image_list # 嵌入图片列表
        }
        
        return jsonify({"success": True, "data": event_detail})

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"数据库错误 (Get Event Detail): {error}")
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if cursor:
            cursor.close()

# --- 4. 反馈 (Feedback) ---
@app.route('/api/feedback', methods=['POST'])
@token_required
def submit_feedback():
    data = request.get_json()
    if not data or not all(k in data for k in ('event_id', 'image_id', 'reason', 'notes')):
        return jsonify({"success": False, "message": "缺少必要信息"}), 400
    
    # [FIX] 从 g 对象获取 user_id
    user_id = g.current_user_id
    event_id = data['event_id']
    image_id = data['image_id']
    reason = data['reason'] # [FIX] 接收 reason
    notes = data['notes']
    
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """
            INSERT INTO feedback (user_id, event_id, image_id, reason, notes)
            VALUES (%s, %s, %s, %s, %s);
            """,
            (user_id, event_id, image_id, reason, notes)
        )
        conn.commit()
        
        return jsonify({"success": True, "message": "フィードバックを受け付けました"}), 201

    except (Exception, psycopg2.DatabaseError) as error:
        print(f"数据库错误 (Feedback): {error}")
        if conn:
            conn.rollback()
        return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
    finally:
        if cursor:
            cursor.close()

# --- 5. 定期报告 (Reports) ---
@app.route('/api/reports', methods=['GET'])
@token_required
def get_reports():
    # ... (这是一个复杂的端点，需要数据库聚合查询) ...
    # [FIX] 提供一个符合 App 期望的模拟 JSON 结构
    
    # 模拟从数据库获取的数据
    f1_score_data = [
        {'date': '2025-07-01', 'model_name': 'model-prototype', 'f1_score': 0.7632},
        {'date': '2025-08-01', 'model_name': 'model-1', 'f1_score': 0.7987},
        {'date': '2025-09-01', 'model_name': 'model-2', 'f1_score': 0.8012}
    ]
    
    category_data = [
        {'category': 'slide', 'count': 6, 'percentage': 40.0},
        {'category': 'swing', 'count': 5, 'percentage': 33.3},
        {'category': 'climbing', 'count': 3, 'percentage': 20.0},
        {'category': 'other', 'count': 1, 'percentage': 6.7}
    ]
    
    time_data = [
        {'hour_range': '12-14', 'count': 4},
        {'hour_range': '14-16', 'count': 4},
        {'hour_range': '16-18', 'count': 7}
    ]
    
    # 组装 App 期望的 JSON
    report_json = {
        "success": True,
        "report_type": "monthly",
        "current_model": "Model-2",
        "total_incidents_this_month": 15,
        "model_performance": {
            "precision_data": [60.0, 90.0, 70.0, 85.0],
            "recall_data": [60.0, 40.0, 50.0, 70.0],
            "f1_score_data": [60.0, 56.25, 58.33, 76.67]
        },
        "incident_stats": {
            "category_distribution": category_data,
            "time_distribution": time_data
        },
        "model_comparison": f1_score_data
    }
    
    return jsonify(report_json)

# --- 6. 事件接收 (AI 脚本调用) ---
@app.route('/api/event/submit', methods=['POST'])
def add_event():
    # [FIX] 这是一个内部端点, 假设它不需要 @token_required
    # 或者需要一个 API 密钥 (这里简化处理)
    
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "No data provided"}), 400
    
    print(f"[Event Received] Data: {data}")

    try:
        # --- 从 AI 脚本获取数据 ---
        camera_id = data.get('camera_id', 0)
        equipment_type = data.get('equipment_type', 'unknown')
        event_time_str = data.get('timestamp')
        risk_type = data.get('risk_type', 'unknown')
        score = data.get('score', 100)
        
        # 假设 AI 脚本发送的是 ISO 格式的字符串
        event_time = datetime.fromisoformat(event_time_str) if event_time_str else datetime.now()
        
        # [FIX] 接收图片文件名列表 (来自 AI 脚本)
        image_filenames = data.get('image_filenames', []) # 假设 AI 发送 'image_filenames': ['img1.jpg', 'img2.jpg', ...]
        deduction_items = data.get('deductions', []) # 扣分项
        
        image_filename = image_filenames[0] if image_filenames else None

        conn = None
        cursor = None
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 1. 插入主事件 (events)
            cursor.execute(
                """
                INSERT INTO events (camera_id, equipment_type, risk_type, score, event_time, status, image_filename)
                VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING event_id;
                """,
                (camera_id, equipment_type, risk_type, score, event_time, 'pending', image_filename)
            )
            event_id = cursor.fetchone()[0]
            
            # 2. 批量插入关联图片 (event_images)
            if image_filenames:
                image_records = []
                # AI 脚本目前只发送一个 score 和 deductions, 我们将其应用到所有图片上 (或只应用到第一张)
                # 为了简单起见，我们只将它们存储在第一张图片上
                
                for i, filename in enumerate(image_filenames):
                    # 假设 score 和 deductions 只与第一张图关联
                    img_score = score if i == 0 else None
                    img_deductions = deduction_items if i == 0 else None
                    
                    # [FIX] 确保 event_time, score, deduction_items 匹配数据库
                    image_records.append((
                        event_id, 
                        filename, 
                        event_time, # 假设所有图片时间戳相同
                        img_score, 
                        json.dumps(img_deductions) if img_deductions else None # [FIX] 转换为 JSON 字符串
                    ))
                
                # [FIX] 修正 INSERT 语句的列名
                cursor.executemany(
                    """
                    INSERT INTO event_images (event_id, image_filename, event_time, score, deduction_items)
                    VALUES (%s, %s, %s, %s, %s);
                    """,
                    image_records
                )
            
            conn.commit()
            print(f"[Event Saved] Event ID: {event_id} 已成功存入数据库。")
            
            # TODO: 在这里触发 Web Socket 或推送通知
            
            return jsonify({"success": True, "message": "事件已接收", "event_id": event_id}), 201

        except (Exception, psycopg2.DatabaseError) as error:
            print(f"数据库错误 (Add Event): {error}")
            if conn:
                conn.rollback()
            return jsonify({"success": False, "message": f"数据库错误: {str(error)}"}), 500
        finally:
            if cursor:
                cursor.close()

    except Exception as e:
        print(f"数据处理错误 (Add Event): {e}")
        return jsonify({"success": False, "message": f"无效的请求数据: {str(e)}"}), 400


# --- 启动服务器 ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"--- Flask API サーバーをポート {port} で起動します ---")
    
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

