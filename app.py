from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
from flask_wtf.csrf import CSRFProtect
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "super-secret-key"
DB_NAME = "market.db"

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False

app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = "super-secret-key"
socketio = SocketIO(app)  # 기존 app.run() 대신 socketio.run() 필요

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        # users 테이블
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                is_blocked INTEGER DEFAULT 0,
                balance INTEGER DEFAULT 10000,
                bio TEXT
            )
        ''')
        # products 테이블
        c.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                price INTEGER,
                seller_id INTEGER,
                is_blocked INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                buyer_id INTEGER
            )
        ''')
        # messages 테이블
        c.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                receiver_id INTEGER,
                message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # transfers 테이블
        c.execute('''
            CREATE TABLE IF NOT EXISTS transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                receiver_id INTEGER,
                product_id INTEGER,
                amount INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # ✅ 신고 테이블 (오류 수정됨)
        c.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL CHECK (type IN ('user', 'product')),
                target_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                reporter_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

@app.route("/", methods=["GET", "POST"])
def index():
    keyword = ""
    if request.method == "POST":
        keyword = request.form.get("keyword", "")
    else:
        keyword = request.args.get("keyword", "")

    query = '''
        SELECT id, name, description, price, seller_id, is_blocked, created_at, buyer_id
        FROM products WHERE is_blocked = 0
    '''
    params = []
    if keyword:
        query += " AND name LIKE ?"
        params.append(f"%{keyword}%")
    query += " ORDER BY created_at DESC"

    with sqlite3.connect(DB_NAME) as conn:
        products = conn.execute(query, params).fetchall()

    return render_template("index.html", products=products, keyword=keyword)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        with sqlite3.connect(DB_NAME) as conn:
            try:
                conn.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                             (username, email, password))
                conn.commit()
                flash("회원가입 성공!", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("이미 존재하는 사용자입니다.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        with sqlite3.connect(DB_NAME) as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user and check_password_hash(user[3], password):
                session["user_id"] = user[0]
                session["username"] = user[1]
                session["is_admin"] = user[4]
                flash("로그인 성공!", "success")
                return redirect(url_for("index"))
            else:
                flash("로그인 실패", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("로그아웃되었습니다.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products WHERE seller_id = ?", (session["user_id"],))
        products = cursor.fetchall()

    return render_template("dashboard.html", products=products)

@app.route("/product/new", methods=["GET", "POST"])
def new_product():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        name = request.form["name"]
        description = request.form["description"]
        price = int(request.form["price"])
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("INSERT INTO products (name, description, price, seller_id) VALUES (?, ?, ?, ?)",
                         (name, description, price, session["user_id"]))
            conn.commit()
            flash("상품 등록 완료!", "success")
            return redirect(url_for("dashboard"))
    return render_template("new_product.html")

@app.route("/product/<int:product_id>")
def view_product(product_id):
    with sqlite3.connect(DB_NAME) as conn:
        product = conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    return render_template("view_product.html", product=product)

@app.route("/product/edit/<int:product_id>", methods=["GET", "POST"])
def edit_product(product_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        product = cursor.execute("SELECT * FROM products WHERE id = ? AND seller_id = ?", (product_id, session["user_id"])).fetchone()

        if not product:
            flash("수정할 권한이 없습니다.", "danger")
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            name = request.form["name"]
            description = request.form["description"]
            price = int(request.form["price"])
            cursor.execute("""
                UPDATE products SET name = ?, description = ?, price = ?
                WHERE id = ? AND seller_id = ?
            """, (name, description, price, product_id, session["user_id"]))
            conn.commit()
            flash("상품이 수정되었습니다.", "success")
            return redirect(url_for("dashboard"))

    return render_template("edit_product.html", product=product)

@app.route("/product/delete/<int:product_id>")
def delete_product(product_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # 본인 상품인지 확인
        product = cursor.execute("SELECT * FROM products WHERE id = ? AND seller_id = ?", (product_id, session["user_id"])).fetchone()

        if not product:
            flash("삭제할 권한이 없습니다.", "danger")
        else:
            cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
            conn.commit()
            flash("상품이 삭제되었습니다.", "info")

    return redirect(url_for("dashboard"))

@app.route("/chat/<int:user_id>", methods=["GET", "POST"])
def chat(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    my_id = session["user_id"]
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        if request.method == "POST":
            msg = request.form["message"]
            cursor.execute("INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)",
                           (my_id, user_id, msg))
            conn.commit()
            return redirect(url_for("chat", user_id=user_id))

        cursor.execute("""
            SELECT sender_id, message, created_at FROM messages
            WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
            ORDER BY created_at
        """, (my_id, user_id, user_id, my_id))
        messages = cursor.fetchall()

        target_username = cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()[0]

    return render_template("chat.html", messages=messages, user_id=my_id, target_username=target_username)

@app.route("/chat_list")
def chat_list():
    if "user_id" not in session:
        return redirect(url_for("login"))
    uid = session["user_id"]
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT
                CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as partner
            FROM messages WHERE sender_id = ? OR receiver_id = ?
        """, (uid, uid, uid))
        ids = cursor.fetchall()
        chat_users = []
        for (pid,) in ids:
            name = cursor.execute("SELECT username FROM users WHERE id = ?", (pid,)).fetchone()
            if name:
                chat_users.append((pid, name[0]))
    return render_template("chat_list.html", chat_users=chat_users)

@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if "user_id" not in session:
        return redirect(url_for("login"))
    uid = session["user_id"]
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT balance FROM users WHERE id = ?", (uid,))
        balance = cursor.fetchone()[0]

        if request.method == "POST":
            receiver_id = int(request.form["receiver_id"])
            amount = int(request.form["amount"])
            product_id = int(request.form["product_id"])
            if balance < amount:
                flash("잔액 부족", "danger")
                return redirect(url_for("transfer"))
            cursor.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, uid))
            cursor.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, receiver_id))
            cursor.execute("UPDATE products SET buyer_id = ? WHERE id = ?", (uid, product_id))
            cursor.execute("INSERT INTO transfers (sender_id, receiver_id, product_id, amount) VALUES (?, ?, ?, ?)",
                           (uid, receiver_id, product_id, amount))
            conn.commit()
            flash("송금 완료", "success")
            return redirect(url_for("dashboard"))

        users = cursor.execute("SELECT id, username FROM users WHERE id != ?", (uid,)).fetchall()
        products = cursor.execute("""
            SELECT id, name, price FROM products
            WHERE seller_id != ? AND buyer_id IS NULL AND is_blocked = 0
        """, (uid,)).fetchall()
    return render_template("transfer.html", users=users, products=products, balance=balance)

@app.route("/admin")
def admin():
    if not session.get("is_admin"):
        flash("접근 권한이 없습니다.", "danger")
        return redirect(url_for("index"))

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        users = cursor.execute("SELECT id, username, email, is_blocked FROM users WHERE is_admin = 0").fetchall()
        products = cursor.execute("SELECT id, name, is_blocked FROM products").fetchall()

        # 관리자용 통계 및 최근 활동 로그
        stats = {
            "total_users": cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "total_products": cursor.execute("SELECT COUNT(*) FROM products").fetchone()[0],
            "sold_products": cursor.execute("SELECT COUNT(*) FROM products WHERE buyer_id IS NOT NULL").fetchone()[0],
            "latest_messages": cursor.execute("""
                SELECT u1.username, u2.username, m.message, m.created_at
                FROM messages m
                JOIN users u1 ON m.sender_id = u1.id
                JOIN users u2 ON m.receiver_id = u2.id
                ORDER BY m.created_at DESC LIMIT 5
            """).fetchall(),
            "latest_transfers": cursor.execute("""
                SELECT u1.username, u2.username, p.name, t.amount, t.created_at
                FROM transfers t
                JOIN users u1 ON t.sender_id = u1.id
                JOIN users u2 ON t.receiver_id = u2.id
                LEFT JOIN products p ON t.product_id = p.id
                ORDER BY t.created_at DESC LIMIT 5
            """).fetchall()
        }

    return render_template("admin.html", users=users, products=products, stats=stats)

@app.route("/report", methods=["GET", "POST"])
def report():
    if "user_id" not in session:
        flash("로그인이 필요합니다.", "warning")
        return redirect(url_for("login"))

    report_type = request.args.get("type")
    target_id = request.args.get("target_id")

    if request.method == "POST":
        type_ = request.form["type"]
        target_id = int(request.form["target_id"])
        reason = request.form["reason"]
        reporter_id = session["user_id"]

        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("""
                INSERT INTO reports (type, target_id, reason, reporter_id)
                VALUES (?, ?, ?, ?)
            """, (type_, target_id, reason, reporter_id))
            conn.commit()
            flash("신고가 접수되었습니다.", "success")
        return redirect(url_for("index"))

    return render_template("report.html", report_type=report_type, target_id=target_id)

@app.route("/admin/reports")
def admin_reports():
    if not session.get("is_admin"):
        return redirect(url_for("index"))

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.id, r.type, r.target_id, r.reason, u.username, r.created_at
            FROM reports r
            JOIN users u ON r.reporter_id = u.id
            ORDER BY r.created_at DESC
        """)
        reports = cursor.fetchall()
    return render_template("admin_reports.html", reports=reports)

@app.route("/admin/delete_report/<int:report_id>")
def delete_report(report_id):
    if not session.get("is_admin"):
        return redirect(url_for("index"))

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
        conn.commit()

    flash("신고가 삭제되었습니다.", "info")
    return redirect(url_for("admin_reports"))

@app.route("/admin/delete_user/<int:user_id>")
def delete_user(user_id):
    if not session.get("is_admin"):
        flash("접근 권한이 없습니다.", "danger")
        return redirect(url_for("index"))

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("DELETE FROM users WHERE id = ? AND is_admin = 0", (user_id,))
        conn.execute("DELETE FROM reports WHERE type = 'user' AND target_id = ?", (user_id,))
        conn.commit()

    flash(f"사용자 ID {user_id}가 삭제되었습니다.", "info")
    return redirect(url_for("admin_reports"))

@app.route("/admin/delete_reported_product/<int:product_id>")
def delete_reported_product(product_id):
    if not session.get("is_admin"):
        flash("접근 권한이 없습니다.", "danger")
        return redirect(url_for("index"))

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("DELETE FROM products WHERE id = ?", (product_id,))
        conn.execute("DELETE FROM reports WHERE type = 'product' AND target_id = ?", (product_id,))
        conn.commit()

    flash(f"신고된 상품 ID {product_id}가 삭제되었습니다.", "info")
    return redirect(url_for("admin_reports"))


@app.route("/admin/reset_products")
def reset_products():
    if not session.get("is_admin"):
        flash("접근 권한이 없습니다.", "danger")
        return redirect(url_for("index"))

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("DELETE FROM products")
        conn.commit()

    flash("모든 상품이 삭제되었습니다.", "info")
    return redirect(url_for("admin"))

@app.route("/admin/reset_users")
def reset_users():
    if not session.get("is_admin"):
        return redirect(url_for("index"))

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("DELETE FROM users WHERE is_admin = 0")
        conn.commit()

    flash("일반 사용자가 모두 삭제되었습니다.", "info")
    return redirect(url_for("admin"))

@app.route("/admin/delete_messages")
def delete_messages():
    if not session.get("is_admin"):
        return redirect(url_for("index"))

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("DELETE FROM messages")
        conn.commit()

    flash("모든 메시지가 삭제되었습니다.", "info")
    return redirect(url_for("admin"))

@app.route("/admin/block_user/<int:user_id>")
def block_user(user_id):
    if not session.get("is_admin"):
        return redirect(url_for("index"))

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        status = cursor.execute("SELECT is_blocked FROM users WHERE id = ?", (user_id,)).fetchone()
        if status:
            new_status = 0 if status[0] == 1 else 1
            cursor.execute("UPDATE users SET is_blocked = ? WHERE id = ?", (new_status, user_id))
            conn.commit()

    return redirect(url_for("admin"))

@app.route("/admin/block_product/<int:product_id>")
def block_product(product_id):
    if not session.get("is_admin"):
        return redirect(url_for("index"))

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        status = cursor.execute("SELECT is_blocked FROM products WHERE id = ?", (product_id,)).fetchone()
        if status:
            new_status = 0 if status[0] == 1 else 1
            cursor.execute("UPDATE products SET is_blocked = ? WHERE id = ?", (new_status, product_id))
            conn.commit()

    return redirect(url_for("admin"))

@app.route("/admin/messages")
def admin_messages():
    if not session.get("is_admin"):
        return redirect(url_for("index"))

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT m.id, u1.username, u2.username, m.message, m.created_at
            FROM messages m
            JOIN users u1 ON m.sender_id = u1.id
            JOIN users u2 ON m.receiver_id = u2.id
            ORDER BY m.created_at DESC
        """)
        messages = cursor.fetchall()

    return render_template("admin_messages.html", messages=messages)

@app.route("/admin/transfers")
def admin_transfers():
    if not session.get("is_admin"):
        return redirect(url_for("index"))

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.id, u1.username, u2.username, p.name, t.amount, t.created_at
            FROM transfers t
            JOIN users u1 ON t.sender_id = u1.id
            JOIN users u2 ON t.receiver_id = u2.id
            LEFT JOIN products p ON t.product_id = p.id
            ORDER BY t.created_at DESC
        """)
        transfers = cursor.fetchall()

    return render_template("admin_transfers.html", transfers=transfers)

@app.route("/admin/blocked")
def admin_blocked():
    if not session.get("is_admin"):
        flash("접근 권한이 없습니다.", "danger")
        return redirect(url_for("index"))

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        blocked_users = cursor.execute("""
            SELECT id, username, email FROM users WHERE is_blocked = 1
        """).fetchall()

        blocked_products = cursor.execute("""
            SELECT id, name, price FROM products WHERE is_blocked = 1
        """).fetchall()

    return render_template("admin_blocked.html",
                           blocked_users=blocked_users,
                           blocked_products=blocked_products)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        if request.method == "POST":
            bio = request.form["bio"]
            cursor.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, session["user_id"]))
            conn.commit()
            flash("소개글이 저장되었습니다.", "success")
            return redirect(url_for("profile"))  # ✅ 이 redirect가 반드시 있어야 중복 렌더링 방지됨!

        cursor.execute("SELECT username, email, bio FROM users WHERE id = ?", (session["user_id"],))
        user = cursor.fetchone()

    return render_template("profile.html", user=user)

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        current = request.form["current_password"]
        new = request.form["new_password"]
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE id = ?", (session["user_id"],))
            user_pw = cursor.fetchone()[0]
            if not check_password_hash(user_pw, current):
                flash("현재 비밀번호가 틀렸습니다.", "danger")
            else:
                hashed = generate_password_hash(new)
                cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, session["user_id"]))
                conn.commit()
                flash("비밀번호가 변경되었습니다.", "success")
    return render_template("change_password.html")

@app.route("/user/<int:user_id>")
def view_user(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, bio FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            flash("사용자를 찾을 수 없습니다.", "danger")
            return redirect(url_for("index"))
    return render_template("view_user.html", username=user[0], bio=user[1])

@app.route("/group_chat")
def group_chat():
    if "user_id" not in session:
        flash("로그인이 필요합니다.", "danger")
        return redirect(url_for("login"))
    return render_template("group_chat.html")

@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

@socketio.on("send_message")
def handle_group_message(message):
    username = session.get("username", "익명")
    emit("receive_message", {"username": username, "message": message}, broadcast=True)

# ✅ 앱 실행
if __name__ == "__main__":
    if not os.path.exists(DB_NAME):
        init_db()
    else:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='products'")
            if not cursor.fetchone():
                init_db()

            # 관리자 계정 자동 생성
            cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
            if cursor.fetchone()[0] == 0:
                admin_pw = generate_password_hash("admin1234")
                cursor.execute("""
                    INSERT INTO users (username, email, password, is_admin)
                    VALUES (?, ?, ?, 1)
                """, ("관리자", "admin@example.com", admin_pw))
                conn.commit()
                print("✅ 기본 관리자 계정이 생성되었습니다.")

    # Flask 대신 SocketIO로 실행
    socketio.run(app, debug=True)
