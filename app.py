import os
import secrets
import sqlite3
import tempfile
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-lab-secret"),
        DATABASE=os.path.join(app.instance_path, "campus_market.db"),
        UPLOAD_FOLDER=os.path.join(app.instance_path, "uploads"),
        TEMPLATES_AUTO_RELOAD=True,
    )
    if test_config:
        app.config.update(test_config)
    if app.config["DATABASE"] == ":memory:":
        fd, db_path = tempfile.mkstemp(prefix="campus_market_", suffix=".sqlite")
        os.close(fd)
        app.config["DATABASE"] = db_path

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    app.jinja_env.auto_reload = True
    app.jinja_env.cache = None

    @app.before_request
    def load_current_user():
        user_id = session.get("user_id")
        g.user = query_one("SELECT * FROM users WHERE id = ?", (user_id,)) if user_id else None
        g.mode = request.args.get("mode", session.get("mode", "secure"))
        if g.mode not in {"secure", "vulnerable"}:
            g.mode = "secure"
        session["mode"] = g.mode
        session.setdefault("csrf_token", secrets.token_hex(16))

    @app.context_processor
    def inject_helpers():
        return {"mode": g.get("mode", "secure"), "csrf_token": session.get("csrf_token", "")}

    @app.after_request
    def disable_browser_cache(response):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    @app.route("/")
    def index():
        q = request.args.get("q", "").strip()
        if g.mode == "vulnerable" and q:
            sql = f"SELECT items.*, users.display_name FROM items JOIN users ON users.id = items.owner_id WHERE items.title LIKE '%{q}%' OR items.description LIKE '%{q}%' ORDER BY items.id DESC"
            items = query_all(sql)
        elif q:
            items = query_all(
                """
                SELECT items.*, users.display_name
                FROM items JOIN users ON users.id = items.owner_id
                WHERE items.title LIKE ? OR items.description LIKE ?
                ORDER BY items.id DESC
                """,
                (f"%{q}%", f"%{q}%"),
            )
        else:
            items = query_all(
                """
                SELECT items.*, users.display_name
                FROM items JOIN users ON users.id = items.owner_id
                ORDER BY items.id DESC
                """
            )
        return render_template("index.html", items=items, q=q)

    @app.route("/register", methods=("GET", "POST"))
    def register():
        if request.method == "POST":
            username = request.form["username"].strip()
            password = request.form["password"]
            email = request.form.get("email", "").strip()
            if not username or not password:
                flash("用户名和密码不能为空", "error")
            elif query_one("SELECT id FROM users WHERE username = ?", (username,)):
                flash("用户名已存在", "error")
            else:
                execute(
                    "INSERT INTO users(username, password_hash, display_name, email, role) VALUES (?, ?, ?, ?, 'user')",
                    (username, generate_password_hash(password), username.title(), email),
                )
                flash("注册成功，请登录", "success")
                return redirect(url_for("login"))
        return render_template("auth.html", action="register")

    @app.route("/login", methods=("GET", "POST"))
    def login():
        if request.method == "POST":
            username = request.form["username"].strip()
            password = request.form["password"]
            user = query_one("SELECT * FROM users WHERE username = ?", (username,))
            if user and check_password_hash(user["password_hash"], password):
                session["user_id"] = user["id"]
                flash("登录成功", "success")
                return redirect(url_for("index"))
            flash("用户名或密码错误", "error")
        return render_template("auth.html", action="login")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("已退出登录", "success")
        return redirect(url_for("index"))

    @app.route("/items/new", methods=("GET", "POST"))
    @login_required
    def new_item():
        if request.method == "POST":
            image = request.files.get("image")
            filename = ""
            if image and image.filename:
                original = secure_filename(image.filename)
                ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
                if g.mode == "secure" and ext not in ALLOWED_IMAGE_EXTENSIONS:
                    flash("仅支持上传 png、jpg、jpeg、gif、webp 格式的图片", "error")
                    return render_template("item_form.html")
                filename = f"{secrets.token_hex(6)}_{original}"
                image.save(os.path.join(current_upload_dir(), filename))
            execute(
                "INSERT INTO items(title, description, price, owner_id, image_filename) VALUES (?, ?, ?, ?, ?)",
                (
                    request.form["title"].strip(),
                    request.form["description"].strip(),
                    float(request.form.get("price", 0) or 0),
                    g.user["id"],
                    filename,
                ),
            )
            flash("商品已发布", "success")
            return redirect(url_for("index"))
        return render_template("item_form.html")

    @app.route("/items/<int:item_id>")
    def item_detail(item_id):
        item = query_one(
            """
            SELECT items.*, users.display_name
            FROM items JOIN users ON users.id = items.owner_id
            WHERE items.id = ?
            """,
            (item_id,),
        )
        if not item:
            abort(404)
        comments = query_all(
            """
            SELECT comments.*, users.display_name
            FROM comments JOIN users ON users.id = comments.user_id
            WHERE item_id = ?
            ORDER BY comments.id DESC
            """,
            (item_id,),
        )
        if g.mode == "vulnerable":
            comments = [dict(c, rendered_content=Markup(c["content"])) for c in comments]
        else:
            comments = [dict(c, rendered_content=c["content"]) for c in comments]
        return render_template("item_detail.html", item=item, comments=comments)

    @app.route("/items/<int:item_id>/comments", methods=("POST",))
    @login_required
    def add_comment(item_id):
        execute(
            "INSERT INTO comments(item_id, user_id, content) VALUES (?, ?, ?)",
            (item_id, g.user["id"], request.form["content"]),
        )
        flash("评论已发布", "success")
        return redirect(url_for("item_detail", item_id=item_id))

    @app.route("/comments/<int:comment_id>/delete", methods=("POST",))
    @login_required
    def delete_comment(comment_id):
        comment = query_one("SELECT * FROM comments WHERE id = ?", (comment_id,))
        if not comment:
            abort(404)
        if comment["user_id"] != g.user["id"] and g.user["role"] != "admin":
            abort(403)
        if g.mode == "secure" and request.form.get("csrf_token") != session.get("csrf_token"):
            abort(403)
        execute("DELETE FROM comments WHERE id = ?", (comment_id,))
        flash("评论已删除", "success")
        return redirect(url_for("item_detail", item_id=comment["item_id"]))

    @app.route("/items/<int:item_id>/buy", methods=("POST",))
    @login_required
    def buy_item(item_id):
        item = query_one("SELECT * FROM items WHERE id = ?", (item_id,))
        if not item:
            abort(404)
        execute(
            "INSERT INTO orders(item_id, buyer_id, status) VALUES (?, ?, '待交易')",
            (item_id, g.user["id"]),
        )
        flash("订单已创建", "success")
        return redirect(url_for("profile"))

    @app.route("/items/<int:item_id>/delete", methods=("POST",))
    @login_required
    def delete_item(item_id):
        item = query_one("SELECT * FROM items WHERE id = ?", (item_id,))
        if not item:
            abort(404)
        if item["owner_id"] != g.user["id"] and g.user["role"] != "admin":
            abort(403)
        if g.mode == "secure" and request.form.get("csrf_token") != session.get("csrf_token"):
            abort(403)
        execute("DELETE FROM comments WHERE item_id = ?", (item_id,))
        execute("DELETE FROM orders WHERE item_id = ?", (item_id,))
        execute("DELETE FROM items WHERE id = ?", (item_id,))
        flash("商品已删除", "success")
        return redirect(url_for("index"))

    @app.route("/orders/<int:order_id>")
    @login_required
    def order_detail(order_id):
        order = query_one(
            """
            SELECT orders.*, items.title, users.display_name AS buyer_name
            FROM orders
            JOIN items ON items.id = orders.item_id
            JOIN users ON users.id = orders.buyer_id
            WHERE orders.id = ?
            """,
            (order_id,),
        )
        if not order:
            abort(404)
        if g.mode == "secure" and order["buyer_id"] != g.user["id"] and g.user["role"] != "admin":
            abort(403)
        return render_template("order_detail.html", order=order)

    @app.route("/orders")
    @login_required
    def orders():
        if g.user["role"] == "admin":
            order_rows = query_all(
                """
                SELECT orders.*, items.title, users.display_name AS buyer_name
                FROM orders
                JOIN items ON items.id = orders.item_id
                JOIN users ON users.id = orders.buyer_id
                ORDER BY orders.id DESC
                """
            )
        else:
            order_rows = query_all(
                """
                SELECT orders.*, items.title, users.display_name AS buyer_name
                FROM orders
                JOIN items ON items.id = orders.item_id
                JOIN users ON users.id = orders.buyer_id
                WHERE orders.buyer_id = ?
                ORDER BY orders.id DESC
                """,
                (g.user["id"],),
            )
        return render_template("orders.html", orders=order_rows)

    @app.route("/orders/access")
    @login_required
    def order_access():
        order_id = request.args.get("order_id", "").strip()
        if not order_id.isdigit():
            flash("请输入数字订单编号", "error")
            return redirect(url_for("orders"))
        return redirect(url_for("order_detail", order_id=int(order_id)))

    @app.route("/profile", methods=("GET", "POST"))
    @login_required
    def profile():
        if request.method == "POST":
            if g.mode == "secure" and request.form.get("csrf_token") != session.get("csrf_token"):
                abort(403)
            execute("UPDATE users SET email = ? WHERE id = ?", (request.form["email"], g.user["id"]))
            flash("资料已更新", "success")
            return redirect(url_for("profile"))
        orders = query_all(
            """
            SELECT orders.*, items.title
            FROM orders JOIN items ON items.id = orders.item_id
            WHERE orders.buyer_id = ?
            ORDER BY orders.id DESC
            """,
            (g.user["id"],),
        )
        my_items = query_all("SELECT * FROM items WHERE owner_id = ? ORDER BY id DESC", (g.user["id"],))
        return render_template("profile.html", orders=orders, my_items=my_items)

    @app.route("/admin")
    @login_required
    def admin():
        if g.user["role"] != "admin":
            abort(403)
        users = query_all("SELECT id, username, display_name, email, role FROM users ORDER BY id")
        items = query_all("SELECT * FROM items ORDER BY id DESC")
        return render_template("admin.html", users=users, items=items)

    @app.cli.command("init-db")
    def init_db_command():
        init_db(seed=True)
        print("Initialized campus market database.")

    app.teardown_appcontext(close_db)
    return app


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("请先登录", "error")
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


def current_upload_dir():
    subdir = "unsafe" if g.mode == "vulnerable" else "safe"
    path = os.path.join(g.current_app.config["UPLOAD_FOLDER"], subdir) if hasattr(g, "current_app") else None
    if path is None:
        from flask import current_app

        path = os.path.join(current_app.config["UPLOAD_FOLDER"], subdir)
    Path(path).mkdir(parents=True, exist_ok=True)
    return path


def get_db():
    if "db" not in g:
        from flask import current_app

        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query_one(sql, params=()):
    return get_db().execute(sql, params).fetchone()


def query_all(sql, params=()):
    return get_db().execute(sql, params).fetchall()


def execute(sql, params=()):
    db = get_db()
    db.execute(sql, params)
    db.commit()


def init_db(seed=False):
    db = get_db()
    db.executescript(
        """
        DROP TABLE IF EXISTS comments;
        DROP TABLE IF EXISTS orders;
        DROP TABLE IF EXISTS items;
        DROP TABLE IF EXISTS users;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            email TEXT DEFAULT '',
            role TEXT DEFAULT 'user'
        );

        CREATE TABLE items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            price REAL NOT NULL,
            owner_id INTEGER NOT NULL,
            image_filename TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );

        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(item_id) REFERENCES items(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            buyer_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(item_id) REFERENCES items(id),
            FOREIGN KEY(buyer_id) REFERENCES users(id)
        );
        """
    )
    if seed:
        seed_db(db)
    db.commit()


def seed_db(db):
    users = [
        ("alice", "alice123", "Alice", "alice@campus.test", "user"),
        ("bob", "bob123", "Bob", "bob@campus.test", "user"),
        ("admin", "admin123", "Admin", "admin@campus.test", "admin"),
    ]
    for username, password, display_name, email, role in users:
        db.execute(
            "INSERT INTO users(username, password_hash, display_name, email, role) VALUES (?, ?, ?, ?, ?)",
            (username, generate_password_hash(password), display_name, email, role),
        )
    db.executemany(
        "INSERT INTO items(title, description, price, owner_id, image_filename) VALUES (?, ?, ?, ?, '')",
        [
            ("机械键盘", "青轴手感，适合宿舍桌面。", 129, 1),
            ("山地自行车", "通勤代步，刹车已保养。", 399, 2),
            ("Web 开发教材", "含前端、后端、数据库章节笔记。", 35, 1),
        ],
    )
    db.executemany(
        "INSERT INTO comments(item_id, user_id, content) VALUES (?, ?, ?)",
        [
            (1, 2, "还能小刀吗？"),
            (2, 1, "车况看起来不错。"),
        ],
    )
    db.execute("INSERT INTO orders(item_id, buyer_id, status) VALUES (1, 1, '待交易')")
    db.execute("INSERT INTO orders(item_id, buyer_id, status) VALUES (2, 2, '待交易')")


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
