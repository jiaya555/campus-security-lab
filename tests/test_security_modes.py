import io
import unittest

from app import create_app, init_db


class SecurityModeTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True, "DATABASE": ":memory:", "WTF_CSRF_ENABLED": False})
        self.client = self.app.test_client()
        with self.app.app_context():
            init_db(seed=True)

    def login(self, username="alice", password="alice123"):
        return self.client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=True,
        )

    def test_sql_injection_works_only_in_vulnerable_search(self):
        payload = "' OR 1=1 --"
        vulnerable = self.client.get(f"/?mode=vulnerable&q={payload}")
        secure = self.client.get(f"/?mode=secure&q={payload}")

        self.assertIn("机械键盘", vulnerable.get_data(as_text=True))
        self.assertIn("山地自行车", vulnerable.get_data(as_text=True))
        self.assertNotIn("机械键盘", secure.get_data(as_text=True))
        self.assertNotIn("山地自行车", secure.get_data(as_text=True))

    def test_xss_is_rendered_only_in_vulnerable_comment_mode(self):
        self.login()
        payload = "<script>alert('xss')</script>"
        self.client.post("/items/1/comments?mode=vulnerable", data={"content": payload})

        vulnerable = self.client.get("/items/1?mode=vulnerable")
        secure = self.client.get("/items/1?mode=secure")

        self.assertIn(payload, vulnerable.get_data(as_text=True))
        self.assertIn("&lt;script&gt;alert", secure.get_data(as_text=True))

    def test_idor_order_access_is_blocked_in_secure_mode(self):
        self.login("bob", "bob123")

        vulnerable = self.client.get("/orders/1?mode=vulnerable")
        secure = self.client.get("/orders/1?mode=secure")

        self.assertEqual(vulnerable.status_code, 200)
        self.assertIn("Alice", vulnerable.get_data(as_text=True))
        self.assertEqual(secure.status_code, 403)

    def test_file_upload_accepts_bad_extension_only_in_vulnerable_mode(self):
        self.login()
        bad_file = {"image": (io.BytesIO(b"<?php echo 'bad'; ?>"), "shell.php")}

        vulnerable = self.client.post(
            "/items/new?mode=vulnerable",
            data={
                "title": "危险上传测试",
                "description": "vulnerable upload",
                "price": "1",
                **bad_file,
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        secure = self.client.post(
            "/items/new?mode=secure",
            data={
                "title": "安全上传测试",
                "description": "secure upload",
                "price": "1",
                "image": (io.BytesIO(b"<?php echo 'bad'; ?>"), "shell.php"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        self.assertIn("商品已发布", vulnerable.get_data(as_text=True))
        self.assertIn("仅支持上传", secure.get_data(as_text=True))

    def test_csrf_token_is_required_only_in_secure_profile_update(self):
        self.login()

        vulnerable = self.client.post(
            "/profile?mode=vulnerable",
            data={"email": "attacker@example.com"},
            follow_redirects=True,
        )
        secure = self.client.post(
            "/profile?mode=secure",
            data={"email": "blocked@example.com"},
            follow_redirects=True,
        )
        profile = self.client.get("/profile?mode=secure")

        self.assertIn("资料已更新", vulnerable.get_data(as_text=True))
        self.assertEqual(secure.status_code, 403)
        self.assertIn("attacker@example.com", profile.get_data(as_text=True))

    def test_item_delete_requires_csrf_only_in_secure_mode(self):
        self.login("alice", "alice123")

        secure = self.client.post("/items/1/delete?mode=secure", follow_redirects=True)
        still_there = self.client.get("/items/1?mode=secure")
        vulnerable = self.client.post("/items/1/delete?mode=vulnerable", follow_redirects=True)
        gone = self.client.get("/items/1?mode=vulnerable")

        self.assertEqual(secure.status_code, 403)
        self.assertEqual(still_there.status_code, 200)
        self.assertIn("商品已删除", vulnerable.get_data(as_text=True))
        self.assertEqual(gone.status_code, 404)

    def test_comment_delete_requires_owner_and_csrf_in_secure_mode(self):
        self.login("bob", "bob123")

        forbidden = self.client.post("/comments/2/delete?mode=vulnerable", follow_redirects=True)
        secure = self.client.post("/comments/1/delete?mode=secure", follow_redirects=True)
        still_there = self.client.get("/items/1?mode=secure")
        vulnerable = self.client.post("/comments/1/delete?mode=vulnerable", follow_redirects=True)
        gone = self.client.get("/items/1?mode=vulnerable")

        self.assertEqual(forbidden.status_code, 403)
        self.assertEqual(secure.status_code, 403)
        self.assertIn("还能小刀吗？", still_there.get_data(as_text=True))
        self.assertIn("评论已删除", vulnerable.get_data(as_text=True))
        self.assertNotIn("还能小刀吗？", gone.get_data(as_text=True))

    def test_orders_page_lists_only_current_users_orders(self):
        self.login("bob", "bob123")

        response = self.client.get("/orders?mode=secure")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("山地自行车", html)
        self.assertNotIn("机械键盘", html)
        self.assertIn('/orders/2"', html)

    def test_vulnerable_orders_page_keeps_list_normal_but_keeps_access_route(self):
        self.login("bob", "bob123")

        response = self.client.get("/orders?mode=vulnerable")
        html = response.get_data(as_text=True)
        jump = self.client.get("/orders/access?mode=vulnerable&order_id=1", follow_redirects=False)

        self.assertEqual(response.status_code, 200)
        self.assertIn("山地自行车", html)
        self.assertNotIn("机械键盘", html)
        self.assertNotIn("按编号访问订单", html)
        self.assertEqual(jump.status_code, 302)
        self.assertIn("/orders/1", jump.headers["Location"])


if __name__ == "__main__":
    unittest.main()
