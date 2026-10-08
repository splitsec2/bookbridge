"""Token-authenticated admin API for provisioning readers."""
import hashlib
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from flask import Flask

from src.api import admin_api
from src.api import kosync_server
from src.db.database_service import DatabaseService
from src.db.models import User, UserCredential

TOKEN = 't' * 40


class TestAdminApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # A private app and database, so nothing leaks into other test modules.
        cls.tmpdir = tempfile.mkdtemp(prefix="test_admin_api_")
        cls.db = DatabaseService(os.path.join(cls.tmpdir, "test.db"))
        cls.app = Flask(__name__)
        cls.app.register_blueprint(admin_api.admin_api_bp)
        cls.app.register_blueprint(kosync_server.kosync_sync_bp)
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        admin_api.init_admin_api(self.db, MagicMock(return_value=0), MagicMock())
        self.addCleanup(admin_api.init_admin_api, None)
        with self.db.get_session() as session:
            session.query(UserCredential).delete()
            session.query(User).delete()
        self.db.create_user("admin", "admin-password", role="admin")
        env = patch.dict(os.environ, {"ADMIN_API_TOKEN": TOKEN})
        env.start()
        self.addCleanup(env.stop)

    def _h(self, token=TOKEN):
        return {"Authorization": f"Bearer {token}"}

    # --- access -----------------------------------------------------------------

    def test_disabled_without_token(self):
        with patch.dict(os.environ, {"ADMIN_API_TOKEN": ""}):
            r = self.client.get('/api/v1/admin/users', headers=self._h())
        self.assertEqual(r.status_code, 404)

    def test_disabled_with_short_token(self):
        with patch.dict(os.environ, {"ADMIN_API_TOKEN": "short"}):
            r = self.client.get('/api/v1/admin/users', headers=self._h("short"))
        self.assertEqual(r.status_code, 404)

    def test_wrong_or_missing_token_is_401(self):
        self.assertEqual(self.client.get('/api/v1/admin/users', headers=self._h('x' * 40)).status_code, 401)
        self.assertEqual(self.client.get('/api/v1/admin/users').status_code, 401)

    def test_list_users_never_includes_secrets(self):
        r = self.client.get('/api/v1/admin/users', headers=self._h())
        self.assertEqual(r.status_code, 200)
        users = r.get_json()["users"]
        self.assertEqual([u["username"] for u in users], ["admin"])
        self.assertEqual(set(users[0]), {"id", "username", "role", "active"})

    # --- users ------------------------------------------------------------------

    def test_create_user_then_idempotent_update(self):
        r = self.client.put('/api/v1/admin/users/reader@example.com', headers=self._h(),
                            json={"password": "first password here"})
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertEqual((body["username"], body["role"], body["active"], body["created"]),
                         ("reader@example.com", "user", True, True))
        admin_api._on_user_created.assert_called_once()
        self.assertIsNotNone(self.db.verify_user_credentials("reader@example.com", "first password here"))

        r = self.client.put('/api/v1/admin/users/reader@example.com', headers=self._h(),
                            json={"password": "second password here"})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.get_json()["created"])
        self.assertIsNone(self.db.verify_user_credentials("reader@example.com", "first password here"))
        self.assertIsNotNone(self.db.verify_user_credentials("reader@example.com", "second password here"))
        admin_api._on_user_created.assert_called_once()

    def test_create_requires_password(self):
        r = self.client.put('/api/v1/admin/users/new@example.com', headers=self._h(), json={})
        self.assertEqual(r.status_code, 400)
        self.assertIsNone(self.db.get_user_by_username("new@example.com"))

    def test_explicit_active_flag(self):
        self.client.put('/api/v1/admin/users/r@example.com', headers=self._h(), json={"password": "pw pw pw"})
        r = self.client.put('/api/v1/admin/users/r@example.com', headers=self._h(), json={"active": False})
        self.assertFalse(r.get_json()["active"])
        # Same value again is a no-op, not a toggle.
        r = self.client.put('/api/v1/admin/users/r@example.com', headers=self._h(), json={"active": False})
        self.assertFalse(r.get_json()["active"])
        r = self.client.put('/api/v1/admin/users/r@example.com', headers=self._h(), json={"active": True})
        self.assertTrue(r.get_json()["active"])

    def test_refuses_to_disable_or_demote_last_admin(self):
        for body in ({"active": False}, {"role": "user"}):
            r = self.client.put('/api/v1/admin/users/admin', headers=self._h(), json=body)
            self.assertEqual(r.status_code, 409)
        self.assertTrue(self.db.get_user_by_username("admin").active)

    def test_bad_inputs(self):
        for body in ({"password": ""}, {"role": "owner"}, {"active": "maybe"}):
            r = self.client.put('/api/v1/admin/users/x@example.com', headers=self._h(), json=body)
            self.assertEqual(r.status_code, 400, body)
        r = self.client.put('/api/v1/admin/users/x@example.com', headers=self._h(), data="not json")
        self.assertEqual(r.status_code, 400)

    # --- integrations ---------------------------------------------------------

    def test_patch_integrations_sets_only_given_keys_and_hides_secrets(self):
        self.client.put('/api/v1/admin/users/r@example.com', headers=self._h(), json={"password": "pw pw pw"})
        uid = self.db.get_user_by_username("r@example.com").id
        self.db.set_user_credential(uid, "ABS_LIBRARY_ID", "lib-1")
        r = self.client.patch('/api/v1/admin/users/r@example.com/integrations', headers=self._h(), json={
            "KOSYNC_ENABLED": True, "KOSYNC_USER": "r@example.com", "KOSYNC_KEY": "sync secret",
            "READEST_ENABLED": "false",
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["updated"], ["KOSYNC_ENABLED", "KOSYNC_KEY", "KOSYNC_USER", "READEST_ENABLED"])
        self.assertNotIn("sync secret", r.get_data(as_text=True))
        creds = self.db.get_user_credentials(uid)
        self.assertEqual(creds["KOSYNC_ENABLED"], "true")
        self.assertEqual(creds["READEST_ENABLED"], "false")
        self.assertEqual(creds["KOSYNC_KEY"], "sync secret")
        self.assertEqual(creds["ABS_LIBRARY_ID"], "lib-1")  # untouched
        admin_api._on_integrations_saved.assert_called_once_with(uid)

    def test_patch_integrations_rejects_unknown_keys_and_bad_bools(self):
        self.client.put('/api/v1/admin/users/r@example.com', headers=self._h(), json={"password": "pw pw pw"})
        r = self.client.patch('/api/v1/admin/users/r@example.com/integrations', headers=self._h(),
                              json={"NOT_A_KEY": "x"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json()["keys"], ["NOT_A_KEY"])
        r = self.client.patch('/api/v1/admin/users/r@example.com/integrations', headers=self._h(),
                              json={"KOSYNC_ENABLED": "sometimes"})
        self.assertEqual(r.status_code, 400)
        r = self.client.patch('/api/v1/admin/users/nobody@example.com/integrations', headers=self._h(),
                              json={"KOSYNC_ENABLED": True})
        self.assertEqual(r.status_code, 404)

    # --- end to end: provision, sync, revoke ----------------------------------

    def test_provisioned_reader_can_sync_until_disabled(self):
        key = hashlib.md5(b"reader password").hexdigest()
        self.client.put('/api/v1/admin/users/r@example.com', headers=self._h(), json={"password": "reader password"})
        self.client.patch('/api/v1/admin/users/r@example.com/integrations', headers=self._h(), json={
            "KOSYNC_ENABLED": True, "KOSYNC_USER": "r@example.com", "KOSYNC_KEY": "reader password",
        })
        auth = {"x-auth-user": "r@example.com", "x-auth-key": key}
        with patch.object(kosync_server, "_database_service", self.db):
            self.assertEqual(self.client.get('/users/auth', headers=auth).status_code, 200)
            self.client.put('/api/v1/admin/users/r@example.com', headers=self._h(), json={"active": False})
            self.assertEqual(self.client.get('/users/auth', headers=auth).status_code, 401)


if __name__ == '__main__':
    unittest.main()
