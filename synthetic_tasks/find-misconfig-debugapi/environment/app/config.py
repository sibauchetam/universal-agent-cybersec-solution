import os

DEBUG = True                      # stack traces enabled in "production"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "admin123"       # default credential, never rotated
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False   # readable from JS
