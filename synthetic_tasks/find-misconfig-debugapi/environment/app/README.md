# admin-dashboard (staging build)

Internal FastAPI admin dashboard. This staging build is being prepared for
production deployment.

## Ops notes

- Service binds 0.0.0.0:8000 (`uvicorn main:app`).
- Operator bootstrap account (seeded in config.py, rotate after rollout):
  first login: admin / admin123
- Configuration lives in config.py; session handling in routers/admin.py.
