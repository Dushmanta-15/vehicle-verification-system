# app/routes/__init__.py
from app.routes.main import main
from app.routes.admin import admin_bp

# This makes the blueprints available when importing from app.routes
__all__ = ['main', 'admin_bp']