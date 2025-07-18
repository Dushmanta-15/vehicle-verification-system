# migrate.py
from flask_migrate import Migrate
from app import create_app, db
from app.models.user import User
from app.models.vehicle import Vehicle
from app.models.admin import Admin

app = create_app()
migrate = Migrate(app, db)

if __name__ == '__main__':
    app.run()