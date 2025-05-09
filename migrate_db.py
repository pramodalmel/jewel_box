from app import app, db, User, Billing
from werkzeug.security import generate_password_hash

def migrate_database():
    with app.app_context():
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()
        
        # Create admin user
        if not User.query.filter_by(username='admin').first():
            hashed_password = generate_password_hash('admin123')
            admin = User(username='admin', password=hashed_password)
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")
        
        print("Database migration completed successfully!")

if __name__ == "__main__":
    migrate_database()
