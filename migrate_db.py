from app import app, db, User, Billing
from werkzeug.security import generate_password_hash
import json
import os

def backup_users():
    users = []
    with app.app_context():
        for user in User.query.all():
            users.append({
                'username': user.username,
                'password': user.password
            })
    return users

def restore_users(users):
    with app.app_context():
        for user_data in users:
            if not User.query.filter_by(username=user_data['username']).first():
                user = User(
                    username=user_data['username'],
                    password=user_data['password']
                )
                db.session.add(user)
        db.session.commit()

def migrate_database():
    # Backup existing users
    users = backup_users()
    
    with app.app_context():
        # Recreate tables
        db.drop_all()
        db.create_all()
        
        # Restore users including admin
        restore_users(users)
        
        # Create admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():            from app import create_admin_user
            create_admin_user()
            print("Admin user created successfully!")
        
        print("Database migration completed successfully!")
        print(f"Restored {len(users)} existing users")

if __name__ == "__main__":
    migrate_database()
