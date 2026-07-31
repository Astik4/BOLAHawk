import hashlib
from models import db, User, Order

def seed_db():
    # Reset the database tables
    db.drop_all()
    db.create_all()
    
    def hash_pw(pw):
        return hashlib.sha256(pw.encode()).hexdigest()
    
    # Create users
    alice = User(username="alice", password_hash=hash_pw("password123"), role="user", is_admin=False)
    bob = User(username="bob", password_hash=hash_pw("password456"), role="user", is_admin=False)
    admin = User(username="admin", password_hash=hash_pw("adminpass"), role="admin", is_admin=True)
    
    db.session.add_all([alice, bob, admin])
    db.session.commit()  # Flush to populate IDs
    
    # Create orders
    order1 = Order(item_name="Laptop", quantity=1, price=1200.0, user_id=alice.id)
    order2 = Order(item_name="Phone", quantity=2, price=800.0, user_id=bob.id)
    
    db.session.add_all([order1, order2])
    db.session.commit()
    print("Vulnerable target API database seeded successfully!")
    print(f"Alice ID: {alice.id}, Order ID: {order1.id}")
    print(f"Bob ID: {bob.id}, Order ID: {order2.id}")
    print(f"Admin ID: {admin.id}")
