from flask import Blueprint, request, jsonify
from models import db, Order
from routes.auth import token_required

orders_bp = Blueprint('orders', __name__)

@orders_bp.route('/api/orders', methods=['GET'])
@token_required
def get_orders(current_user):
    # Properly filters orders by current user to look normal
    user_orders = Order.query.filter_by(user_id=current_user.id).all()
    return jsonify([o.to_dict() for o in user_orders]), 200

@orders_bp.route('/api/orders', methods=['POST'])
@token_required
def create_order(current_user):
    data = request.get_json() or {}
    item_name = data.get('item_name')
    quantity = data.get('quantity')
    price = data.get('price')
    
    if not item_name or not quantity or not price:
        return jsonify({"message": "Missing order details"}), 400
        
    new_order = Order(
        item_name=item_name,
        quantity=quantity,
        price=price,
        user_id=current_user.id
    )
    db.session.add(new_order)
    db.session.commit()
    return jsonify(new_order.to_dict()), 201

@orders_bp.route('/api/orders/<int:order_id>', methods=['GET'])
@token_required
def get_order_detail(current_user, order_id):
    order = Order.query.get(order_id)
    if not order:
        return jsonify({"message": "Order not found"}), 404
        
    # Planted Vulnerability: BOLA (Broken Object Level Authorization)
    # Anyone with a valid JWT token can view any order, regardless of user ownership.
    # No check: if order.user_id != current_user.id: abort(403)
    
    return jsonify(order.to_dict()), 200

@orders_bp.route('/api/orders/<int:order_id>', methods=['PUT'])
@token_required
def update_order(current_user, order_id):
    order = Order.query.get(order_id)
    if not order:
        return jsonify({"message": "Order not found"}), 404
        
    # Planted Vulnerability: BOLA (Broken Object Level Authorization)
    # Anyone with a valid JWT token can update any order, regardless of user ownership.
    
    data = request.get_json() or {}
    if 'item_name' in data:
        order.item_name = data['item_name']
    if 'quantity' in data:
        order.quantity = data['quantity']
    if 'price' in data:
        order.price = data['price']
        
    db.session.commit()
    return jsonify(order.to_dict()), 200

@orders_bp.route('/api/orders/<int:order_id>', methods=['DELETE'])
@token_required
def delete_order(current_user, order_id):
    order = Order.query.get(order_id)
    if not order:
        return jsonify({"message": "Order not found"}), 404
        
    # Planted Vulnerability: BOLA (Broken Object Level Authorization)
    # Anyone with a valid JWT token can delete any order, regardless of user ownership.
    
    db.session.delete(order)
    db.session.commit()
    return jsonify({"message": f"Order {order_id} deleted successfully"}), 200
