# Planted Vulnerabilities in Target API

This document serves as the reference guide and answer key for validation testing. It records every security vulnerability deliberately introduced in the `vulnerable-target-api`.

---

## 1. Broken Object Level Authorization (BOLA / IDOR)

- **Endpoints:** 
  - `GET /api/orders/<int:order_id>` (Retrieve order details)
  - `PUT /api/orders/<int:order_id>` (Modify order details)
  - `DELETE /api/orders/<int:order_id>` (Delete order)
- **File:** [`vulnerable-target-api/routes/orders.py`](file:///c:/Users/gupta/OneDrive/Desktop/Api%20Security/vulnerable-target-api/routes/orders.py)
- **Explanation:** 
  These routes utilize the `@token_required` decorator to verify that a client provides a valid JWT. However, after fetching the order from the database using `Order.query.get(order_id)`, they do not verify if `order.user_id == current_user.id`. Any authenticated user can read, modify, or delete orders belonging to other users by changing the ID parameter in the URL.

---

## 2. Mass Assignment

- **Endpoint:** `POST /api/users/signup`
- **File:** [`vulnerable-target-api/routes/auth.py`](file:///c:/Users/gupta/OneDrive/Desktop/Api%20Security/vulnerable-target-api/routes/auth.py)
- **Explanation:**
  The registration endpoint accepts a JSON request body and feeds it raw into the database model constructor: `new_user = User(**user_data)`. Since there is no input whitelist schema, an attacker can append `"role": "admin"` or `"is_admin": true` inside their registration payload. The application will silently apply these values, promoting the user to admin.

---

## 3. Broken Function Level Authorization (BFLA)

- **Endpoint:** `GET /api/admin/users`
- **File:** [`vulnerable-target-api/routes/admin.py`](file:///c:/Users/gupta/OneDrive/Desktop/Api%20Security/vulnerable-target-api/routes/admin.py)
- **Explanation:**
  The administration module exposes an endpoint listing all registered users. While protected by `@token_required` to block anonymous users, the endpoint lacks role checks. It does not check if `current_user.role == 'admin'` or `current_user.is_admin`. As a result, standard users can access this admin function.

---

## 4. JWT Flaws (Broken Authentication)

- **Endpoints:** All endpoints protected by `@token_required`
- **File:** [`vulnerable-target-api/routes/auth.py`](file:///c:/Users/gupta/OneDrive/Desktop/Api%20Security/vulnerable-target-api/routes/auth.py)
- **Explanation:**
  - **Weak Secret Key:** Tokens are generated and validated using a static, easily guessable secret: `"secret"`. Attackers can brute-force this secret key to sign arbitrary tokens.
  - **Algorithm None Bypass:** The validation logic reads the token header first. If `alg` is `"none"`, it calls `jwt.decode` with signature validation disabled: `jwt.decode(token, options={"verify_signature": False})`. An attacker can modify their JWT header to `"alg": "none"` and alter their username/role values without a signature block.
  - **No Expiration Validation:** The JWT token generated in `POST /api/auth/login` does not include an expiration (`exp`) timestamp claim, rendering tokens valid indefinitely.

---

## 5. Missing Rate Limiting

- **Endpoint:** `POST /api/auth/login`
- **File:** [`vulnerable-target-api/routes/auth.py`](file:///c:/Users/gupta/OneDrive/Desktop/Api%20Security/vulnerable-target-api/routes/auth.py)
- **Explanation:**
  No throttling middleware is active on the login endpoint. A client can make infinite requests to guess accounts and passwords without hitting rate limits or blocking thresholds.
