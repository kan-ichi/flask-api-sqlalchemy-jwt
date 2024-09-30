from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from ulid import ULID
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # テスト時以外の場合は、安全な秘密鍵に変更

db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.String(26), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

@app.route('/register-first-user', methods=['POST', 'OPTIONS'])
def register_first_user():
    if request.method == 'OPTIONS':
        return '', 200
    
    if User.query.first():
        return jsonify({"message": "ユーザーが既に存在します。このエンドポイントは使用できません。"}), 400

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"message": "ユーザー名とパスワードが必要です"}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(id=str(ULID()), username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "最初のユーザーが正常に登録されました"}), 201

@app.route('/register-user', methods=['POST', 'OPTIONS'])
@jwt_required()
def register_user():
    if request.method == 'OPTIONS':
        return '', 200
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"message": "ユーザー名とパスワードが必要です"}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({"message": "ユーザー名は既に使用されています"}), 400
    
    hashed_password = generate_password_hash(password)
    new_user = User(id=str(ULID()), username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "ユーザーが正常に登録されました"}), 201

@app.route('/login-user', methods=['POST', 'OPTIONS'])
def login_user():
    if request.method == 'OPTIONS':
        return '', 200
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        return jsonify({
            "access_token": access_token,
            "user_id": user.id,
            "username": user.username
        }), 200
    
    return jsonify({"message": "無効なユーザー名またはパスワード"}), 401

@app.route('/get-user/<string:user_id>', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_user(user_id):
    if request.method == 'OPTIONS':
        return '', 200
    
    current_user_id = get_jwt_identity()
    if current_user_id != user_id:
        return jsonify({"message": "アクセス権限がありません"}), 403

    user = User.query.get(user_id)
    if user:
        return jsonify({"id": user.id, "username": user.username}), 200
    return jsonify({"message": "ユーザーが見つかりません"}), 404

@app.route('/delete-user/<string:user_id>', methods=['DELETE', 'OPTIONS'])
@jwt_required()
def delete_user(user_id):
    if request.method == 'OPTIONS':
        return '', 200

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "ユーザーが正常に削除されました"}), 200
    return jsonify({"message": "ユーザーが見つかりません"}), 404

@app.route('/list-users', methods=['GET', 'OPTIONS'])
@jwt_required()
def list_users():
    if request.method == 'OPTIONS':
        return '', 200
    
    users = User.query.all()
    user_list = [{"id": user.id, "username": user.username} for user in users]
    return jsonify(user_list), 200

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"message": "ログインが必要です"}), 401

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)