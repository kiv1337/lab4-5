from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SECRET_KEY'] = '123'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(250), unique=True, nullable=False)

@app.route('/')
def index():
    return render_template('register.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)}, app.config['SECRET_KEY'], algorithm='HS256')
            
            new_token = Token(user_id=user.id, token=token)
            db.session.add(new_token)
            db.session.commit()
            
            return jsonify({'token': token})
        
        return 'Неверные данные!'
    
    return render_template('login.html')

@app.route('/dashboard', methods=['GET'])
def dashboard():
    token = request.args.get('token')
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = data['user_id']
        
        user = User.query.get(user_id)
        
        if user:
            return f'{user.username}, вы попали на страницу dashboard, ваш токен - {token}'
        else:
            return 'Неверный токен'
    except jwt.ExpiredSignatureError:
        return 'Срок дейсвтия токена иссяк.'
    except jwt.InvalidTokenError:
        return 'Неверный токен.'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
