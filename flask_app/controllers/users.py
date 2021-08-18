from flask import render_template, redirect, session, flash, request
from flask_app import app
from flask_bcrypt import Bcrypt
from flask_app.models.user import User

bcrypt = Bcrypt(app)

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register',methods=['POST'])
def register():
    if not User.valid_registration(request.form):
        return redirect('/')
    data ={ 
        "first_name": request.form['first_name'],
        "last_name": request.form['last_name'],
        "email": request.form['email'],
        "password": bcrypt.generate_password_hash(request.form['password'])
    }
    id = User.save(data)
    session['user_id'] = id

    return redirect('/dashboard')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/logout')
    data = {
        'id': session['user_id']
    }
    
    return render_template('dashboard.html', user = User.get_user_by_id(data))


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/login', methods=['POST'])
def login():
    user = User.valid_login(request.form)
    if not user:
        return redirect('/')
    session['user_id'] = user.id
    return redirect('/dashboard')