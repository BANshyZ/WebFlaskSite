from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, current_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from models import guest, db


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'secret-key-goes-here'
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@app.route('/')
def Main():
    return render_template('Main.html')


@app.route('/firstArticle')
def firstArticle():
    return render_template('firstArticle.html')


@app.route('/secondArticle')
def secondArticle():
    return render_template('secondArticle.html')


@app.route('/User')
def User():
    if current_user.is_authenticated:
        return render_template('userPage.html', user=current_user)
    else:
        return redirect(url_for('authorisation'))


@app.route('/Admin')
def Admin():
    return render_template('adminPage.html')


@login_manager.user_loader
def load_user(user_id):
    return guest.query.get(int(user_id))


@app.route('/authorisation', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('User'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = guest.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('User'))
        else:
            flash('Неправильный логин или пароль')
    return render_template('authorisation.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('User'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        user = guest.query.filter_by(username=username).first()
        if user:
            flash('Такое имя пользователся уже существует')
        else:
            hashed_password = generate_password_hash(password)
            new_user = guest(username=username, password=hashed_password, email=email)
            db.session.add(new_user)
            db.session.commit()
            flash('Аккаунт создан успешно!')
            return redirect(url_for('authorisation'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('Main'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(host="0.0.0.0", port=10000)