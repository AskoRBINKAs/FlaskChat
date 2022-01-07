from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///chat.db'
app.config['SECRET_KEY']='powerful secretkey'
app.config['WTF_CSRF_SECRET_KEY']="a csrf secret key"
bootstrap = Bootstrap(app)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#models
class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    password = db.Column(db.String(128))

   

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(64),index=True)
    text = db.Column(db.String(500))
    data = db.Column(db.DateTime, default=datetime.utcnow)
    def __repr__(self):
        return '<Message %r>' % self.id




#auth

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    #remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    #email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


#routes

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@app.route('/index')
def index():
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('chat'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data,  password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect('/login')
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('reg.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/get_messages")
@login_required
def get_messages():
     return Message.query.order_by(Message.data.desc()).all()

@app.route("/chat", methods=['POST','GET'])
@login_required
def chat():
    if request.method == "POST":
        message = request.form['message']
        sender = current_user.username
        message = Message(text=message, sender=sender)
        try:
            db.session.add(message)
            db.session.commit()
            return redirect("/chat")
        except:
            return "Вовремя отправки произошла ошибка. Повторите еще раз или позже"
    else:
       
        return render_template("chat.html",user=current_user.username, messages=get_messages())
#start point
if __name__=="__main__":
    app.run(debug=True)