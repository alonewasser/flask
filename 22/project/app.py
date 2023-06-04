from flask import Flask, jsonify, request, render_template, redirect, flash, url_for, session
from flask_sqlalchemy import SQLAlchemy
import hashlib
import string
import random

import mysql.connector

app = Flask(__name__)
app.template_folder = 'C:\\Users\\AloneWasser\\Desktop\\22\\templates'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/123'
db = SQLAlchemy(app)
# Подключение к базе данных
cnx = mysql.connector.connect(
    host='localhost',
    user='root',
    password='',
    database='123'
)
registered_users = {}  # Словарь для хранения зарегистрированных пользователей
cursor = cnx.cursor()




class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)
    token = db.Column(db.String(64), unique=True)

    def __init__(self, username, password, is_admin=False, token=None):
        self.username = username
        self.password = password
        self.is_admin = is_admin
        self.token = token

class Course(db.Model):
    __tablename__ = 'courses'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)

class Test(db.Model):
    __tablename__ = 'test'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'))

    course = db.relationship('Course', backref=db.backref('tests', lazy=True))

class Question(db.Model):
    __tablename__ = 'questions'

    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.Text)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'))
    correct_option = db.Column(db.Integer)
    question = db.Column(db.String(255))

    test = db.relationship('Test', backref=db.backref('questions', lazy=True))

class Option(db.Model):
    __tablename__ = 'options'

    id = db.Column(db.Integer, primary_key=True)
    option_text = db.Column(db.Text)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'))
    correct_option = db.Column(db.Boolean, default=False)

    question = db.relationship('Question', backref=db.backref('options', lazy=True))





def check_admin_status(token):
    user = User.query.filter_by(token=token).first()
    if user and user.is_admin:
        return True
    return False

# ...

# Функция для создания администратора по умолчанию
def create_default_admin():
    default_admin_username = 'admin'
    default_admin_password = 'adminpassword'

    admin = User.query.filter_by(username=default_admin_username, is_admin=True).first()
    if admin is None:
        hashed_password = hash_password(default_admin_password)
        admin = User(username=default_admin_username, password=hashed_password, is_admin=True)
        db.session.add(admin)
        db.session.commit()

# Вспомогательная функция для хеширования пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Вспомогательная функция для проверки пароля
def check_password(password, hashed_password):
    return hashlib.sha256(password.encode()).hexdigest() == hashed_password




def generate_token(token_type):
    if token_type == 'admin':
        admin_token = 'admin_token'  # Админский токен
        hashed_token = hashlib.sha256(admin_token.encode('utf-8')).hexdigest()  # Хеширование админского токена
    else:
        user_token = 'user_token'  # Пользовательский токен
        hashed_token = hashlib.sha256(user_token.encode('utf-8')).hexdigest()  # Хеширование пользовательского токена

    return hashed_token


@app.before_request
def setup():

    # Вызов функции для создания администратора по умолчанию
    create_default_admin()



@app.route('/')
def home():
    token = session.get('token')  # Получение токена из сеанса пользователя
    return render_template('index.html', token=token)



# Роут для страницы с информацией о конкретном курсе
@app.route('/courses/<int:course_id>')
def course_details(course_id):
    token = request.headers.get('Authorization')
    session['token'] = token
    course = Course.query.get(course_id)
    if not course:
        return jsonify({'error': 'Course not found'}), 404

    test = Test.query.filter_by(course_id=course_id).all()
    return render_template('course_details.html', course=course, test=test,
                           token=request.headers.get('Authorization'))




# Роут для страницы с созданием курса
@app.route('/create_course', methods=['POST', 'GET'])
def create_course():
    token = session.get('token')
    username = session.get('username')

    if not token:
        return redirect('/login')

    is_admin_token = (token == generate_token('admin'))

    if not is_admin_token:
        return redirect('/courses')

    courses = Course.query.all()

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')

        if not title or not description:
            return jsonify({'error': 'Missing data'}), 400

        course = Course(title=title, description=description)
        db.session.add(course)
        db.session.commit()

        return redirect('/courses')

    return render_template('create_course.html')



@app.route('/courses/<int:course_id>/create_test', methods=['GET', 'POST'])
def create_test(course_id):
    token = session.get('token')
    username = session.get('username')

    if not token:
        return redirect('/login')

    is_admin_token = (token == generate_token('admin'))

    if not is_admin_token:
        return jsonify({'error': 'Unauthorized'}), 401

    create_test_id = request.form.get('course_id')
    course = db.session.query(Course).filter_by(id=course_id).first()
    if not course:
        return jsonify({'error': 'Course not found'}), 404

    if request.method == 'POST':
        title = request.form.get('title')
        questions = []
        options = []
        correct_answers = []

        for key, value in request.form.items():
            if key.startswith('question-'):
                questions.append(value)
            elif key.startswith('option'):
                options.append(value)
            elif key.startswith('correct_option'):
                correct_answers.append(value)

        if not title or not questions or not options or not correct_answers:
            return jsonify({'error': 'Missing data'}), 400

        test = Test(title=title, course_id=course_id)
        db.session.add(test)
        db.session.commit()

        for i, question_text in enumerate(questions):
            question = Question(test_id=test.id, question=question_text)
            db.session.add(question)

            for j, option_text in enumerate(options[i * 4: (i + 1) * 4]):
                option = Option(question_id=question.id, option=option_text)
                db.session.add(option)

        db.session.commit()

        return redirect('/courses')

    return render_template('add_questions.html', course=course)




@app.route('/courses/<int:course_id>/add_questions', methods=['GET', 'POST'])
def add_questions(course_id):
    if request.method == 'POST':
        return redirect(url_for('create_test', course_id=course_id))

    return render_template('add_questions.html', course_id=course_id)


@app.route('/courses/<int:course_id>/delete', methods=['POST'])
def delete_course(course_id):
    token = session.get('token')
    username = session.get('username')

    if not token:
        return redirect('/login')

    is_admin_token = (token == generate_token('admin'))

    if not is_admin_token:
        return jsonify({'error': 'Unauthorized'}), 401

    course = Course.query.get(course_id)
    if not course:
        return jsonify({'error': 'Course not found'}), 404

    db.session.delete(course)
    db.session.commit()

    return redirect('/courses')


# ...
# Определение функции secure_filename
def secure_filename(filename):
    # Допустимые символы для имени файла
    allowed_chars = string.ascii_letters + string.digits + '._-'

    # Удаляем символы, отличные от допустимых
    cleaned_filename = ''.join(c for c in filename if c in allowed_chars)

    # Генерируем случайное имя файла, если после очистки имя стало пустым
    if not cleaned_filename:
        random_chars = ''.join(random.choices(allowed_chars, k=8))
        cleaned_filename = f'unnamed_{random_chars}'

    return cleaned_filename

# ...
# Функция проверки допустимых расширений файлов
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
#
# @app.route('/upload_avatar', methods=['POST'])
# def upload_avatar():
#     if 'avatar' not in request.files:
#         return 'No file uploaded', 400
#
#     avatar = request.files['avatar']
#
#     if avatar.filename == '':
#         return 'No selected file', 400
#
#     if avatar and allowed_file(avatar.filename):
#         filename = secure_filename(avatar.filename)
#         avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
#     else:
#         filename = 'default_avatar.png'


# ...
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        # Проверка наличия активной сессии пользователя
        if 'username' in session:
            return redirect(url_for('courses'))

        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')


        user = User.query.filter_by(username=username).first()

        if user:
            error_message = 'Имя пользователя уже существует'
            return render_template('register.html', error_message=error_message)

        if password != confirm_password:
            error_message = 'Пароли не совпадают'
            return render_template('register.html', error_message=error_message)

        # Создание нового пользователя
        token = generate_token(token_type='registration')
        new_user = User(username=username, password=hash_password(password), token=token)
        db.session.add(new_user)
        db.session.commit()

        # Успешная регистрация
        flash('Регистрация прошла успешно', 'success')
        return redirect(url_for('courses'))

    return render_template('register.html')




# ...

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        if 'username' in session:
            return redirect(url_for('courses'))

        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if not user or not check_password(password, user.password):
            error_message = 'Неверное имя пользователя или пароль'
            return render_template('login.html', error_message=error_message)

        if user.is_admin:
            token_type = 'admin'
        else:
            token_type = 'user'

        token = generate_token(token_type)

        session['username'] = username
        session['token'] = token
        print(f"Token saved in session: {session['token']}")
        if token_type == 'admin':
            print("Admin token is set")

        flash('Вход выполнен успешно', 'success')
        return redirect(url_for('courses'))

    return render_template('login.html')


def save_question(question, options, correct_option, test_id):
    # Сохранение вопроса
    query = "INSERT INTO Questions (test_id, question) VALUES (%s, %s)"
    cursor.execute(query, (test_id, question))
    question_id = cursor.lastrowid

    # Сохранение вариантов ответа
    for option in options:
        query = "INSERT INTO Option (question_id, option) VALUES (%s, %s)"
        cursor.execute(query, (question_id, option))

    # Сохранение правильного варианта ответа
    query = "UPDATE Questions SET correct_option = %s WHERE id = %s"
    cursor.execute(query, (correct_option, question_id))


    cnx.commit()






# ...

@app.route('/courses')
def courses():
    token = session.get('token')
    username = session.get('username')

    if not token:
        return redirect('/login')

    is_admin_token = (token == generate_token('admin'))  # Проверяем, является ли токен админским

    courses = Course.query.all()

    return render_template('courses.html', courses=courses, username=username, is_admin_token=is_admin_token)









# ...

@app.route('/logout', methods=['POST'])
def logout():
    # Проверка наличия активной сессии пользователя
    if 'username' in session:
        session.pop('username')
        session.pop('token', None)  # Удаление токена из сеанса

    return render_template('login.html')


# ...


# ...

if __name__ == '__main__':
    app.secret_key = 'your_secret_key_here'
    app.run(debug=True)
    cursor.close()
    cnx.close()
