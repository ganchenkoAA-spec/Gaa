from flask import Flask, render_template, request, jsonify
import mysql.connector
import bcrypt

app = Flask(__name__)

# --- ФУНКЦИЯ ДЛЯ ПОДКЛЮЧЕНИЯ К БАЗЕ (чтобы не дублировать код) ---
def get_db_connection():
    return mysql.connector.connect(
        host="185.114.247.43",
        port=3306,
        database="sch688_vvedenie",
        user="sch688_vvedenie",
        password="Qwerty123"
    )

# --- РЕГИСТРАЦИЯ ---
@app.route('/user_register', methods=['POST'])
def user_register():
    req = request.get_json()
    
    name = req.get('name')
    login = req.get('email')
    password = req.get('password')

    # Проверка на пустые поля
    if not name or not login or not password:
        return jsonify({'error': 'Все поля обязательны для заполнения'}), 400

    cnx = get_db_connection()
    cur = cnx.cursor(dictionary=True)

    # Проверяем, существует ли уже такой email
    cur.execute('SELECT id FROM `users` WHERE `email` = %s', (login,))
    existing = cur.fetchone()

    if existing:
        cur.close()
        cnx.close()
        return jsonify({'error': 'Пользователь с таким email уже зарегистрирован'}), 409

    # Хешируем пароль
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    password_hash_str = password_hash.decode('utf-8')

    # Вставляем нового пользователя
    cur.execute(
        'INSERT INTO `users`(`username`, `email`, `password_hash`) VALUES (%s, %s, %s)',
        (name, login, password_hash_str)
    )
    cnx.commit()
    cur.close()
    cnx.close()

    return jsonify({'message': 'Регистрация прошла успешно!'}), 201


# --- АВТОРИЗАЦИЯ (НОВЫЙ МАРШРУТ) ---
@app.route('/user_login', methods=['POST'])
def user_login():
    req = request.get_json()
    
    login = req.get('email')
    password = req.get('password')

    if not login or not password:
        return jsonify({'error': 'Введите email и пароль'}), 400

    cnx = get_db_connection()
    cur = cnx.cursor(dictionary=True)

    # Ищем пользователя по email
    cur.execute('SELECT id, username, password_hash FROM `users` WHERE `email` = %s', (login,))
    user = cur.fetchone()

    cur.close()
    cnx.close()

    if not user:
        return jsonify({'error': 'Пользователь с таким email не найден'}), 404

    # Проверяем пароль (сравниваем введенный пароль с хешем из базы)
    if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({
            'message': 'Авторизация успешна',
            'user_id': user['id'],
            'username': user['username']
        }), 200
    else:
        return jsonify({'error': 'Неверный пароль'}), 401


# --- СТРАНИЦЫ ---
@app.route("/")
def registration():
    return render_template('registration.html')

@app.route("/login")
def login():
    return render_template('login.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)