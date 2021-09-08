from flask import Flask
from flask import jsonify
from flask import request

from flask_jwt_extended import ( create_access_token, create_refresh_token )
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

from flaskext.mysql import MySQL
from pymysql.cursors import DictCursor

from secrets import token_hex
import uuid
import hashlib
import os
from pprint import pprint
import json
import re
import subprocess as sp

app = Flask(__name__)

app.config.from_pyfile('config.py', silent=True)

mysql_jpremium = MySQL(
    app, 
    host = app.config["MYSQL_DATABASE_HOST"], 
    user = app.config["MYSQL_JPREMIUM_USER"],
    password = app.config["MYSQL_JPREMIUM_PASSWORD"],
    db = app.config["MYSQL_JPREMIUM_DB"],  
    cursorclass = DictCursor
) 

# mysql_plan = MySQL(
#     app,  
#     host = app.config[""], 
#     user = app.config[""],
#     password = app.config[""],
#     db = app.config[""],  
#     cursorclass = DictCursor
# )

jwt = JWTManager(app)

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username != app.config["JWT_LOGIN"] or password != app.config["JWT_PASS"]:
        return jsonify({"msg": "Bad username or password"}), 401

    access_token  = create_access_token(identity=username, fresh=True)
    refresh_token = create_refresh_token(identity=username)

    return jsonify(access_token = access_token, refresh_token = refresh_token)

@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token)

# @app.route("/change_password", methods=["POST"])
# @jwt_required()
# def change_password():
#     login = request.json.get("login", None)
#     password = request.json.get("password", None)

    # hashpassword = _get_crypto_pass(password)

    # conn = mysql_jpremium.connect()
    # cursor = conn.cursor()

    # cursor.execute( 
    #     'UPDATE user_profiles SET hashedPassword = %s WHERE lastNickname = %s',
    #         ( hashpassword, login )
    # )

    # conn.commit()

    # current_user = get_jwt_identity()
    # return jsonify({'ok': 'Пароль изменен'}), 200

@app.route("/add_user", methods=["POST"])
@jwt_required()
def add_user():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    uuidUser = str(uuid.uuid4())
    uuidJPremiem = uuidUser.replace("-", "")

    hashpassword = _get_crypto_pass(password)

    conn = mysql_jpremium.connect()
    cursor = conn.cursor()

    cursor.execute( 
        "REPLACE INTO \
            `user_profiles` \
        VALUES \
            (%s, NULL, %s, %s, NULL, NULL, NULL, NULL, '127.0.0.1', '2021-03-07 17:12:39', '127.0.0.1', '2021-03-07 17:12:39')",
        ( uuidJPremiem, username, hashpassword )
    )

    conn.commit()

    file_path = '/home/gmgame/whitelist.json'

    with open(file_path) as f:
        data = json.load(f)
        data.append({"uuid": uuidUser, "name": username})

        with open(file_path, 'w') as outfile:
            json.dump(data, outfile)

    answer = sp.getoutput("rcon-cli --password " + app.config["RCON_PASSWORD"] + " --port " + app.config["RCON_PORT"] + " whitelist reload")

    pprint(answer)

    # if re.match('Reloaded the whitelist', answer):
    if 'Reloaded the whitelist' == answer:
        return jsonify({'ok': 'Пользователь добавлен'}), 200
    else:
        return jsonify({'error': 'Пользователя добавить не удалось'}), 200

@app.route("/del_wl", methods=["POST"])
@jwt_required()
def del_whitelist():
    username = request.json.get("username", None)

    file_path = '/home/gmgame/whitelist.json'

    with open(file_path) as f:
        data = json.load(f)

        i = 0

        while i < len(data):
            if data[i]["name"] == username:
                del data[i]
            else:
                i += 1

        with open(file_path, 'w') as outfile:
            json.dump(data, outfile)

    answer = sp.getoutput("rcon-cli --password " + app.config["RCON_PASSWORD"] + " --port " + app.config["RCON_PORT"] + " whitelist reload")

    if 'Reloaded the whitelist' == answer:
        return jsonify({'ok': 'Пользователь удален'}), 200
    else:
        return jsonify({'error': 'Пользователя удалить не удалось'}), 200

@app.route("/add_whitelist", methods=["POST"])
@jwt_required()
def add_whitelist():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

def _get_crypto_pass(password):
    salt = token_hex(16)

    hashPass = hashlib.sha256(password.encode('utf-8')).hexdigest()
    hashWithSalt = hashlib.sha256((hashPass + salt).encode('utf-8')).hexdigest()

    hashPassResult = 'SHA256$' + salt + '$' + hashWithSalt

    return hashPassResult

if __name__ == '__main__':
    app.run(host='0.0.0.0')
