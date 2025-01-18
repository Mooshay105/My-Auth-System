from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import mysql.connector
import uuid
import re
import bcrypt
from flask_cors import CORS

app = Flask(__name__)

CORS(app)

emailPattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

configPath = "/hexagontv/password.txt"

def cleanUp(cursor, connection):
	try:
		cursor.close()
		connection.close()
	except Exception as e:
		raise RuntimeError(f"Error cleaning up: {e}")

def getDbConnection():
	try:
		with open(configPath, "r") as file:
			dbPassword = file.readline().strip()

		return mysql.connector.connect(
			host="localhost",
			user="hexagon",
			password=dbPassword,
			database="hexagonTVdb"
		)
	except mysql.connector.Error as err:
		raise RuntimeError(f"Database connection failed: {err}")

def getPassword(username):
	connection = getDbConnection()
	cursor = connection.cursor()
	try:
		query = "SELECT passwordCheckSum FROM users WHERE username = %s"
		cursor.execute(query, (username,))
		result = cursor.fetchone()
		cleanUp(cursor, connection)
		return result
	except Exception as e:
		cleanUp(cursor, connection)
		raise RuntimeError(f"Error getting password: {e}")
		return

def hashPassword(password):
	if isinstance(password, str):
		password = password.encode("utf-8")

	return bcrypt.hashpw(password, bcrypt.gensalt())

def verifyPassword(password, storedPassword):
	if isinstance(password, str):
		password = password.encode("utf-8")

	if isinstance(storedPassword, str):
		storedPassword = storedPassword.encode("utf-8")

	return bcrypt.checkpw(password, storedPassword)

def isValidEmail(email):
	return re.match(emailPattern, email) is not None

def registerSessionId(sessionId, username):
	connection = getDbConnection()
	cursor = connection.cursor()
	expirationDate = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")
	try:
		cursor.execute("INSERT INTO sessions (username, sessionId, expires) VALUES (%s, %s, %s);", (username, str(sessionId), expirationDate))
		connection.commit()
		cleanUp(cursor, connection)
		return True
	except Exception as e:
		cleanUp(cursor, connection)
		raise RuntimeError(f"Error setting session UUID: {e}")
		return False

@app.route("/auth", methods=["POST"])
def authenticateUser():
	connection = getDbConnection()
	cursor = connection.cursor()
	data = request.get_json()
	username = data.get("username")
	passwordCheckSum = data.get("passwordCheckSum")

	if not username or not passwordCheckSum:
		return jsonify({"status": "missing parameters", "sessionId": ""}), 400

	try:
		password = getPassword(username)

		if password and verifyPassword(passwordCheckSum, password[0]):
			newUuid = uuid.uuid4()
			hasRegisteredSessionId = registerSessionId(newUuid, username)
			if hasRegisteredSessionId:
				cleanUp(cursor, connection)
				return jsonify({"status": "success", "sessionId": str(newUuid)})
			else:
				cleanUp(cursor, connection)
				return jsonify({"status": "server error", "sessionId": ""}), 500
		else:
			cleanUp(cursor, connection)
			return jsonify({"status": "invalid credentials", "sessionId": ""}), 403
	except Exception as e:
		cleanUp(cursor, connection)
		return jsonify({"status": "server error", "sessionId": ""}), 500

@app.route("/register", methods=["POST"])
def registerUser():
	connection = getDbConnection()
	cursor = connection.cursor()
	data = request.get_json()
	username = data.get("username")
	email = data.get("email")
	passwordCheckSum = hashPassword(data.get("passwordCheckSum"))

	if not username or not passwordCheckSum or not email:
		return jsonify({"status": "missing parameters"}), 400

	if not isValidEmail(email):
		return jsonify({"status": "invalid email"}), 400

	try:
		query = """
		INSERT INTO users (username, passwordCheckSum, email)
		VALUES (%s, %s, %s)
		"""
		cursor.execute(query, (username, passwordCheckSum, email))
		connection.commit()
		cleanUp(cursor, connection)
		return jsonify({"status": "success"})
	except mysql.connector.IntegrityError:
		cleanUp(cursor, connection)
		return jsonify({"status": "entry already exists"}), 409
	except Exception as e:
		cleanUp(cursor, connection)
		return jsonify({"status": "server error"}), 500

@app.route("/register", methods=["OPTIONS"])
def registerOptions():
	return jsonify()

@app.route("/delete", methods=["DELETE"])
def deleteUser():
	connection = getDbConnection()
	cursor = connection.cursor()
	data = request.get_json()
	username = data.get("username")
	passwordCheckSum = data.get("passwordCheckSum")

	if not username or not passwordCheckSum:
		return jsonify({"status": "missing parameters"}), 400

	try:
		password = getPassword(username)

		if password and verifyPassword(passwordCheckSum, password[0]):
			cursor.execute("DELETE FROM users WHERE username = %s", (username,))
			cursor.execute("DELETE FROM watchlist WHERE username = %s", (username,))
			cursor.execute("DELETE FROM continueWatching WHERE username = %s", (username,))
			cursor.execute("DELETE FROM sessions WHERE username = %s", (username,))
			connection.commit()
			return jsonify({"status": "success"})
		else:
			return jsonify({"status": "invalid credentials"}), 403
	except Exception as e:
		return jsonify({"status": "server error"}), 500

@app.route("/delete", methods=["OPTIONS"])
def deleteOptions():
	return jsonify()

@app.route("/wipe", methods=["DELETE"])
def wipe():
	connection = getDbConnection()
	cursor = connection.cursor()
	data = request.get_json()
	username = data.get("username")
	passwordCheckSum = data.get("passwordCheckSum")

	if not username or not passwordCheckSum:
		return jsonify({"status": "missing parameters"}), 400

	try:
		password = getPassword(username)

		if password and verifyPassword(passwordCheckSum, password[0]):
			cursor.execute("DELETE FROM watchlist WHERE username = %s", (username,))
			cursor.execute("DELETE FROM continueWatching WHERE username = %s", (username,))
			cursor.execute("DELETE FROM sessions WHERE username = %s", (username,))
			connection.commit()
			return jsonify({"status": "success"})
		else:
			return jsonify({"status": "invalid credentials"}), 403
	except Exception as e:
		return jsonify({"status": "server error"}), 500

@app.route("/wipe", methods=["OPTIONS"])
def wipeOptions():
	return jsonify()

@app.route("/logout", methods=["POST"])
def logout():
		connection = getDbConnection()
		cursor = connection.cursor()
		data = request.get_json()
		username = data.get("username")
		sessionId = data.get("sessionId")
		allSessions = data.get("all", False)  

		if not username or not sessionId and not allSessions:
			return jsonify({"status": "missing parameters"}), 400

		isValidSession = False
		getSessions = cursor.execute("SELECT sessionId FROM sessions WHERE username = %s", (username,))
		results = cursor.fetchall()
		for result in results:
			if result[0] == sessionId:
				isValidSession = True
				break

		if isValidSession:
			try:
				if allSessions:
					query = "DELETE FROM sessions WHERE username = %s"
					cursor.execute(query, (username,))
				else:
					query = "DELETE FROM sessions WHERE username = %s AND sessionId = %s"
					cursor.execute(query, (username, sessionId))
				connection.commit()
				cleanUp(cursor, connection)
				return jsonify({"status": "success"})
			except Exception as e:
				cleanUp(cursor, connection)
				return jsonify({"status": "server error"}), 500
		else:
			cleanUp(cursor, connection)
			return jsonify({"status": "invalid credentials"}), 403

@app.route("/logout", methods=["OPTIONS"])
def logoutOptions():
	return jsonify()

@app.route("/changePassword", methods=["PATCH"])
def changePassword():
	connection = getDbConnection()
	cursor = connection.cursor()
	data = request.get_json()
	username = data.get("username")
	passwordCheckSum = data.get("oldPassword")
	newPassword = hashPassword(data.get("newPassword"))

	if not username or not passwordCheckSum or not newPassword:
		return jsonify({"status": "missing parameters"}), 400

	try:
		password = getPassword(username)

		if password and verifyPassword(passwordCheckSum, password[0]):
			cursor.execute("UPDATE users SET passwordCheckSum = %s WHERE username = %s", (newPassword, username))
			connection.commit()
			return jsonify({"status": "success"})
		else:
			return jsonify({"status": "invalid credentials"}), 403
	except Exception as e:
		return jsonify({"status": "server error"}), 500

@app.route("/changePassword", methods=["OPTIONS"])
def changePasswordOptions():
	return jsonify()

if __name__ == "__main__":
	app.run(host="0.0.0.0", port=8071)