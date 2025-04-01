from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from db import get_db_connection
import json
from dotenv import load_dotenv
from cryptography.fernet import Fernet

app = Flask(__name__)
CORS(app)

load_dotenv()
key = os.getenv("KEY")

@app.before_request
def before_request():
    global connection
    connection = get_db_connection()

@app.teardown_request
def teardown_request(exception):
    global connection
    if connection:
        connection.close()

def encrypt_data(data):
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    return encrypted_data 

def decrypt_data(encrypted_data):
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
    return decrypted_data

def get_response_id(test_id):
    prime = 1000000007  
    try:
        test_id = int(test_id)
        response_id = pow(test_id, -1, prime)  
        return response_id
    except ValueError:
        raise ValueError("test_id must be an integer")
    except Exception as e:
        raise Exception(f"An error occurred while calculating response_id: {str(e)}")

def calculate_marks(response):
    marks = 0
    for item in response:
        if item["selected_option"] == item["correct_option"]:
            marks += 1
    return marks

@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json()
        required_fields = ['id', 'name', 'email', 'password', 'department']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"success": False, "message": f"{field} is required"}), 400
        encrypted_password = encrypt_data(data['password'])
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM students WHERE email = %s", (data['email'],))
            if cursor.fetchone():
                return jsonify({"success": False, "message": "Email already exists"}), 400
            cursor.execute("SELECT id FROM students WHERE id = %s", (data['id'],))
            if cursor.fetchone():
                return jsonify({"success": False, "message": "ID already exists"}), 400
            cursor.execute("SELECT department_name FROM department WHERE department_name = %s", 
                          (data['department'],))
            if not cursor.fetchone():
                return jsonify({"success": False, "message": "Invalid department"}), 400
            cursor.execute(
                """INSERT INTO students 
                (id, email, name, dept_name, password) 
                VALUES (%s, %s, %s, %s, %s)""",
                (data['id'], data['email'], data['name'], 
                 data['department'], encrypted_password)
            )
            connection.commit()
            return jsonify({
                "success": True,
                "message": "student account created successfully"
            }), 201 
    except Exception as e:
        connection.rollback()
        return jsonify({
            "success": False,
            "message": "An error occurred during signup",
            "error": str(e)
        }), 500

@app.route("/verify", methods=["POST"])
def verify():
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({"success": False, "message": "Email is required"}), 400
        email = data['email']
        with connection.cursor() as cursor:
            cursor.execute("SELECT email FROM students WHERE email = %s", (email,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Email not found"
                }), 404
            cursor.execute(
                "UPDATE students SET verified = 1 WHERE email = %s",
                (email,)
            )
            connection.commit()
            return jsonify({
                "success": True,
                "message": "Account verified successfully"
            }), 200   
    except Exception as e:
        connection.rollback()
        return jsonify({
            "success": False,
            "message": "An error occurred during verification",
            "error": str(e)
        }), 500

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"success": False, "message": "Email and password are required"}), 400
        email = data['email']
        password = data['password']
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT id, email, name, dept_name, password, verified 
                FROM students WHERE email = %s""",
                (email,)
            )
            student = cursor.fetchone()
            if not student:
                return jsonify({
                    "success": False,
                    "message": "Invalid email or password"
                }), 401
            stored_password = student["password"]  
            decrypted_password = decrypt_data(stored_password)
            if password != decrypted_password:
                return jsonify({
                    "success": False,
                    "message": "Invalid email or password"
                }), 401
            if not student["verified"]: 
                return jsonify({
                    "success": False,
                    "message": "Account not verified. Please check your email."
                }), 403
            cursor.execute(
                "SELECT subject_name FROM subjects WHERE dept_name = %s",
                (student["dept_name"],)
            )
            subjects = cursor.fetchall()
            subjects_list = [subject["subject_name"] for subject in subjects]
            cursor.execute(
                """SELECT COUNT(*) FROM results WHERE student_email = %s""",
                (email, )
            )
            tests_submitted = cursor.fetchone()["COUNT(*)"]
            cursor.execute(
                """SELECT SUM(marks) FROM results WHERE student_email = %s""",
                (email, )
            )
            total_score = cursor.fetchone()["SUM(marks)"]
            avg_score = (total_score / tests_submitted) * 100
            user_data = {
                "id": student["id"],
                "email": student["email"],
                "name": student["name"],
                "department": student["dept_name"],
                "verified": student["verified"],
                "subjects": subjects_list,
                "tests_done": tests_submitted,
                "average_score": avg_score
            }
            return jsonify({
                "success": True,
                "message": "Login successful",
                "user": user_data
            })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "An error occurred during login",
            "error": str(e)
        }), 500

@app.route("/tests", methods=["GET"])
def get_tests():
    try:
        data = request.args
        if 'department' not in data:
            return jsonify({"success": False, "message": "Department is required"}), 400
        department = data['department']
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT *
                FROM tests WHERE dept_name = %s""",
                (department,)
            )
            tests = cursor.fetchall()
            if not tests:
                return jsonify({
                    "success": False,
                    "message": "No tests found for this department"
                }), 404
            return jsonify({
                "success": True,
                "tests": tests
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "An error occurred fetching tests",
            "error": str(e)
        }), 500

@app.route("/questions", methods=["GET"])
def get_questions():
    try:
        data = request.args
        if 'subject' not in data or 'difficulty' not in data or 'limit' not in data:
            return jsonify({"success": False, "message": "Subject and difficulty are required"}), 400
        subject = data['subject']
        difficulty = data['difficulty']
        count = int(data['limit'])
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT id, question, optionA, optionB, optionC, optionD, correct_option, subject, difficulty
                FROM mcq WHERE subject = %s AND difficulty = %s LIMIT %s""",
                (subject, difficulty, count)
            )
            questions = cursor.fetchall()
            if not questions:
                return jsonify({
                    "success": False,
                    "message": "No questions found for this subject and difficulty"
                }), 404
            return jsonify({
                "success": True,
                "mcq": questions
            }), 200
    except Exception as e:
        print(str(e))
        return jsonify({
            "success": False,
            "message": "An error occurred fetching questions",
            "error": str(e)
        }), 500

@app.route("/submit", methods=["POST"])
def submit_test():
    try:
        data = request.get_json()
        if not 'user' in data:
            return jsonify({"success": False, "message": "User data is required"}), 400
        if not 'test' in data:
            return jsonify({"success": False, "message": "Test data is required"}), 400
        if not 'responses' in data:
            return jsonify({"success": False, "message": "Response is required"}), 400
        user = data['user']
        test = data['test']
        response = data['responses']
        response_id = get_response_id(test['id'])
        marks_scored = calculate_marks(response)
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO results 
                (id, name, marks, total_marks, difficulty, subject, student_email, teacher_email, data, test_id) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (response_id, test['name'], marks_scored, test['marks'], test['difficulty'],
                 test['subject'], user['email'], test['teacher'], json.dumps(response), test['id'])
            )
            connection.commit()
            return jsonify({
                "success": True,
                "message": "Test submitted successfully",
            }), 201
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "An error occurred during test submission",
            "error": str(e)
        }), 500

@app.route("/results", methods=["GET"])
def get_results():
    try:
        data = request.args
        if not 'email' in data:
            return jsonify({"success": False, "message": "Email is required"}), 400
        email = data['email']
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT * FROM results WHERE student_email = %s""",
                (email,)
            )
            results = cursor.fetchall()
            if not results:
                return jsonify({
                    "success": False,
                    "message": "No results found for this email"
                }), 404
            return jsonify({
                "success": True,
                "results": results
            }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "An error occurred fetching results",
            "error": str(e)
        }), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)