import os
import json
from typing import Dict, List, Optional, Union
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from db import get_db_connection

# Load environment variables
load_dotenv()

class StudentAPI:
    def __init__(self):
        self.app = Flask(__name__)
        self.connection = None
        self.cipher_suite = Fernet(os.getenv("KEY"))
        self.allowed_origins = [
            "https://aptipro-student-frontend.vercel.app",
            "http://localhost:3000"
        ]
        self._configure_app()
        self._register_routes()
        self._register_middlewares()

    def _configure_app(self) -> None:
        """Configure Flask application settings and CORS."""
        CORS(self.app, resources={
            r"/*": {
                "origins": self.allowed_origins,
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"],
                "supports_credentials": True
            }
        })

    def _register_middlewares(self) -> None:
        """Register application middleware functions."""
        self.app.before_request(self._before_request)
        self.app.teardown_request(self._teardown_request)
        self.app.after_request(self._after_request)

    def _register_routes(self) -> None:
        """Register application routes."""
        routes = [
            ("/signup", self.signup, ["POST"]),
            ("/verify", self.verify, ["POST"]),
            ("/login", self.login, ["POST"]),
            ("/tests", self.get_tests, ["GET"]),
            ("/questions", self.get_questions, ["GET"]),
            ("/submit", self.submit_test, ["POST"]),
            ("/results", self.get_results, ["GET"]),
            ("/update_profile", self.update_profile, ["POST"])
        ]
        
        for route, handler, methods in routes:
            self.app.route(route, methods=methods)(handler)

    def _before_request(self) -> None:
        """Establish database connection before each request."""
        self.connection = get_db_connection()

    def _teardown_request(self, exception: Optional[Exception]) -> None:
        """Close database connection after each request."""
        if self.connection:
            self.connection.close()

    def _after_request(self, response) -> None:
        """Add CORS headers to each response."""
        origin = request.headers.get('Origin')
        if origin in self.allowed_origins:
            response.headers.add('Access-Control-Allow-Origin', origin)
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    def encrypt_data(self, data: str) -> bytes:
        """Encrypt sensitive data using Fernet encryption."""
        return self.cipher_suite.encrypt(data.encode())

    def decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt data using Fernet encryption."""
        return self.cipher_suite.decrypt(encrypted_data).decode()

    def _validate_required_fields(self, data: Dict, required_fields: List[str]) -> Optional[Dict]:
        """Validate that all required fields are present in the request data."""
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        if missing_fields:
            return {
                "success": False,
                "message": f"Missing required fields: {', '.join(missing_fields)}"
            }
        return None

    def _generate_response_id(self, test_id: Union[str, int]) -> int:
        """Generate a unique response ID using modular inverse."""
        prime = 1000000007
        try:
            return pow(int(test_id), -1, prime)
        except ValueError:
            raise ValueError("test_id must be an integer")
        except Exception as e:
            raise Exception(f"Error generating response ID: {str(e)}")

    def _calculate_marks(self, responses: List[Dict]) -> int:
        """Calculate total marks from test responses."""
        return sum(1 for item in responses if item["selected_option"] == item["correct_option"])

    def signup(self) -> Dict:
        """Handle student signup requests."""
        try:
            data = request.get_json()
            required_fields = ['id', 'name', 'email', 'password', 'department']
            
            if validation_error := self._validate_required_fields(data, required_fields):
                return jsonify(validation_error), 400

            with self.connection.cursor() as cursor:
                # Check if email or ID already exists
                cursor.execute(
                    "SELECT id FROM students WHERE email = %s OR id = %s", 
                    (data['email'], data['id'])
                )
                if cursor.fetchone():
                    return jsonify({
                        "success": False,
                        "message": "Email or ID already exists"
                    }), 400

                # Validate department exists
                cursor.execute(
                    "SELECT department_name FROM department WHERE department_name = %s", 
                    (data['department'],)
                )
                if not cursor.fetchone():
                    return jsonify({
                        "success": False,
                        "message": "Invalid department"
                    }), 400

                # Create new student account
                encrypted_password = self.encrypt_data(data['password'])
                cursor.execute(
                    """INSERT INTO students 
                    (id, email, name, dept_name, password) 
                    VALUES (%s, %s, %s, %s, %s)""",
                    (data['id'], data['email'], data['name'], 
                     data['department'], encrypted_password)
                )
                self.connection.commit()
                
                return jsonify({
                    "success": True,
                    "message": "Student account created successfully"
                }), 201

        except Exception as e:
            self.connection.rollback()
            self.app.logger.error(f"Signup error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "An error occurred during signup",
                "error": str(e)
            }), 500

    def verify(self) -> Dict:
        """Handle account verification requests."""
        try:
            data = request.get_json()
            
            if not data or 'email' not in data:
                return jsonify({
                    "success": False,
                    "message": "Email is required"
                }), 400

            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT email FROM students WHERE email = %s", 
                    (data['email'],)
                )
                if not cursor.fetchone():
                    return jsonify({
                        "success": False,
                        "message": "Email not found"
                    }), 404

                cursor.execute(
                    "UPDATE students SET verified = 1 WHERE email = %s",
                    (data['email'],)
                )
                self.connection.commit()
                
                return jsonify({
                    "success": True,
                    "message": "Account verified successfully"
                }), 200

        except Exception as e:
            self.connection.rollback()
            self.app.logger.error(f"Verification error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "An error occurred during verification",
                "error": str(e)
            }), 500

    def login(self) -> Dict:
        """Handle student login requests."""
        try:
            data = request.get_json()
            
            if validation_error := self._validate_required_fields(data, ['email', 'password']):
                return jsonify(validation_error), 400

            with self.connection.cursor() as cursor:
                cursor.execute(
                    """SELECT id, email, name, dept_name, password, verified 
                    FROM students WHERE email = %s""",
                    (data['email'],)
                )
                student = cursor.fetchone()
                
                if not student:
                    return jsonify({
                        "success": False,
                        "message": "Invalid email or password"
                    }), 401

                # Verify password
                decrypted_password = self.decrypt_data(student["password"])
                if data['password'] != decrypted_password:
                    return jsonify({
                        "success": False,
                        "message": "Invalid email or password"
                    }), 401

                # Check if account is verified
                if not student["verified"]: 
                    return jsonify({
                        "success": False,
                        "message": "Account not verified. Please check your email."
                    }), 403

                # Get student's subjects
                cursor.execute(
                    "SELECT subject_name FROM subjects WHERE dept_name = %s",
                    (student["dept_name"],)
                )
                subjects = [subject["subject_name"] for subject in cursor.fetchall()]

                # Get student statistics
                cursor.execute(
                    "SELECT COUNT(*) FROM results WHERE student_email = %s",
                    (data['email'],)
                )
                tests_submitted = cursor.fetchone()["COUNT(*)"] or 0

                cursor.execute(
                    "SELECT SUM(marks) FROM results WHERE student_email = %s",
                    (data['email'],)
                )
                total_score = cursor.fetchone()["SUM(marks)"] or 0

                avg_score = (total_score / tests_submitted * 100) if tests_submitted > 0 else 0

                # Get recent results
                cursor.execute(
                    """SELECT * FROM results 
                    WHERE student_email = %s 
                    ORDER BY id DESC LIMIT 10""",
                    (data['email'],)
                )
                recent_results = cursor.fetchall()

                # Prepare response data
                user_data = {
                    "id": student["id"],
                    "email": student["email"],
                    "name": student["name"],
                    "department": student["dept_name"],
                    "verified": student["verified"],
                    "subjects": subjects,
                    "tests_done": tests_submitted,
                    "average_score": round(avg_score, 2),
                    "recent_results": recent_results
                }

                return jsonify({
                    "success": True,
                    "message": "Login successful",
                    "user": user_data
                })

        except Exception as e:
            self.app.logger.error(f"Login error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "An error occurred during login",
                "error": str(e)
            }), 500

    def get_tests(self) -> Dict:
        """Handle requests for department tests."""
        try:
            department = request.args.get('department')
            
            if not department:
                return jsonify({
                    "success": False,
                    "message": "Department is required"
                }), 400

            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM tests WHERE dept_name = %s",
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
            self.app.logger.error(f"Tests fetch error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "An error occurred fetching tests",
                "error": str(e)
            }), 500

    def get_questions(self) -> Dict:
        """Handle requests for MCQ questions."""
        try:
            subject = request.args.get('subject')
            difficulty = request.args.get('difficulty')
            limit = request.args.get('limit')
            
            if not all([subject, difficulty, limit]):
                return jsonify({
                    "success": False,
                    "message": "Subject, difficulty and limit are required"
                }), 400

            with self.connection.cursor() as cursor:
                cursor.execute(
                    """SELECT id, question, optionA, optionB, optionC, optionD, 
                    correct_option, subject, difficulty
                    FROM mcq WHERE subject = %s AND difficulty = %s LIMIT %s""",
                    (subject, difficulty, int(limit))
                )
                questions = cursor.fetchall()
                
                if not questions:
                    return jsonify({
                        "success": False,
                        "message": "No questions found for this criteria"
                    }), 404
                
                return jsonify({
                    "success": True,
                    "mcq": questions
                }), 200

        except Exception as e:
            self.app.logger.error(f"Questions fetch error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "An error occurred fetching questions",
                "error": str(e)
            }), 500

    def submit_test(self) -> Dict:
        """Handle test submission requests."""
        try:
            data = request.get_json()
            required_fields = ['user', 'test', 'responses']
            
            if validation_error := self._validate_required_fields(data, required_fields):
                return jsonify(validation_error), 400

            user = data['user']
            test = data['test']
            responses = data['responses']
            
            response_id = self._generate_response_id(test['id'])
            marks_scored = self._calculate_marks(responses)

            with self.connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO results 
                    (id, name, marks, total_marks, difficulty, subject, 
                     student_email, teacher_email, data, test_id) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (response_id, test['name'], marks_scored, test['marks'], 
                     test['difficulty'], test['subject'], user['email'], 
                     test['teacher'], json.dumps(responses), test['id'])
                )
                self.connection.commit()
                
                return jsonify({
                    "success": True,
                    "message": "Test submitted successfully",
                }), 201

        except Exception as e:
            self.connection.rollback()
            self.app.logger.error(f"Test submission error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "An error occurred during test submission",
                "error": str(e)
            }), 500

    def get_results(self) -> Dict:
        """Handle requests for student results."""
        try:
            email = request.args.get('email')
            
            if not email:
                return jsonify({
                    "success": False,
                    "message": "Email is required"
                }), 400

            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM results WHERE student_email = %s",
                    (email,)
                )
                results = cursor.fetchall()
                
                if not results:
                    return jsonify({
                        "success": False,
                        "message": "No results found"
                    }), 404
                
                return jsonify({
                    "success": True,
                    "results": results
                }), 200

        except Exception as e:
            self.app.logger.error(f"Results fetch error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "An error occurred fetching results",
                "error": str(e)
            }), 500

    def update_profile(self) -> Dict:
        """Handle profile update requests."""
        try:
            data = request.get_json()
            required_fields = ["id", "name", "email", "department", "password"]
            
            if validation_error := self._validate_required_fields(data, required_fields):
                return jsonify(validation_error), 400

            encrypted_password = self.encrypt_data(data['password'])

            with self.connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE students 
                    SET name = %s, email = %s, dept_name = %s, password = %s 
                    WHERE id = %s""",
                    (data['name'], data['email'], data['department'], 
                     encrypted_password, data['id'])
                )
                self.connection.commit()
                
                return jsonify({
                    "success": True,
                    "message": "Profile updated successfully"
                }), 200

        except Exception as e:
            self.connection.rollback()
            self.app.logger.error(f"Profile update error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "An error occurred updating profile",
                "error": str(e)
            }), 500

    def run(self):
        """Run the Flask application."""
        port = int(os.environ.get('PORT', 5000))
        debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
        self.app.run(debug=debug, host='0.0.0.0', port=port)

if __name__ == "__main__":
    api = StudentAPI()
    api.run()