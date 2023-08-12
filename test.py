import unittest
from app import app, db, bcrypt
from models import User, Feedback

class UserTests(unittest.TestCase):
    
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()

        self.client = app.test_client()
        app.config['TESTING'] = True

        app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///users_test"
        db.create_all()
        
        hashed_pwd = bcrypt.generate_password_hash('samplepass').decode('utf-8')
        user = User(username="sampleuser", password=hashed_pwd, email="sample@sample.com", first_name="Sample", last_name="User")
        db.session.add(user)
        db.session.commit()
        
    def tearDown(self):
        db.session.close()
        db.drop_all()
        self.app_context.pop()

    def test_homepage(self):
        response = self.client.get('/')
        self.assertIn(b'Welcome', response.data)
        
    def test_successful_user_registration(self):
        data = {
            'username': 'testuser',
            'password': 'testpass',
            'email': 'test@test.com',
            'first_name': 'Test',
            'last_name': 'User'
        }
        response = self.client.post('/register', data=data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)  # Now this is after following the redirect
        user = User.query.filter_by(username='testuser').first()
        self.assertIsNotNone(user)


    def test_successful_login(self):
        data = {
            'username': 'sampleuser',
            'password': 'samplepass'
        }
        response = self.client.post('/login', data=data)
        self.assertEqual(response.status_code, 200)

if __name__ == "__main__":
    unittest.main()
