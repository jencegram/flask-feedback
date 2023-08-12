from models import User, db, connect_db, Feedback
from flask import Flask, render_template, redirect, flash, session, url_for
from flask_bcrypt import Bcrypt
from forms import RegisterForm, LoginForm, FeedbackForm
from flask_debugtoolbar import DebugToolbarExtension


app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = '5300749'

# Configurations
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///users"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True  
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

toolbar = DebugToolbarExtension(app)

# Connect the app to the database
connect_db(app)

# Create database tables
with app.app_context():
    db.create_all()
    
@app.route('/')
def home():
    """Display homepage."""
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user."""
    form = RegisterForm()
    
    if form.validate_on_submit():
        # Get form data
        username = form.username.data
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')  # Hashing the password
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        
        # Create user and add to database
        new_user = User(username=username, password=password, email=email, first_name=first_name, last_name=last_name)
        db.session.add(new_user)
        db.session.commit()

        # Add username to session
        session["username"] = username
        
        flash('User registered successfully!', 'success')
        return redirect(f'/users/{username}')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    form = LoginForm()
    
    if form.validate_on_submit():
        # Check for user and authenticate
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):  # Comparing hashed password
            # Add username to session
            session["username"] = user.username
            flash('Logged in successfully!', 'success')
            return redirect(f'/users/{user.username}')
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/users/<username>')
def user_info(username):
    """Show user profile and feedback."""
    if "username" not in session or session["username"] != username:
        flash("Access denied!", "danger")
        return redirect('/login')
    
    user = User.query.get_or_404(username)
    feedbacks = Feedback.query.filter_by(username=username).all()

    return render_template('user_info.html', user=user, feedbacks=feedbacks)

@app.route('/logout')
def logout():
    """Log out the user."""
    session.pop("username", None)  # Providing a default of None in case "username" doesn't exist in the session
    flash("You've been logged out.", "success")
    return redirect(url_for('home'))

@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    """Delete the specified user."""
    if "username" not in session or session["username"] != username:
        flash("Access denied!", "danger")
        return redirect('/login')

    user = User.query.get_or_404(username)
    db.session.delete(user)
    db.session.commit()

    session.pop("username")
    flash("Account deleted!", "success")
    return redirect('/')

@app.route('/users/<username>/feedback/add', methods=['GET'])
def add_feedback_form(username):
    """Displaying feedback form"""
    if "username" not in session or session["username"] != username:
        flash("Access denied!", "danger")
        return redirect('/login')
    
    form = FeedbackForm()
    return render_template('add_feedback.html', form=form)

@app.route('/users/<username>/feedback/add', methods=['POST'])
def add_feedback(username):
    """Add a new feedback."""
    if "username" not in session or session["username"] != username:
        flash("Access denied!", "danger")
        return redirect('/login')
    
    form = FeedbackForm()
    if form.validate_on_submit():
        feedback = Feedback(title=form.title.data, content=form.content.data, username=username)
        db.session.add(feedback)
        db.session.commit()
        flash("Feedback added!", "success")
        return redirect(f'/users/{username}')

    return render_template('add_feedback.html', form=form)

@app.route('/feedback/<int:feedback_id>/update', methods=['GET'])
def edit_feedback_form(feedback_id):
    """Display edit feedback form."""
    feedback = Feedback.query.get_or_404(feedback_id)

    if "username" not in session or session["username"] != feedback.username:
        flash("Access denied!", "danger")
        return redirect('/login')

    form = FeedbackForm(obj=feedback)
    return render_template('edit_feedback.html', form=form, feedback_id=feedback_id)

@app.route('/feedback/<int:feedback_id>/update', methods=['POST'])
def edit_feedback(feedback_id):
    """Update a feedback."""
    feedback = Feedback.query.get_or_404(feedback_id)

    if "username" not in session or session["username"] != feedback.username:
        flash("Access denied!", "danger")
        return redirect('/login')

    form = FeedbackForm()
    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()
        flash("Feedback updated!", "success")
        return redirect(f'/users/{feedback.username}')

    return render_template('edit_feedback.html', form=form, feedback_id=feedback_id)

@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    """Delete the specified feedback."""
    feedback = Feedback.query.get_or_404(feedback_id)

    if "username" not in session or session["username"] != feedback.username:
        flash("Access denied!", "danger")
        return redirect('/login')

    db.session.delete(feedback)
    db.session.commit()
    flash("Feedback deleted!", "success")
    return redirect(f'/users/{feedback.username}')

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 error page."""
    return render_template('404.html'), 404


if __name__ == "__main__":
    app.run(debug=True)