import os
import io
import base64
from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from azure.ai.vision.imageanalysis import ImageAnalysisClient
from azure.core.credentials import AzureKeyCredential
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import click

# --- Basic App Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a-super-secret-key-change-this'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # Increased to 16MB for multiple files

# --- Database Configuration ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'assets.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Login Manager Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to /login if user is not logged in

# --- Azure AI Configuration ---
try:
    AZURE_AI_ENDPOINT = os.environ['AZURE_AI_ENDPOINT']
    AZURE_AI_KEY = os.environ['AZURE_AI_KEY']
except KeyError:
    AZURE_AI_ENDPOINT = "https://lostandfound.cognitiveservices.azure.com/"
    AZURE_AI_KEY = "FLkgjgY0lDmgJzwwMyOL1Rtl9ZzSepMgLePZZCNqRCgcocYhTmveJQQJ99BIACqBBLyXJ3w3AAAFACOGr2c0"


# --- Database Model Definitions ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(80), nullable=False, default='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class LostItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    contact = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Found')
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    images = db.relationship('ItemImage', backref='item', lazy=True, cascade="all, delete-orphan")

class ItemImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_data = db.Column(db.LargeBinary, nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('lost_item.id'), nullable=False)

    def get_b64_image(self):
        return base64.b64encode(self.image_data).decode('utf-8')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- App Routes (Views) ---

@app.route('/')
@login_required
def home():
    """Redirects user based on their role after login."""
    if current_user.role == 'admin':
        return redirect(url_for('index'))
    else:
        return redirect(url_for('mobile_list')) # Updated redirect

@app.route('/admin')
@app.route('/admin/item/<int:item_id>')
@login_required
def index(item_id=None):
    """Admin dashboard: the original two-column layout."""
    if current_user.role != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('mobile_list'))
    
    items = LostItem.query.order_by(LostItem.created_at.desc()).all()
    selected_item = None
    if item_id:
        selected_item = LostItem.query.get(item_id)
    return render_template('index.html', items=items, selected_item=selected_item)

@app.route('/mobile')
@login_required
def mobile_list():
    """The main list view for mobile users."""
    items = LostItem.query.order_by(LostItem.created_at.desc()).all()
    return render_template('mobile_list.html', items=items)

@app.route('/mobile/item/<int:item_id>')
@login_required
def mobile_detail(item_id):
    """The detail view for a single item for mobile users."""
    item = LostItem.query.get_or_404(item_id)
    return render_template('mobile_detail.html', item=item)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user is None or not user.check_password(request.form['password']):
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/analyze', methods=['POST'])
@login_required
def analyze_image():
    title = request.form['title']
    location = request.form['location']
    contact = request.form['contact']
    status = request.form['status']
    files = request.files.getlist('file')

    if not files or files[0].filename == '':
        flash('At least one image is required.', 'danger')
        return redirect(url_for('index'))
    try:
        first_image_bytes = files[0].read()
        client = ImageAnalysisClient(endpoint=AZURE_AI_ENDPOINT, credential=AzureKeyCredential(AZURE_AI_KEY))
        result = client.analyze(image_data=first_image_bytes, visual_features=['DenseCaptions', 'Tags', 'Read'])
        
        description_parts = []
        if result.dense_captions is not None:
            description_parts.append(result.dense_captions.list[0].text.capitalize() + ".")
        if result.tags is not None:
            top_tags = [tag.name for tag in result.tags.list if tag.confidence > 0.7]
            if top_tags:
                description_parts.append("Features: " + ", ".join(top_tags) + ".")
        if result.read is not None:
            found_text = " ".join([line.text for block in result.read.blocks for line in block.lines])
            if found_text:
                description_parts.append("Visible text: '" + found_text + "'.")
        
        ai_description = " ".join(description_parts) if description_parts else "No detailed description generated."

        new_item = LostItem(title=title, description=ai_description, location=location, contact=contact, status=status)
        db.session.add(new_item)
        db.session.commit()

        for file in files:
            file.seek(0)
            image_bytes = file.read()
            new_image = ItemImage(image_data=image_bytes, item_id=new_item.id)
            db.session.add(new_image)
        db.session.commit()
        flash('New item added successfully!', 'success')
        return redirect(url_for('index', item_id=new_item.id))
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {e}', 'danger')
        return redirect(url_for('index'))

# --- CLI Commands ---
@app.cli.command('init-db')
def init_db_command():
    """Creates the database tables."""
    with app.app.app_context():
        db.create_all()
    print('Initialized the database.')

@app.cli.command('create-admin')
def create_admin_command():
    """Creates a default admin user."""
    with app.app.app_context():
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', role='admin')
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
            print('Admin user created with username "admin" and password "admin".')
        else:
            print('Admin user already exists.')

@app.cli.command('create-user')
@click.argument('username')
@click.argument('password')
def create_user_command(username, password):
    """Creates a regular user for the mobile view."""
    with app.app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username, role='user')
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            print(f'User "{username}" created successfully.')
        else:
            print(f'User "{username}" already exists.')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')