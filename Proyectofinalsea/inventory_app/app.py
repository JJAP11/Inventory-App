from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelos
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    categories = db.relationship('Category', backref='user', lazy=True, cascade='all, delete-orphan')
    items = db.relationship('Item', backref='user', lazy=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(250))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    items = db.relationship('Item', backref='category', lazy=True, cascade='all, delete-orphan')

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(250))
    quantity = db.Column(db.Integer, nullable=False, default=0)
    price = db.Column(db.Float, nullable=False, default=0.0)
    date_added = db.Column(db.DateTime, default=db.func.current_timestamp())
    date_modified = db.Column(db.DateTime, onupdate=db.func.current_timestamp())
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Rutas
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def inventory():
    query = request.args.get('query')
    if query:
        categories = Category.query.filter(Category.name.contains(query), Category.user_id == current_user.id).all()
        items = Item.query.filter(Item.name.contains(query), Item.user_id == current_user.id).all()
    else:
        categories = Category.query.filter_by(user_id=current_user.id).all()
        items = Item.query.filter_by(user_id=current_user.id).all()
    return render_template('inventory.html', categories=categories, items=items, query=query)

@app.route('/category/<int:category_id>')
@login_required
def category(category_id):
    category = Category.query.get_or_404(category_id)
    items = Item.query.filter_by(category_id=category.id, user_id=current_user.id).all()
    return render_template('category.html', category=category, items=items)

@app.route('/add_category', methods=['GET', 'POST'])
@login_required
def add_category():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        new_category = Category(name=name, description=description, user_id=current_user.id)
        db.session.add(new_category)
        db.session.commit()
        flash('Category added successfully!', 'success')
        return redirect(url_for('inventory'))
    return render_template('add_category.html')

@app.route('/edit_category/<int:category_id>', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    category = Category.query.get_or_404(category_id)
    if request.method == 'POST':
        category.name = request.form['name']
        category.description = request.form['description']
        db.session.commit()
        flash('Category updated successfully!', 'success')
        return redirect(url_for('category', category_id=category.id))
    return render_template('edit_category.html', category=category)

@app.route('/delete_category/<int:category_id>')
@login_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()
    flash('Category deleted successfully!', 'success')
    return redirect(url_for('inventory'))

@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        quantity = request.form['quantity']
        price = request.form['price']
        category_id = request.form['category']
        new_item = Item(name=name, description=description, quantity=quantity, price=price, category_id=category_id, user_id=current_user.id)
        db.session.add(new_item)
        db.session.commit()
        flash('Item added successfully!', 'success')
        return redirect(url_for('inventory'))
    categories = Category.query.filter_by(user_id=current_user.id).all()
    return render_template('add_item.html', categories=categories)

@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    if request.method == 'POST':
        item.name = request.form['name']
        item.description = request.form['description']
        item.quantity = request.form['quantity']
        item.price = request.form['price']
        item.category_id = request.form['category']
        db.session.commit()
        flash('Item updated successfully!', 'success')
        return redirect(url_for('inventory'))
    categories = Category.query.filter_by(user_id=current_user.id).all()
    return render_template('edit_item.html', item=item, categories=categories)

@app.route('/delete_item/<int:item_id>')
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash('Item deleted successfully!', 'success')
    return redirect(url_for('inventory'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('inventory'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates database tables
    app.run(host='0.0.0.0', port=5000, debug=True)
