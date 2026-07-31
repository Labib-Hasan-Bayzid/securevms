from flask import Flask, render_template, request, redirect, flash, session
import mysql.connector
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import hashlib

app = Flask(__name__)
app.secret_key = 'your-very-secret-key-change-this-in-production'

# Configuration
UPLOAD_FOLDER = '/app/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt', 'doc', 'docx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    """Get database connection"""
    try:
        conn = mysql.connector.connect(
            host='db',
            user='user',
            password='password',
            database='securevms'
        )
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def init_db():
    """Create tables if they don't exist"""
    conn = get_db()
    if conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role ENUM('internal', 'external') DEFAULT 'external',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                severity ENUM('Critical', 'High', 'Medium', 'Low') DEFAULT 'Medium',
                status ENUM('New', 'Assigned', 'Fixed', 'Verified', 'Closed') DEFAULT 'New',
                reported_by INT,
                assigned_to INT,
                file_name VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (reported_by) REFERENCES users(id),
                FOREIGN KEY (assigned_to) REFERENCES users(id)
            )
        ''')
        
        # Audit trail
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_trail (
                id INT AUTO_INCREMENT PRIMARY KEY,
                vulnerability_id INT,
                action VARCHAR(100),
                performed_by INT,
                notes TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id),
                FOREIGN KEY (performed_by) REFERENCES users(id)
            )
        ''')
        
        conn.commit()
        cursor.close()
        conn.close()

# --------------- AUTHENTICATION ---------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    # If already logged in, go to dashboard
    if 'user_id' in session:
        return redirect('/vulnerabilities')
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db()
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and user['password'] == password:
                # Login successful
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['user_email'] = user['email']
                session['user_role'] = user['role']
                
                flash(f'Welcome back, {user["name"]}!', 'success')
                return redirect('/vulnerabilities')
            else:
                flash('Invalid email or password!', 'danger')
        else:
            flash('Database connection error!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect('/')

# --------------- ROUTES ---------------

@app.route('/')
def index():
    """Homepage"""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register user - both internal and external"""
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        conn = get_db()
        if conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    'INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)',
                    (name, email, password, role)
                )
                conn.commit()
                flash('Registration successful! Please login.', 'success')
                return redirect('/login')
            except mysql.connector.IntegrityError:
                flash('Email already registered! Please use a different email.', 'danger')
            finally:
                cursor.close()
                conn.close()
        else:
            flash('Database connection error!', 'danger')
    
    return render_template('register.html')

@app.route('/report', methods=['GET', 'POST'])
def report():
    """Report vulnerability - for external consultants"""
    # CHECK: User must be logged in
    if 'user_id' not in session:
        flash('Please login to report vulnerabilities.', 'warning')
        return redirect('/login')
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        severity = request.form.get('severity')
        
        # Get user ID from session
        user_id = session['user_id']
        
        # Handle file upload
        file = request.files.get('file')
        filename = None
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        conn = get_db()
        if conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    '''INSERT INTO vulnerabilities 
                       (title, description, severity, reported_by, file_name, status) 
                       VALUES (%s, %s, %s, %s, %s, 'New')''',
                    (title, description, severity, user_id, filename)
                )
                vuln_id = cursor.lastrowid
                
                # Add to audit trail
                cursor.execute(
                    'INSERT INTO audit_trail (vulnerability_id, action, performed_by, notes) VALUES (%s, %s, %s, %s)',
                    (vuln_id, 'Reported', user_id, f'Vulnerability reported by {session["user_name"]}')
                )
                
                conn.commit()
                flash('Vulnerability reported successfully! Internal team notified.', 'success')
            except Exception as e:
                flash(f'Error: {str(e)}', 'danger')
            finally:
                cursor.close()
                conn.close()
        else:
            flash('Database connection error!', 'danger')
        
        return redirect('/vulnerabilities')
    
    return render_template('report.html')

@app.route('/vulnerabilities')
def list_vulnerabilities():
    """View all reported vulnerabilities"""
    # CHECK: User must be logged in
    if 'user_id' not in session:
        flash('Please login to view vulnerabilities.', 'warning')
        return redirect('/login')
    
    conn = get_db()
    vulnerabilities = []
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT v.*, u.name as reported_by_name 
            FROM vulnerabilities v
            LEFT JOIN users u ON v.reported_by = u.id
            ORDER BY 
                CASE severity 
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                END,
                v.created_at DESC
        ''')
        vulnerabilities = cursor.fetchall()
        cursor.close()
        conn.close()
    
    return render_template('vulnerabilities.html', vulnerabilities=vulnerabilities, session=session)

@app.route('/update_status/<int:vuln_id>', methods=['POST'])
def update_status(vuln_id):
    """Update vulnerability status - ONLY for Internal Engineers"""
    # CHECK: User must be logged in
    if 'user_id' not in session:
        flash('Please login first.', 'warning')
        return redirect('/login')
    
    # CHECK: User must be INTERNAL ENGINEER
    if session.get('user_role') != 'internal':
        flash('⚠️ Only Internal Engineers can update vulnerability status!', 'danger')
        return redirect('/vulnerabilities')
    
    status = request.form.get('status')
    user_id = session['user_id']
    user_name = session.get('user_name', 'Unknown')
    
    conn = get_db()
    if conn:
        cursor = conn.cursor()
        
        # Update status
        cursor.execute(
            'UPDATE vulnerabilities SET status = %s WHERE id = %s',
            (status, vuln_id)
        )
        
        # Audit trail
        cursor.execute(
            'INSERT INTO audit_trail (vulnerability_id, action, performed_by, notes) VALUES (%s, %s, %s, %s)',
            (vuln_id, f'Status changed to {status}', user_id, f'Changed by {user_name}')
        )
        
        conn.commit()
        cursor.close()
        conn.close()
        flash(f'✅ Status updated to "{status}" by {user_name}', 'success')
    
    return redirect('/vulnerabilities')

@app.route('/profile')
def profile():
    """Show user profile"""
    if 'user_id' not in session:
        flash('Please login to view profile.', 'warning')
        return redirect('/login')
    
    return render_template('profile.html', session=session)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)