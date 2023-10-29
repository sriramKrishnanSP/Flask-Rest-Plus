# from flask import Response
from flask import Flask, request, render_template, url_for, redirect, flash, session, g, jsonify
import werkzeug, flask.scaffold
werkzeug.cached_property = werkzeug.utils.cached_property
flask.helpers._endpoint_from_view_func = flask.scaffold._endpoint_from_view_func
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restplus import Api, Resource, fields
from datetime import datetime
# from flask_restplus import ValidationError
import jwt,os,re,json,uuid, sqlite3, requests
# from flask_jwt_extended import jwt_required
from datetime import timedelta


app = Flask(__name__)
api = Api(app, version='1.0', title='Todo API', description='A simple Todo API')
app.secret_key=os.urandom(24)

# SQLite database initialization for TO_DO Task
conn = sqlite3.connect('todo.db')
conn.execute('''
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task text NOT NULL,
        due_date DATE NOT NULL,
        status text NOT NULL
    )
''')
conn.commit()
conn.close()


# SQLite database initialization for User registration
conn = sqlite3.connect('users.db')
conn.execute('''
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(50) NOT NULL,
    user_role BOOLEAN, 
    token TEXT NULL
    )
''')
conn.commit()
conn.close()


# Model for task
task_model = api.model('Task', {
    'id': fields.Integer(readonly=True, description='The task unique identifier'),
    'task': fields.String(required=True, description='The task details'),
    'due_date': fields.Date(description='Due date of the task (format: yyyy-mm-dd)'),
    'status': fields.String(required=True, description='Task status: Not started, In progress, Finished')
})

tasks = api.namespace('tasks', description='Task operations')

def session_expiration_time():
    expiration_time = timedelta(seconds=50000)
    return expiration_time

def get_current_user():
    user=None
    if 'user' in session:
        user=session['user']
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username=?', (user,))
        user=cursor.fetchone()
    return user



# ---------------------------  Flask Rest Plus View for GET AND POST --------------------------- 
def validate_auth_token(auth_token):
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    res=cursor.execute('SELECT * FROM users where token=?',(auth_token,))
    user_data = res.fetchone()
    print("User data:", user_data)
    # print("res:",res)
    print("current token:",auth_token)
    if user_data:
        return True
    else:
        return False

@tasks.route('/')
class TaskList(Resource):
    @api.doc('list_tasks')
    @api.marshal_list_with(task_model)
    def get(self):
        auth_token = request.headers.get('Authorization')
        token_validate=validate_auth_token(auth_token)
        print("token_validate:",token_validate)
        if token_validate:
            '''List all tasks'''
            conn = sqlite3.connect('todo.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM tasks')
            tasks = cursor.fetchall()
            tasks_list = [{
                "id": row[0],
                "task": row[1],
                'due_date': datetime.strptime(row[2], '%Y-%m-%d').strftime('%Y-%m-%d'),
                "status": row[3]
            } for row in tasks]
            conn.commit()
            conn.close()
            return tasks_list, 200
        else:
            api.abort(401, ' Authorization Token Error - Login again.')
            return {"message":" Authorization Token Error - Login again."}
        

    @api.doc('create_task')
    @api.expect(task_model)
    @api.response(201, 'Task successfully created')
    def post(self):
        '''Create a new task'''
        auth_token = request.headers.get('Authorization')
       
        token_validate=validate_auth_token(auth_token)
        if token_validate:
            data = request.get_json()  

            required_keys = ['task', 'due_date', 'status']
            if all(key in data for key in required_keys):
                conn = sqlite3.connect('todo.db')
                cursor = conn.cursor()

                valid_statuses = ['Not started'.capitalize().strip(), 'In progress'.capitalize().strip(), 'Finished'.capitalize().strip()]
                if len(data['task'].capitalize().strip())==0:
                    api.abort(400, 'Invalid task. Please provide some task')

                regex = r'^\d{4}-\d{2}-\d{2}$'
                match = re.match(regex, data['due_date'])
                print("match:",match)
                if match==None:
                    api.abort(400, 'Pass Valid date as format of "YYYY-MM-DD')
                    return {"message":"Pass Valid date as format of YYYY-MM-DD"}
                
                if data['status'].capitalize().strip() not in valid_statuses:
                    api.abort(400, 'Invalid task status. Please provide one of these: Not started, In progress, Finished')

                cursor.execute('INSERT INTO tasks (task, due_date, status) VALUES (?, ?, ?)',
                            (data['task'].capitalize(), data.get('due_date'), data['status'].capitalize()))
                conn.commit()
                task_id = cursor.lastrowid
                conn.close()
                return {'id': task_id}, 201
            else:
                api.abort(400, 'Please make sure to provide proper key in the payload - task, due_date, status')
        else:
            api.abort(401, ' Authorization Token Error - Login again.')
            return {"message":" Authorization Token Error - Login again."}

    

@tasks.route('/<int:task_id>')
@api.response(404, 'Task not found')
class Task(Resource):
    @api.doc('update_task')
    @api.expect(task_model)
    @api.response(204, 'Task successfully updated')
    def put(self, task_id):
        '''Update a task'''
        auth_token = request.headers.get('Authorization')
        token_validate=validate_auth_token(auth_token)
        if token_validate:
            print("token_validate:",token_validate)
            data = request.get_json()

            required_keys = ['task', 'due_date', 'status']
            if all(key in data for key in required_keys):
                valid_statuses = ['Not started'.capitalize().strip(), 'In progress'.capitalize().strip(), 'Finished'.capitalize().strip()]

                if len(data['task'].capitalize().strip())==0:
                    api.abort(400, 'Invalid task. Please provide some task')

                regex = r'^\d{4}-\d{2}-\d{2}$'
                match = re.match(regex, data['due_date'])
                print("match:",match)
                if match==None:
                    api.abort(400, 'Pass Valid date as format of "YYYY-MM-DD')
                    return {"message":"Pass Valid date as format of YYYY-MM-DD"}
                
                if data['status'].capitalize().strip() not in valid_statuses:
                    api.abort(400, 'Invalid task status. Please provide one of these: Not started, In progress, Finished')

                conn = sqlite3.connect('todo.db')
                cursor = conn.cursor()
                cursor.execute('UPDATE tasks SET task=?, due_date=?, status=? WHERE id=?',
                            (data['task'].capitalize(), data.get('due_date'), data['status'].capitalize(), task_id))
                conn.commit()
                conn.close()
                return {'id': task_id}, 200
            else:
                api.abort(400, 'Please make sure to provide proper key in the payload - task, due_date, status')
        else:
            api.abort(401, ' Authorization Token Error - Login again.')
            return {"message":" Authorization Token Error - Login again."}


    @api.doc('delete_task')
    @api.response(204, 'Task successfully deleted')
    def delete(self, task_id):
        '''Delete a task'''
        auth_token = request.headers.get('Authorization')
        token_validate=validate_auth_token(auth_token)
        if token_validate:
            conn = sqlite3.connect('todo.db')
            cursor = conn.cursor()
            cursor.execute('DELETE FROM tasks WHERE id=?', (task_id,))
            conn.commit()
            conn.close()
            return {'Deleted task id': task_id}, 200
        else:
            api.abort(401, ' Authorization Token Error - Login again.')
            return {"message":" Authorization Token Error - Login again."}
        
        
@tasks.route('/due')
class DueTasks(Resource):
    @api.doc('get_due_tasks')
    @api.marshal_list_with(task_model)
    def get(self):
        auth_token = request.headers.get('Authorization')
        token_validate=validate_auth_token(auth_token)
        if token_validate:
            print("Get tasks due on a specific date")
            '''Get tasks due on a specific date'''
            due_date = request.args.get('due_date')
            if not due_date:
                api.abort(400, 'Pass Valid date as format of "YYYY-MM-DD')
                return {"message":"Pass Valid date as format of YYYY-MM-DD"}
            
            regex = r'^\d{4}-\d{2}-\d{2}$'
            match = re.match(regex, due_date)
            print("match:",match)
            if match==None:
                api.abort(400, 'Pass Valid date as format of "YYYY-MM-DD')
                return {"message":"Pass Valid date as format of YYYY-MM-DD"}

            
            due_date = datetime.strptime(due_date, '%Y-%m-%d').date()

            conn = sqlite3.connect('todo.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM tasks WHERE due_date=?', (due_date,))
            tasks = cursor.fetchall()

            tasks_date_list = [{
                "id": row[0],
                "task": row[1],
                'due_date': datetime.strptime(row[2], '%Y-%m-%d').strftime('%Y-%m-%d'),
                "status": row[3]
            } for row in tasks]
            conn.commit()
            conn.close()
            print("tasks_list in due date:",tasks_date_list)
       
            return  tasks_date_list, 200
        else:
            api.abort(401, ' Authorization Token Error - Login again.')
            return {"message":" Authorization Token Error - Login again."}

@tasks.route('/overdue')
class OverdueTasks(Resource):
    @api.doc('get_overdue_tasks')
    @api.marshal_list_with(task_model)
    def get(self):
        '''Get overdue tasks'''
        auth_token = request.headers.get('Authorization')
        token_validate=validate_auth_token(auth_token)
        if token_validate:
            current_today = datetime.today()

            conn = sqlite3.connect('todo.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM tasks WHERE due_date < ? AND status != "Finished"', (current_today,))
            tasks = cursor.fetchall()
            # conn.close()
            # return tasks
        
            tasks_list = [{
                "id": row[0],
                "task": row[1],
                'due_date': datetime.strptime(row[2], '%Y-%m-%d').strftime('%Y-%m-%d'),
                # 'due_date': row[2],

                "status": row[3]
            } for row in tasks]
            conn.commit()
            conn.close()
            print("overdue tasks_list:",tasks_list)
            return tasks_list, 200
        else:
            api.abort(401, ' Authorization Token Error - Login again.')
            return {"message":" Authorization Token Error - Login again."}



@tasks.route('/finished')
class FinishedTasks(Resource):
    @api.doc('get_finished_tasks')
    @api.marshal_list_with(task_model)
    def get(self):
        '''Get finished tasks'''
        auth_token = request.headers.get('Authorization')
        token_validate=validate_auth_token(auth_token)
        if token_validate:
            conn = sqlite3.connect('todo.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM tasks WHERE status="Finished"')
            tasks = cursor.fetchall()
            tasks_list = [{
                "id": row[0],
                "task": row[1],
                'due_date': datetime.strptime(row[2], '%Y-%m-%d').strftime('%Y-%m-%d'),
                # 'due_date': row[2],

                "status": row[3]
            } for row in tasks]
            conn.commit()
            conn.close()
            print("overdue tasks_list:",tasks_list)
            return tasks_list, 200
        else:
            api.abort(401, ' Authorization Token Error - Login again.')
            return {"message":" Authorization Token Error - Login again."}





# ___________________________ To Log In & Log Out ______________________________

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        # Handle form data (HTML forms) or JSON request (API requests)
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            admin_bool = data.get('user_role')
        else:
            username = request.form['username']
            password = request.form['password']
            admin_bool = request.form['user_role']
        
        hashed_pass = generate_password_hash(password, method='sha256')
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        check_existing_user = cursor.fetchone()
        
        if check_existing_user:
            if request.is_json:
                return jsonify({'error': 'Username already taken.'}), 400
            else:
                return render_template('register.html', error='Username already taken.')
        
        cursor.execute('INSERT INTO users (username, password, user_role) VALUES (?, ?, ?)',
                       (username, hashed_pass, admin_bool))
        conn.commit()
        
        if request.is_json:
            return jsonify({'message': 'User added successfully.'}), 201
        else:
            return redirect(url_for('login'))
    
    return render_template('register.html')


def update_token(dbusername):
    random_uuid = str(uuid.uuid4())
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    print("random_uuid and dbusername in update_token:",random_uuid,dbusername)
    cursor.execute('UPDATE users SET token=? WHERE username=?',
                    (random_uuid, dbusername))
    conn.commit()
    conn.close()


def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    user=cursor.fetchone()
    return user 



@app.route('/login', methods=["GET", "POST"])
def login():
    error_message = None

    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form['username']
            password = request.form['password']
        
        user = get_user(username)
        
        if user and check_password_hash(user[2], password):
            session['user'] = user[1]  
            update_token(user[1]) 
            user = get_user(username)
            if request.is_json:
                response_data = {
                    'message': 'Authentication successful',
                    'access_token': user[4]
                }
                return jsonify(response_data), 200
            else:
                response = redirect(url_for('get_all_todo'))
                # time = session_expiration_time()
                # response.set_cookie('access_token', user[4], max_age=time.total_seconds())
                response.set_cookie('access_token', user[4])

                return response
        else:
            if request.is_json:
                return jsonify({"message":"Invalid username or password"}), 200
            else:
                error_message = "Invalid username or password"
                return render_template("login.html", loginerror=error_message)
    return render_template("login.html")


@app.route('/logout')
def log_out():
    user=get_current_user()
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET token=? WHERE username=?',("",user[1]))
    conn.commit()
    conn.close()
    session.pop('user', None)
    response = redirect(url_for('login'))
    response.delete_cookie('access_token')
    return response




# ---------------------------  Flask View  --------------------------- 


# Loading all Todo items
@app.route('/get_all_todos')
def get_all_todo():

    user=get_current_user()
    access_token = request.cookies.get('access_token')
    print("access_token in getalltodo:",access_token)
    headers = {
        'Authorization': f'{access_token}'
    }

    base_url = request.host_url
    response_from_api = requests.get(f'{base_url}tasks', headers=headers)
    if response_from_api.status_code == 200:
        # print("response_from_api,user:",response_from_api.json(),user)
        return render_template('todo.html', data=response_from_api.json(),user=user)
    elif response_from_api.status_code == 401:
        response_from_api=response_from_api.json()
        loginerror=response_from_api['message']
        # print("loginerror:",loginerror)
        # return redirect(url_for('login'),loginerror=loginerror)
        return render_template("login.html", loginerror=loginerror)

   
    
# Insert new Todo items
@app.route ("/addtodo",methods=['GET','POST'])
def add_New_Todo():

    user = get_current_user()
    access_token = request.cookies.get('access_token')
    print("access_token in get all todo:", access_token)
    headers = {
        'Authorization': f'{access_token}'
    }
    print("headers:", headers)

    # Check token validity before rendering the form page
    token_validate = validate_auth_token(access_token)
    print("token_validate:",token_validate)
    if not token_validate:
        # Redirect to login page if token is invalid
        return render_template("login.html", loginerror="Authorization Token Error - Login again.")

    if request.method == 'POST':
        form_data = {
            'task': request.form['task'],
            'due_date': request.form['due_date'],
            'status': request.form['status']
        }
        base_url = request.host_url
        api_response = requests.post(f'{base_url}tasks', json=form_data, headers=headers)
        if api_response.status_code == 201:
            flash("Todo task added")
            return redirect(url_for("get_all_todo"))
        elif api_response.status_code == 401:
            api_response = api_response.json()
            loginerror = api_response['message']
            return render_template("login.html", loginerror=loginerror)
    
    return render_template("add_todo.html")


# Edit Todo 
@app.route ("/edit_todo/<int:task_id>",methods=['GET','POST'])
def edit_Todo(task_id):

    user = get_current_user()
    access_token = request.cookies.get('access_token')
    print("access_token in get all todo:", access_token)
    headers = {
        'Authorization': f'{access_token}'
    }
    print("headers:", headers)

    # Check token validity before rendering the form page
    token_validate = validate_auth_token(access_token)
    print("token_validate:",token_validate)
    if not token_validate:
        return render_template("login.html", loginerror="Authorization Token Error - Login again.")
    
    if request.method=='POST':
        form_data = {
            'task': request.form['task'],
            'due_date': request.form['due_date'],
            'status': request.form['status']
        }
        base_url = request.host_url
        print("base_url & form_data:",base_url,form_data)
        api_response = requests.put(f'{base_url}tasks/{task_id}', json=form_data, headers=headers)

        if api_response.status_code == 200:
            flash("Todo task Updated")
            return redirect(url_for("get_all_todo"))
        elif api_response.status_code == 401:
            api_response = api_response.json()
            loginerror = api_response['message']
            return render_template("login.html", loginerror=loginerror)
        
    # when we edit it give values we selected
    conn = sqlite3.connect('todo.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tasks WHERE id=?', (task_id,))
    res=cursor.fetchone()
    task_dict = {
        "id": res[0],
        "task": res[1],
        'due_date': datetime.strptime(res[2], '%Y-%m-%d').strftime('%Y-%m-%d'),
        "status": res[3]
        }
    print("res:",res)
    conn.close()
    return render_template("edit_todo.html",data=task_dict)



# Delete Todo 
@app.route ("/delete_todo/<int:task_id>",methods=['GET','POST'])
def delete_Todo(task_id):
    user = get_current_user()
    access_token = request.cookies.get('access_token')
    print("access_token in get all todo:", access_token)
    headers = {
        'Authorization': f'{access_token}'
    }
    print("headers:", headers)
    base_url = request.host_url
    api_response = requests.delete(f'{base_url}tasks/{task_id}',headers=headers)
    if api_response.status_code == 200:
        flash("Todo task deleted")
        return redirect(url_for("get_all_todo"))
    elif api_response.status_code == 401:
        api_response = api_response.json()
        loginerror = api_response['message']
        return render_template("login.html", loginerror=loginerror)
  


# Get to_do data by date

# http://127.0.0.1:5000//tasks/due?due_date=2023-10-31
@app.route("/due")
def get_Todo_By_Due_By():
    user = get_current_user()
    access_token = request.cookies.get('access_token')
    print("access_token in get all todo:", access_token)
    headers = {
        'Authorization': f'{access_token}'
    }
    print("headers:", headers)
    
    task_date = request.args.get('due_date')
    print("task_date in flask:",task_date)
    base_url = request.host_url
    api_response = requests.get(f'{base_url}tasks/due?due_date={task_date}',headers=headers)
    if api_response.status_code == 200:
        tasks_data = api_response.json()
        print("tasks_data:", tasks_data)
        return render_template('fetch_todo.html', data=tasks_data,user=user)
    
    elif api_response.status_code == 401:
        api_response = api_response.json()
        loginerror = api_response['message']
        return render_template("login.html", loginerror=loginerror)
  

# Get overdue data:
@app.route('/overdue')
def get_overdue_todo():
    user=get_current_user()
    access_token = request.cookies.get('access_token')
    print("access_token in get all todo:", access_token)
    headers = {
        'Authorization': f'{access_token}'
    }
    print("headers:", headers)
    base_url = request.host_url
    response_from_api = requests.get(f'{base_url}tasks/overdue', headers=headers)
    if response_from_api.status_code == 200:
        if len(response_from_api.json()):

            return render_template('fetch_todo.html', data=response_from_api.json(),user=user)
        else:
            flash("No Overdue data")

            return redirect(url_for("get_all_todo"))
    elif response_from_api.status_code == 401:
            response_from_api=response_from_api.json()
            loginerror=response_from_api['message']
            
            # print("loginerror:",loginerror)
            # return redirect(url_for('login'),loginerror=loginerror)
            return render_template("login.html", loginerror=loginerror)

# Get Finished data:
@app.route('/finished')
def get_finished_todo():
    user=get_current_user()
    access_token = request.cookies.get('access_token')
    print("access_token in get all todo:", access_token)
    headers = {
        'Authorization': f'{access_token}'
    }
    print("headers:", headers)
    base_url = request.host_url
    print("base_url in finished:",base_url)
    # response_from_api = FinishedTasks().get()  
    response_from_api = requests.get(f'{base_url}tasks/finished', headers=headers)

    if response_from_api.status_code == 200:
        
        print("esponse_from_api.json():",response_from_api.json())
        
        if len(response_from_api.json()):
            return render_template('fetch_todo.html', data=response_from_api.json(),user=user)
        else:
            flash("No Finished data")

            return redirect(url_for("get_all_todo"))


    elif response_from_api.status_code == 401:
            response_from_api=response_from_api.json()
            loginerror=response_from_api['message']
            return render_template("login.html", loginerror=loginerror)
   


if __name__ == '__main__':
    app.secret_key="000"
    app.run(debug=True)


