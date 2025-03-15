from flask import Flask, render_template, request, session
from flask_socketio import SocketIO, join_room, leave_room, send
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key'
socketio = SocketIO(app)

# Room routing
@app.route('/chat/<community>')
def chat(community):
    session['username'] = f'User{random.randint(1000, 9999)}'
    return render_template('chat.html', community=community)

# Handling messages
@socketio.on('message')
def handle_message(data):
    room = data['room']
    message = f"{session['username']}: {data['message']}"
    send(message, to=room)

# Joining rooms
@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    send(f"{session['username']} has joined {room}!", to=room)

# Leaving rooms
@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)
    send(f"{session['username']} has left {room}.", to=room)

if __name__ == "__main__":
    socketio.run(app, debug=True)
