# CN MINI PROJECT
## UE22CS252B
## 4TH Semester,Academic Year 2024
## Remote Aministration System   

<br>
<br>
<b>Team members</b>
<BR>
Lohit kumar Nagarur - PES2UG22CS280

Kousthubh N Gowda   - PES2UG22CS270
<BR><BR>

## SYNOPSIS
<br>
This project of ours helps to connect multiple servers one by one after giving them as input and can access the data of servers which is runtime of the server,memory status in the cpu of the server,network data usage and cpu usage status.

## Code:
for server side:

```
import socket
import ssl
import subprocess
import psutil
import time
import threading

# Server configuration
SERVER_HOST = '0.0.0.0'  
SERVER_PORT = 5555
BUFFER_SIZE = 1024
QUIT_MESSAGE = "quit"

# User credentials and login status
USER_DB = {
    '123': {'password': '123', 'loggedin': False},
    '456': {'password': '456', 'loggedin': False},
    '789': {'password': '789', 'loggedin': False},
    'pes': {'password': 'pesu', 'loggedin': False},
}

def authenticate_user(username, password):
    """Authenticate user based on provided username and password""" 
    user_data = USER_DB.get(username)
    if user_data and not user_data['loggedin'] and user_data['password'] == password:
        user_data['loggedin'] = True
        return True 
    return False

def handle_client(ssl_client_socket):
    """Handle incoming client connection"""
    authenticated = False
    username = ""

    # Authenticate user
    try:
        username = ssl_client_socket.recv(BUFFER_SIZE).decode().strip()
        password = ssl_client_socket.recv(BUFFER_SIZE).decode().strip()

        authenticated = authenticate_user(username, password)
        if not authenticated:
            ssl_client_socket.send(b"Authentication failed. Please try again.\n")
            return
        else:
            ssl_client_socket.send(b"Authentication successful. You are now logged in.\n")
    except Exception as e:
        ssl_client_socket.send(f"Error during authentication: {str(e)}\n".encode())
        return

    # Now that the user is authenticated, handle commands
    while True:
        try:
            # Receive command from client
            command = ssl_client_socket.recv(BUFFER_SIZE).decode().strip()

            # Check for exit command
            if command.lower() == QUIT_MESSAGE:
                USER_DB[username]['loggedin'] = False
                break

            # Execute command
            if command.lower() == "cpu":
                # Get CPU usage
                cpu_usage = psutil.cpu_percent(interval=1)
                output = f"CPU Usage: {cpu_usage}%"
            elif command.lower() == "runtime":
                # Get server runtime
                runtime = time.time() - start_time
                output = f"Server Runtime: {runtime} seconds"
            elif command.lower() == "network":
                # Get network performance
                network_stats = psutil.net_io_counters()
                bytes_sent_mb = round(network_stats.bytes_sent / (1024 ** 2), 2)
                bytes_recv_mb = round(network_stats.bytes_recv / (1024 ** 2), 2)
                output = f"Network Performance:\nBytes Sent: {bytes_sent_mb} MB\nBytes Received: {bytes_recv_mb} MB"
            elif command.lower() == "memory":
                # Get memory usage
                memory_stats = psutil.virtual_memory()
                total_gb = round(memory_stats.total / (1024 ** 3), 2)
                available_gb = round(memory_stats.available / (1024 ** 3), 2)
                used_gb = round(memory_stats.used / (1024 ** 3), 2)
                output = f"Memory Usage:\nTotal: {total_gb} GB\nAvailable: {available_gb} GB\nUsed: {used_gb} GB"
            else:
                # Execute other commands using subprocess
                output = subprocess.getoutput(command)

            # Send output back to client
            ssl_client_socket.send(output.encode())
        except Exception as e:
            error_message = f"Error executing command: {str(e)}"
            ssl_client_socket.send(error_message.encode())

    # Close client connection
    ssl_client_socket.close()
    USER_DB[username]['loggedin'] = False  # Update login status when the client disconnects

def main():
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"[*] Listening on {SERVER_HOST}:{SERVER_PORT}")

    # SSL context setup
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')

    try:
        while True:
            # Accept incoming client connection
            client_socket, client_address = server_socket.accept()
            print(f"[*] Accepted connection from {client_address[0]}:{client_address[1]}")

            # Wrap the socket with SSL
            ssl_client_socket = context.wrap_socket(client_socket, server_side=True)

            # Handle client connection in a separate thread
            client_handler = threading.Thread(target=handle_client, args=(ssl_client_socket,))
            client_handler.start()
    except KeyboardInterrupt:
        print("[*] Shutting down")
        server_socket.close()

if __name__ == "__main__":
    start_time = time.time()  # Record server start time
    main()
```

for client side
```
import socket
import ssl
import threading

def handle_server_connection(server_host, server_port):
    BUFFER_SIZE = 1024
    QUIT_MESSAGE = "quit"

    # Create a socket and wrap it with SSL
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_client_socket = ssl.wrap_socket(client_socket, ssl_version=ssl.PROTOCOL_TLSv1_2, cert_reqs=ssl.CERT_NONE)

    try:
        # Connect to the server
        server_address = (server_host, server_port)
        ssl_client_socket.connect(server_address)
        print(f"Connected to server {server_host} on port {server_port} using SSL/TLS")

        # Authenticate with the server
        username = input("Enter username: ")
        password = input("Enter password: ")
        ssl_client_socket.sendall(username.encode())
        ssl_client_socket.sendall(password.encode())

        # Receive authentication response
        response = ssl_client_socket.recv(BUFFER_SIZE).decode()
        print(response)

        if "Authentication successful" in response:
            # Now that authentication is successful, handle command execution
            while True:
                # Get command from user
                message = input("Enter a command (or 'quit' to exit): ")
                # Send command to server
                ssl_client_socket.sendall(message.encode())
                if message.lower() == QUIT_MESSAGE:
                    break
                # Receive data from the server
                data = ssl_client_socket.recv(BUFFER_SIZE).decode()
                print(f"Received data from server: {data}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the SSL/TLS socket
        ssl_client_socket.close()

def main():
    # Get server details from the user
    num_servers = int(input("Enter the number of servers: "))
    # List to store server details
    servers = []
    # Input server details
    for server_index in range(num_servers):
        while True:
            try:
                server_host = input(f"Enter server {server_index + 1}'s IP address: ")
                server_port = int(input(f"Enter server {server_index + 1}'s port number: "))
                break  
            except ValueError:
                print("Invalid input. Please enter a valid port number.")

        servers.append((server_host, server_port))

    # For each server, handle the connection and commands
    for server_host, server_port in servers:
        handle_server_connection(server_host, server_port)
if __name__ == "__main__":
    main()
```
<br>
<br>

## OVERVIEW
<b>server_side.py</b>: The server script that listens for incoming connections from clients, authenticates them, and executes commands based on client requests.<br>
<b>client_side.py</b>: The client script that connects to the server, authenticates itself with a username and password, and then sends commands to the server.

The communication between the client and server is encrypted using SSL/TLS to ensure secure transmission of data.