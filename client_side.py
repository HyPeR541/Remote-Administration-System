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
