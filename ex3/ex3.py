import http.server
import ssl

# Use port 4443 to avoid needing sudo privileges
server_address = ('localhost', 4443)

# Create an HTTP server instance
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

# Wrap the server with SSL using your certificate and key
httpd.socket = ssl.wrap_socket(httpd.socket,
                               certfile='tutorial3.com.crt',  # Replace with your certificate
                               keyfile='tutorial3.com.key',    # Replace with your key
                               server_side=True)

print("Serving on https://localhost:443")
httpd.serve_forever()
