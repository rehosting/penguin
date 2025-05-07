#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define RESPONSE_TEMPLATE "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s"

// Global variables for clean shutdown
volatile int server_running = 1;
int server_socket = -1;

// Signal handler for graceful shutdown
void handle_signal(int signal) {
    printf("\nReceived signal %d. Shutting down server...\n", signal);
    server_running = 0;
    if (server_socket != -1) {
        close(server_socket);
    }
    exit(0);
}

void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE] = {0};
    ssize_t bytes_read = read(client_socket, buffer, BUFFER_SIZE - 1);
    
    if (bytes_read > 0) {
        printf("Received request:\n%s\n", buffer);
        
        // Basic HTTP request parsing
        char method[10] = {0};
        char path[100] = {0}; // Vulnerability 1: Stack buffer overflow if path in request > 99 chars
        sscanf(buffer, "%s %s", method, path);
        printf("Method: %s, Path: %s\n", method, path);

        // Vulnerability 2: Format string vulnerability
        printf("Path for logging: ");
        printf(path); // If path contains format specifiers, this is vulnerable
        printf("\n");
        
        // Prepare response content based on path
        char *content;

        // Vulnerability 3: Heap Buffer Overflow & Integer Overflow
        if (strncmp(path, "/echo/", 6) == 0) {
            char* user_input = path + 6;
            int len_to_copy = strlen(user_input);
            char* heap_buf = (char*)malloc(10); // Small fixed-size buffer
            if (heap_buf) {
                printf("Copying %d bytes to heap_buf from user_input: %s\n", len_to_copy, user_input);
                memcpy(heap_buf, user_input, len_to_copy); // Potential heap overflow if len_to_copy > 9
                content = heap_buf; // Note: This will leak memory and send potentially un-terminated string
                                    // For a real scenario, you'd null-terminate and prepare proper HTTP response.
                                    // For fuzzing, this is fine to demonstrate the overflow.
                                    // We will also not free heap_buf to simplify, leading to a memory leak.
            } else {
                content = "<html><body><h1>500 Internal Server Error</h1><p>Failed to allocate memory.</p></body></html>";
            }
        } else if (strncmp(path, "/alloc/", 7) == 0) {
            int num_to_alloc = atoi(path + 7);
            // Vulnerability 4: Integer overflow leading to small allocation then heap overflow
            // e.g. /alloc/2147483647, num_to_alloc * 2 might overflow to a small positive or negative number
            // If it becomes small positive, malloc succeeds, then a large memcpy can occur.
            size_t size_val = num_to_alloc * 2 + 100; // Potential integer overflow
            printf("Attempting to allocate: %zu bytes based on input %d\n", size_val, num_to_alloc);
            char* dynamic_buf = (char*)malloc(size_val);
            if (dynamic_buf) {
                // Simulate using the buffer, potentially overflowing if size_val was small due to overflow
                // For demonstration, let's try to write a fixed large amount if num_to_alloc was positive
                // This is a bit contrived but shows the principle.
                if (num_to_alloc > 0 && num_to_alloc < (BUFFER_SIZE / 2) ) { // Only copy if num_to_alloc is somewhat reasonable to avoid huge copies
                    printf("Copying %d bytes from request buffer to dynamic_buf\n", num_to_alloc);
                    memcpy(dynamic_buf, buffer, num_to_alloc); // If size_val became small, this overflows
                    dynamic_buf[num_to_alloc < size_val ? num_to_alloc : size_val -1] = '\0'; // Ensure null termination if possible
                    content = dynamic_buf; // Memory leak, as above
                } else if (num_to_alloc <=0 && size_val > 0) { // If num_to_alloc was negative or zero but size_val positive (due to +100)
                     snprintf(dynamic_buf, size_val, "<html><body><h1>Allocated small buffer: %zu</h1></body></html>", size_val);
                     content = dynamic_buf; // Memory leak
                }
                 else {
                    content = "<html><body><h1>Allocated, but not using due to input value.</h1></body></html>";
                    free(dynamic_buf); // Free if not used as content
                }
            } else {
                 content = "<html><body><h1>500 Internal Server Error</h1><p>Failed to allocate memory (integer overflow?).</p></body></html>";
            }
        // Vulnerability 5: Command Injection
        } else if (strncmp(path, "/exec/", 6) == 0) {
            char* command_to_run = path + 6;
            char result_buffer[512]; // Buffer to hold command output or message
            printf("Attempting to execute command: %s\n", command_to_run);

            // Construct the full command, e.g., by redirecting output to a temp file
            // For simplicity here, we'll just execute and show a success/failure message
            // A more advanced version might try to capture output.
            // WARNING: This is a command injection vulnerability.
            int ret = system(command_to_run); 

            if (ret == -1) {
                snprintf(result_buffer, sizeof(result_buffer), "<html><body><h1>Command Execution Failed</h1><p>Error executing: %s</p></body></html>", command_to_run);
            } else {
                snprintf(result_buffer, sizeof(result_buffer), "<html><body><h1>Command Executed</h1><p>Command '%s' executed with exit code %d.</p><p>Note: Output is not captured in this simple example.</p></body></html>", command_to_run, ret);
            }
            content = strdup(result_buffer); // Allocate memory for content, will be leaked.
                                            // In a real app, manage this memory.
        } else if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
            content = "<html><body><h1>Welcome to the Simple Web Server</h1>"
                      "<p>This is a basic HTTP server implemented in C.</p>"
                      "<p>Try accessing <a href='/info'>/info</a> for server information.</p>"
                      "<p>Try <a href='/echo/testdata'>/echo/testdata</a> (heap overflow if testdata > 9 chars).</p>"
                      "<p>Try <a href='/alloc/10'>/alloc/10</a> or <a href='/alloc/2000000000'>/alloc/2000000000</a> (integer overflow).</p>"
                      "<p>Try <a href='/exec/ls%20-l'>/exec/ls -l</a> (command injection).</p>"
                      "</body></html>";
        } else if (strcmp(path, "/info") == 0) {
            content = "<html><body><h1>Server Information</h1>"
                      "<p>Server: Simple C Webserver</p>"
                      "<p>Version: 1.0</p>"
                      "<p>Running on port 8080</p>"
                      "<p><a href='/'>Back to Home</a></p>"
                      "</body></html>";
        } else {
            content = "<html><body><h1>404 Not Found</h1>"
                      "<p>The page you requested could not be found.</p>"
                      "<p><a href='/'>Back to Home</a></p>"
                      "</body></html>";
        }
        
        // Format the full HTTP response
        char response[BUFFER_SIZE];
        int content_length = strlen(content);
        snprintf(response, BUFFER_SIZE, RESPONSE_TEMPLATE, content_length, content);
        
        // Send response to client
        write(client_socket, response, strlen(response));
        printf("Response sent.\n\n");
    }
    
    close(client_socket);
}

int main(int argc, char *argv[]) {
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int opt = 1;
    int port = PORT;
    
    // Check for custom port in arguments
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            printf("Invalid port number. Using default port %d.\n", PORT);
            port = PORT;
        }
    }
    
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Create socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    
    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    // Bind socket to address
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    
    printf("Server started on port %d\n", port);
    printf("Press Ctrl+C to stop the server\n\n");
    
    // Main server loop
    while (server_running) {
        int client_socket;
        
        // Accept new connection
        if ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len)) < 0) {
            if (server_running) {
                perror("Accept failed");
            }
            continue;
        }
        
        printf("Connection accepted from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // Handle client in the same thread
        handle_client(client_socket);
    }
    
    // Cleanup
    if (server_socket != -1) {
        close(server_socket);
    }
    
    return 0;
}