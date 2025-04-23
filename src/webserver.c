#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <time.h>

#include <data.h>
#include <http.h>
#include <util.h>
#include <logger.h>
#include <dht.h>

#define MAX_RESOURCES 100

enum server_mode
{
    MODE_STATIC,
    MODE_JOIN,
    MODE_SINGLE
};

struct tuple resources[MAX_RESOURCES] = {
    {"/static/foo", "Foo", sizeof "Foo" - 1},
    {"/static/bar", "Bar", sizeof "Bar" - 1},
    {"/static/baz", "Baz", sizeof "Baz" - 1}};

/**
 * Sends an HTTP reply to the client based on the received request.
 *
 * @param conn      The file descriptor of the client connection socket.
 * @param request   A pointer to the struct containing the parsed request information.
 */
void send_reply(int conn, struct request *request)
{

    // Create a buffer to hold the HTTP reply
    char buffer[HTTP_MAX_SIZE];
    char *reply = buffer;
    size_t offset = 0;

    dht_id uri_hash = hash(request->uri);
    plogf(INFO, "Handling %s request for %s (hash %hu, %lu byte payload)", request->method, request->uri, uri_hash, request->payload_length);

    // Check if the responsible peer for the requested resource is available.
    const struct peer *responsible_peer = dht_responsible(uri_hash);
    if (responsible_peer == NULL)
    {
        dht_lookup(uri_hash);
        reply = "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n";
        offset = strlen(reply);
    }
    else if (responsible_peer != &self)
    {
        // If the responsible peer for the resource is not the current server (self), redirect the client to the responsible peer.

        // Calculate the IP address and port of the responsible peer.
        offset += sprintf(reply + offset, "HTTP/1.1 303 See Other\r\nLocation: http://");

        in_addr_t ip = htonl(responsible_peer->ip.s_addr);
        inet_ntop(AF_INET, &ip, reply + offset, 15);
        offset += strlen(reply + offset);

        offset += sprintf(reply + offset, ":%hu%s\r\nContent-Length: 0\r\n\r\n", responsible_peer->port, request->uri);
    }
    else if (strcmp(request->method, "GET") == 0)
    {

        // Find the resource with the given URI in the 'resources' array.
        size_t resource_length;
        const char *resource = get(request->uri, resources, MAX_RESOURCES, &resource_length);

        if (resource)
        {
            size_t payload_offset = sprintf(reply, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n", resource_length);
            memcpy(reply + payload_offset, resource, resource_length);
            offset = payload_offset + resource_length;
        }
        else
        {
            reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            offset = strlen(reply);
        }
    }
    else if (strcmp(request->method, "PUT") == 0)
    {
        // Try to set the requested resource with the given payload in the 'resources' array.
        if (set(request->uri, request->payload, request->payload_length, resources, MAX_RESOURCES))
        {
            reply = "HTTP/1.1 204 No Content\r\n\r\n";
        }
        else
        {
            reply = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
        }
        offset = strlen(reply);
    }
    else if (strcmp(request->method, "DELETE") == 0)
    {
        // Try to delete the requested resource from the 'resources' array
        if (delete (request->uri, resources, MAX_RESOURCES))
        {
            reply = "HTTP/1.1 204 No Content\r\n\r\n";
        }
        else
        {
            reply = "HTTP/1.1 404 Not Found\r\n\r\n";
        }
        offset = strlen(reply);
    }
    else
    {
        reply = "HTTP/1.1 501 Method Not Supported\r\n\r\n";
        offset = strlen(reply);
    }

    // Send the reply back to the client
    if (send(conn, reply, offset, 0) == -1)
    {
        plogf(FATAL, "send returned an error.");
        close(conn);
    }
}

/**
 * Processes an incoming packet from the client.
 *
 * @param conn The socket descriptor representing the connection to the client.
 * @param buffer A pointer to the incoming packet's buffer.
 * @param n The size of the incoming packet.
 *
 * @return Returns the number of bytes processed from the packet.
 *         If the packet is successfully processed and a reply is sent, the return value indicates the number of bytes processed.
 *         If the packet is malformed or an error occurs during processing, the return value is -1.
 *
 */
size_t process_packet(int conn, char *buffer, size_t n)
{
    struct request request = {
        .method = NULL,
        .uri = NULL,
        .payload = NULL,
        .payload_length = -1};
    ssize_t bytes_processed = parse_request(buffer, n, &request);

    if (bytes_processed > 0)
    {
        send_reply(conn, &request);

        // Check the "Connection" header in the request to determine if the connection should be kept alive or closed.
        const string connection_header = get_header(&request, "Connection");
        if (connection_header && strcmp(connection_header, "close"))
        {
            return -1;
        }
    }
    else if (bytes_processed == -1)
    {
        // If the request is malformed or an error occurs during processing, send a 400 Bad Request response to the client.
        const string bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(conn, bad_request, strlen(bad_request), 0);
        plogf(WARNING, "Received malformed request, terminating connection.");
        close(conn);
        return -1;
    }

    return bytes_processed;
}

/**
 * Sets up the connection state for a new socket connection.
 *
 * @param state A pointer to the connection_state structure to be initialized.
 * @param sock The socket descriptor representing the new connection.
 *
 */
static void connection_setup(struct connection_state *state, int sock)
{
    // Set the socket descriptor for the new connection in the connection_state structure.
    state->sock = sock;

    // Set the 'end' pointer of the state to the beginning of the buffer.
    state->end = state->buffer;

    // Clear the buffer by filling it with zeros to avoid any stale data.
    memset(state->buffer, 0, HTTP_MAX_SIZE);
}

/**
 * Discards the front of a buffer
 *
 * @param buffer A pointer to the buffer to be modified.
 * @param discard The number of bytes to drop from the front of the buffer.
 * @param keep The number of bytes that should be kept after the discarded bytes.
 *
 * @return Returns a pointer to the first unused byte in the buffer after the discard.
 * @example buffer_discard(ABCDEF0000, 4, 2):
 *          ABCDEF0000 ->  EFCDEF0000 -> EF00000000, returns pointer to first 0.
 */
char *buffer_discard(char *buffer, size_t discard, size_t keep)
{
    memmove(buffer, buffer + discard, keep);
    memset(buffer + keep, 0, discard); // invalidate buffer
    return buffer + keep;
}

/**
 * Handles incoming connections and processes data received over the socket.
 *
 * @param state A pointer to the connection_state structure containing the connection state.
 * @return Returns true if the connection and data processing were successful, false otherwise.
 *         If an error occurs while receiving data from the socket, the function exits the program.
 */
bool handle_connection(struct connection_state *state)
{
    // Calculate the pointer to the end of the buffer to avoid buffer overflow
    const char *buffer_end = state->buffer + HTTP_MAX_SIZE;

    // Check if an error occurred while receiving data from the socket
    ssize_t bytes_read = recv(state->sock, state->end, buffer_end - state->end, 0);
    if (bytes_read == -1)
    {
        plogf(FATAL, "recv returned an error.");
        close(state->sock);
        exit(EXIT_FAILURE);
    }
    else if (bytes_read == 0)
    {
        return false;
    }

    char *window_start = state->buffer;
    char *window_end = state->end + bytes_read;

    ssize_t bytes_processed = 0;
    while ((bytes_processed = process_packet(state->sock, window_start, window_end - window_start)) > 0)
    {
        window_start += bytes_processed;
    }
    if (bytes_processed == -1)
    {
        return false;
    }

    state->end = buffer_discard(state->buffer, window_start - state->buffer, window_end - window_start);
    return true;
}

/**
 * Derives a sockaddr_in structure from the provided host and port information.
 *
 * @param host The host (IP address or hostname) to be resolved into a network address.
 * @param port The port number to be converted into network byte order.
 *
 * @return A sockaddr_in structure representing the network address derived from the host and port.
 */
static struct sockaddr_in derive_sockaddr(const char *host, const char *port)
{
    struct addrinfo hints = {
        .ai_family = AF_INET,
    };
    struct addrinfo *result_info;

    // Resolve the host (IP address or hostname) into a list of possible addresses.
    int returncode = getaddrinfo(host, port, &hints, &result_info);
    if (returncode)
    {
        plogf(FATAL, "Error parsing host/port.");
        exit(EXIT_FAILURE);
    }

    // Copy the sockaddr_in structure from the first address in the list
    struct sockaddr_in result = *((struct sockaddr_in *)result_info->ai_addr);

    // Free the allocated memory for the result_info
    freeaddrinfo(result_info);
    return result;
}

/**
 * Sets up a TCP server socket and binds it to the provided sockaddr_in address.
 *
 * @param addr The sockaddr_in structure representing the IP address and port of the server.
 *
 * @return The file descriptor of the created TCP server socket.
 */
static int setup_server_socket(struct sockaddr_in addr)
{
    const int enable = 1;
    const int backlog = 1;

    // Create a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        plogf(FATAL, "socket");
        exit(EXIT_FAILURE);
    }

    // Avoid dead lock on connections that are dropped after poll returns but before accept is called
    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1)
    {
        plogf(FATAL, "fcntl");
        exit(EXIT_FAILURE);
    }

    // Set the SO_REUSEADDR socket option to allow reuse of local addresses
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1)
    {
        plogf(FATAL, "setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind socket to the provided address
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        plogf(FATAL, "bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Start listening on the socket with maximum backlog of 1 pending connection
    if (listen(sock, backlog))
    {
        plogf(FATAL, "listen");
        exit(EXIT_FAILURE);
    }

    return sock;
}

/**
 * Sets up a TCP socket for the peer with the provided sockaddr_in address.
 *
 * @param addr The sockaddr_in structure representing the IP address and port of the peer.
 *
 * @return The file descriptor of the created UDP socket
 */
static int setup_peer_socket(struct sockaddr_in addr)
{
    // Create a socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
    {
        plogf(FATAL, "socket");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to the provided address
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        plogf(FATAL, "bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    return sock;
}

/**
 * Creates a peer struct from the provided arguments (id, ip, port).
 *
 * @param id   The ID of the peer (parsed as an unsigned long).
 * @param ip   The IP address of the peer (in string format, e.g., "192.168.0.1").
 * @param port The port number of the peer (in string format, e.g., "8080").
 *
 * @return A struct peer object representing the peer created from the provided arguments.
 *         The struct contains the ID, IP address, and port number of the peer.
 */
static struct peer peer_from_args(const string id, const string ip, const string port)
{
    // Create a sockaddr_in struct to derive IP and port information
    struct sockaddr_in addr = derive_sockaddr(ip, port);

    // Create a struct peer object to hold peer information
    struct peer result = {
        .id = safe_strtoul(id, NULL, 10, "Failed to parse peer ID"),
        .ip = {.s_addr = ntohl(addr.sin_addr.s_addr)},
        .port = ntohs(addr.sin_port),
    };

    // Return the created peer struct
    return result;
}

/**
 *  The program expects 3, 4, or 6 arguments; otherwise, it returns EXIT_FAILURE.
 *
 *  Call as:
 *
 *  ./build/webserver self.ip self.port
 *  ./build/webserver self.ip self.port self.id
 *  ./build/webserver self.ip self.port self.id anchor.ip anchor.port
 */
int main(int argc, char **argv)
{
    // init stuff
    setvbuf(stdout, NULL, _IONBF, 0); // remove this before handing in
    logger_init(stdout, DEBUG);
    enum server_mode mode = MODE_SINGLE;

    if (argc != 3 && argc != 4 && argc != 6)
        return EXIT_FAILURE;

    const string id_arg = (argc > 3) ? argv[3] : "0";
    self = peer_from_args(id_arg, argv[1], argv[2]);

    if (argc == 6)
    {
        mode = MODE_JOIN;
    }

    struct sockaddr_in addr;
    peer_to_sockaddr(self, &addr);

    // Set up a server socket and a DHT socket.
    int server_socket = setup_server_socket(addr);
    dht_socket = setup_peer_socket(addr);

    if (mode != MODE_JOIN)
    {
        // Check if the program is running in static mode or join mode.
        bool pred_set = getenv("PRED_ID") && getenv("PRED_IP") && getenv("PRED_PORT");
        bool succ_set = getenv("SUCC_ID") && getenv("SUCC_IP") && getenv("SUCC_PORT");
        if (pred_set && succ_set)
            mode = MODE_STATIC;
    }

    switch (mode)
    {
        case MODE_JOIN:
        {
            // If running in join mode, use the provided anchor information.
            plogf(INFO, "Starting in join mode.");
            char *anchor_ip = argv[4];
            char *anchor_port = argv[5];
            anchor = peer_from_args("0", anchor_ip, anchor_port);
            dht_join();
        }
        break;
        case MODE_STATIC:
        {
            // If running in static mode, use the provided predecessor and successor information.
            plogf(INFO, "Starting in static mode.");
            predecessor = peer_from_args(getenv("PRED_ID"), getenv("PRED_IP"), getenv("PRED_PORT"));
            successor = peer_from_args(getenv("SUCC_ID"), getenv("SUCC_IP"), getenv("SUCC_PORT"));
        }
        break;
        default:
        case MODE_SINGLE:
        {
            // If neither static mode nor join mode, set predecessor and successor to self.
            plogf(INFO, "Starting in solo mode.");
            predecessor = self;
            successor = self;
        }
        break;
    }

    // Create an array of pollfd structures to monitor sockets.
    struct pollfd sockets[3] = {
        {.fd = server_socket, .events = POLLIN},
        {.fd = dht_socket, .events = POLLIN},
    };

    struct connection_state state = {0};
    state.timestamp = time(NULL);
    bool stabilize = !getenv("NO_STABILIZE");

    plogf(DEBUG, "Entering main loop with periodic stabilisation %s. Current timestamp is %ld",
          stabilize ? "ON" : "OFF", state.timestamp);
    
    while (true)
    {
        if (stabilize && time(NULL) - state.timestamp > 0)
        {
            state.timestamp = time(NULL);
            plogf(DEBUG, "Periodical stabilization of DHT.");
            dht_stabilize();
        }

        // Use poll() to wait for events on the monitored sockets.
        int ready = poll(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
        if (ready == -1)
        {
            plogf(FATAL, "poll");
            exit(EXIT_FAILURE);
        }

        // Process events on the monitored sockets.
        for (size_t i = 0; i < sizeof(sockets) / sizeof(sockets[0]); i += 1)
        {
            if (sockets[i].revents != POLLIN)
            {
                // If there are no POLLIN events on the socket, continue to the next iteration.
                continue;
            }
            int s = sockets[i].fd;

            if (s == server_socket)
            {
                plogf(DEBUG, "Handling new connection event.");

                // If the event is on the server_socket, accept a new connection from a client.
                int connection = accept(server_socket, NULL, NULL);
                if (connection == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    close(server_socket);
                    plogf(FATAL, "accept");
                    exit(EXIT_FAILURE);
                }
                else
                {
                    connection_setup(&state, connection);

                    // limit to one connection at a time
                    sockets[0].events = 0;
                    sockets[2].fd = connection;
                    sockets[2].events = POLLIN;
                }
            }
            else if (s == dht_socket)
                // If the event is on the dht_socket, handle the DHT-related socket event.
                dht_handle_socket();
            else
            {
                assert(s == state.sock);

                // Call the 'handle_connection' function to process the incoming data on the socket.
                bool cont = handle_connection(&state);
                if (!cont)
                { // get ready for a new connection
                    sockets[0].events = POLLIN;
                    sockets[2].fd = -1;
                    sockets[2].events = 0;
                }
            }
        }
    }

    return EXIT_SUCCESS;
}
