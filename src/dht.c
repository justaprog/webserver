/**
 * dht.c defines a Distributed Hash Table (DHT) implementation using a ring-based structure where each node is responsible for a range of IDs.
 */
#include <dht.h>
#include <logger.h>

#include <assert.h>
#include <limits.h>
#include <math.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

#include <openssl/sha.h>

#define LOOKUP_CACHE_ENTRIES 30
#define LOOKUP_CACHE_VALIDIY_MS 2000

struct peer predecessor;
struct peer anchor;
struct peer self;
struct peer successor;
int dht_socket;

/**
 * Table for the most recent lookup replies.
 */
struct
{
    unsigned long entry;
    dht_id predecessor;
    struct peer peer;
} lookup_cache[LOOKUP_CACHE_ENTRIES];

/**
 * Process the given lookup

 * @brief If our successor is responsible for the requested ID, a reply is sent to the originator. Otherwise, the message is forwarded to our successor.
 * @param lookup The lookup message to process
 */
static void process_lookup(struct dht_message lookup);

/**
 * Process the given reply
 *
 * @brief The information about the peer is entered into the the `lookup_cache`, replacing a previous entry for the same hash, the first empty entry, or the first outdated one, in this order.
 * @param reply The reply message to process
 */
static void process_reply(const struct dht_message reply);

/**
 * Process the given stabilize
 *
 * @brief If the given peer is responsible for our successor, the given peer becomes the new successor.
 * @param msg The stabilize message to process
 */
static void process_stabilize(struct dht_message stabilize);

/**
 * Process the given notify
 *
 * @brief If the given peer is responsible for our predecessor, the given peer becomes the new predecessor.
 * @param msg The notify message to process
 */
static void process_notify(struct dht_message notify);

/**
 * Process the given join
 *
 * @brief If we are responsible for the given peer, the given peer becomes our predecessor and we notify the peer. Otherwise, the message is forwarded to our successor.
 * @param msg The join message to process
 */
static void process_join(struct dht_message msg);

/**
 * Send the given message to the given peer
 *
 * @brief The message is serialized and sent to the given peer.
 * @param msg The message to send
 * @param peer The peer to send the message to
 */
static void dht_send(struct dht_message msg, const struct peer peer);

/**
 * @brief Receives and deserializes a DHT message from the DHT socket.
 * @param msg The message buffer
 * @param address The address buffer
 * @param address_length The address length buffer
 * @return The number of bytes received
 */
static ssize_t dht_recv(struct dht_message *msg, struct sockaddr *address, socklen_t *address_length);

/**
 * @brief Deserializes the given DHT message.
 * @param msg The message to deserialize
 * @return The deserialized message
 */
static struct dht_message dht_deserialize(struct dht_message msg);
static struct dht_message dht_serialize(struct dht_message msg);

unsigned long time_ms(void);
static bool outdated(unsigned long entry);

static bool peer_cmp(const struct peer *a, const struct peer *b);
static bool is_responsible(dht_id peer_predecessor, dht_id peer, dht_id id);

unsigned long time_ms(void)
{
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    return 1000 * spec.tv_sec + round(spec.tv_nsec / 1.0e6);
}

struct dht_message dht_deserialize(struct dht_message msg)
{
    struct dht_message message_inverse = {
        .flags = msg.flags,
        .hash = ntohs(msg.hash),
        .peer.id = ntohs(msg.peer.id),
        .peer.ip.s_addr = ntohl(msg.peer.ip.s_addr),
        .peer.port = ntohs(msg.peer.port),
    };
    return message_inverse;
}

struct dht_message dht_serialize(struct dht_message msg)
{
    struct dht_message message_inverse = {
        .flags = msg.flags,
        .hash = htons(msg.hash),
        .peer.id = htons(msg.peer.id),
        .peer.ip.s_addr = htonl(msg.peer.ip.s_addr),
        .peer.port = htons(msg.peer.port),
    };
    return message_inverse;
}

static bool outdated(unsigned long entry)
{
    return (time_ms() - entry) >= LOOKUP_CACHE_VALIDIY_MS;
}

static bool peer_cmp(const struct peer *a, const struct peer *b)
{
    return a && b && (memcmp(a, b, sizeof(struct peer)) == 0);
}

static void dht_send(struct dht_message msg, const struct peer peer)
{
    struct sockaddr_in addr; // The address of the peer

    plogf(DEBUG, "Sending DHT msg (%s, %d, (%d %d %d)) to peer (%d %d %d)",
          opcode_str(msg.flags), msg.hash, msg.peer.id, msg.peer.ip, msg.peer.port, peer.id, peer.ip, peer.port);
    
    msg = dht_serialize(msg);       // Serialize the message before sending it
    peer_to_sockaddr(peer, &addr);  // Convert the peer to a sockaddr_in

    // Send the message to the peer
    if (sendto(dht_socket, &msg, sizeof(struct dht_message), 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1)
    {
        plogf(FATAL, "dht_send: sendto returned an error.");
        exit(EXIT_FAILURE);
    }
}

static void process_lookup(struct dht_message lookup)
{
    // If we are responsible for the hash, we reply to the originator
    if (peer_cmp(&successor, dht_responsible(lookup.hash)))
        dht_reply(lookup.peer, self.id);
    // Otherwise, we forward the message to our successor
    else
        dht_send(lookup, successor);
}

static void process_reply(const struct dht_message reply)
{
    // Try to replace existing value
    for (size_t i = 0; i < LOOKUP_CACHE_ENTRIES; i += 1)
    {
        const bool peer_match = peer_cmp(&lookup_cache[i].peer, &reply.peer);
        const bool more_recent = lookup_cache[i].entry < time_ms();

        if (peer_match && more_recent)
        {
            lookup_cache[i].entry = time_ms();
            lookup_cache[i].predecessor = reply.hash;
            return;
        }
    }

    // If no existing value was replaced, replace the oldest one
    unsigned long oldest_time = ULONG_MAX;
    size_t oldest_idx = 0;
    for (size_t i = 0; i < LOOKUP_CACHE_ENTRIES; i += 1)
    {
        if (lookup_cache[i].entry < oldest_time)
        {
            oldest_idx = i;
        }
    }

    // Since the table is zero-initialized, empty values are implicitly the
    // oldest ones. Moreover, any outdated value is older than any non-outdated
    // one, so no explicit check is required.
    lookup_cache[oldest_idx].entry = time_ms();
    lookup_cache[oldest_idx].predecessor = reply.hash;
    lookup_cache[oldest_idx].peer = reply.peer;
}

static void process_join(struct dht_message msg)
{
    // If we are responsible for the given peer, it becomes our predecessor
    if (is_responsible(predecessor.id, self.id, msg.peer.id))
    {
        predecessor = msg.peer;
        // We notify the peer about our existence
        struct dht_message msg_not = {
            .flags = NOTIFY,
            .hash = 0,
            .peer = self};
        dht_send(msg_not, msg.peer);
    }
    // Otherwise, we forward the message to our successor
    else
        dht_send(msg, successor);
}

static void process_notify(struct dht_message msg)
{
    // If the given peer is responsible for our predecessor, it becomes our predecessor
    // Special case: If we are the first node in the DHT, we accept any predecessor
    if (self.id != msg.peer.id || self.port != msg.peer.port){
        successor = msg.peer;
        dht_stabilize(msg.peer);
    }

}

static void process_stabilize(struct dht_message msg)
{
    if(predecessor.id == '\0' && predecessor.port == '\0') {
        predecessor = msg.peer;
    }
    dht_notify(msg.peer);
}

static ssize_t dht_recv(struct dht_message *msg, struct sockaddr *address, socklen_t *address_length)
{
    ssize_t result = recvfrom(dht_socket, msg, sizeof(struct dht_message), 0, address, address_length);

    if (result < 0)
    {
        plogf(FATAL, "recv returned an error.");
        exit(EXIT_FAILURE);
    }

    *msg = dht_deserialize(*msg);

    return result;
}

static bool is_responsible(dht_id peer_predecessor, dht_id peer, dht_id id)
{
    // Gotta store differences explicitly as unsigned since C promotes them to signed otherwise...
    const dht_id distance_peer_predecessor = peer_predecessor - id;
    const dht_id distance_peer = peer - id;
    return (peer_predecessor == peer) || (distance_peer < distance_peer_predecessor);
}

dht_id hash(const string str)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256((uint8_t *)str, strlen(str), digest);
    return htons(*((dht_id *)digest)); // We only use the first two bytes here
}

struct peer *dht_responsible(dht_id id)
{
    if (is_responsible(predecessor.id, self.id, id))
    {
        return &self;
    }
    else if (is_responsible(self.id, successor.id, id))
    {
        return &successor;
    }

    // Check for recent lookup replies that match the datum
    for (size_t i = 0; i < LOOKUP_CACHE_ENTRIES; i += 1)
    {
        const bool match = is_responsible(lookup_cache[i].predecessor, lookup_cache[i].peer.id, id);

        if (match && !outdated(lookup_cache[i].entry))
        {
            return &lookup_cache[i].peer;
        }
    }

    return NULL;
}

void peer_to_sockaddr(const struct peer peer, struct sockaddr_in *addr)
{
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(peer.ip.s_addr);
    addr->sin_port = htons(peer.port);
}

void dht_lookup(dht_id id)
{
    struct dht_message msg = {
        .flags = LOOKUP,
        .hash = id,
        .peer = self};
    dht_send(msg, successor);
}

void dht_reply(const struct peer peer, dht_id id)
{
    struct dht_message msg = {
        .flags = REPLY,
        .hash = id,
        .peer = successor};
    dht_send(msg, peer);
}

void dht_join()
{
    struct dht_message msg = {
        .flags = JOIN,
        .hash = 0,
        .peer = self};
    dht_send(msg, anchor);
}

void dht_notify(const struct peer peer)
{
    struct dht_message msg = {
        .flags = NOTIFY,
        .hash = 0,
        .peer = predecessor};
    dht_send(msg, peer);
}

void dht_stabilize()
{
    struct dht_message msg = {
        .flags = STABILIZE,
        .hash = self.id,
        .peer = self};
    dht_send(msg, successor);
}

void dht_handle_socket(void)
{
    struct sockaddr address = {0};
    socklen_t address_length = sizeof(struct sockaddr);
    struct dht_message msg = {0};

    dht_recv(&msg, &address, &address_length);

    plogf(INFO, "Processing DHT message (%s %d (%d %d %d))",
          opcode_str(msg.flags), msg.hash, msg.peer.id, msg.peer.ip, msg.peer.port);
    switch (msg.flags)
    {
    case LOOKUP:
        process_lookup(msg);
        break;
    case REPLY:
        process_reply(msg);
        break;
    case STABILIZE:
        process_stabilize(msg);
        break;
    case NOTIFY:
        process_notify(msg);
        break;
    case JOIN:
        process_join(msg);
        break;
    default:
        plogf(WARNING, "Received an invalid DHT message (%d %d (%d %d %d)).", msg.flags, msg.hash, msg.peer.id, msg.peer.ip, msg.peer.port);
        break;
    }
}
