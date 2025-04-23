#pragma once

#include <stdint.h>
#include <netinet/in.h>

#include "http.h"

/**
 * Type for all of the DHT's IDs
 *
 * For simplicity we use a relatively small namespace.
 */
typedef uint16_t dht_id;

/**
 * Types of messages
 */
enum OPCODE
{
    LOOKUP,
    REPLY,
    STABILIZE,
    NOTIFY,
    JOIN,
    N_OPCODES,
};

static const char *opcode_str(enum OPCODE opcode)
{
    switch (opcode)
    {
    case LOOKUP:
        return "LOOKUP";
    case REPLY:
        return "REPLY";
    case STABILIZE:
        return "STABILIZE";
    case NOTIFY:
        return "NOTIFY";
    case JOIN:
        return "JOIN";
    default:
        return "INVALID OPCODE";
    }
}

/**
 * A complete description of a peer in the DHT
 *
 * A peer is specified by its ID, an IPv4 address and the port it's reachable by.
 */
struct __attribute__((packed)) peer
{
    dht_id id;
    struct in_addr ip;
    uint16_t port;
};

/**
 * The message structure for internal DHT messages
 *
 * Messages include flags indicating the message type, a hash, and a peer
 * description. The semantics of these differ depending on the message type,
 * in particular, not all are used for all messages.
 *
 * Lookup: `hash` indicates the ID of the datum that is requested, `peer`
 *         contains the lookup's originator.
 * Reply: `peer` describes the responsible peer, and `hash` its predecessor's ID
 * Stabilize: `peer` indicates the originator, and `hash` it's ID. This is
 *            redundant but avoids confusion.
 * Notify: `peer` indicates the originator's predecessor
 * Join: `peer` indicates the originator
 */
struct __attribute__((packed)) dht_message
{
    uint8_t flags;
    dht_id hash;
    struct peer peer;
};

/**
 * A description of our predecessor in the DHT
 *
 * Depending on the current state (e.g., joining) this may contain no valid peer
 * description.
 */
extern struct peer predecessor;

/**
 * A description of our anchor in the DHT
 */
extern struct peer anchor;

/**
 * Our own identity in the DHT
 */
extern struct peer self;

/**
 * A description of our successor in the DHT
 *
 * Depending on the current state (e.g., joining) this may contain no valid peer
 * description.
 */
extern struct peer successor;

/**
 * The socket used for communicating with the DHT
 */
extern int dht_socket;

/**
 * Compute the ID associated with the given string
 */
dht_id hash(const string str);

/**
 * Retrieve the peer that is responsible for the given ID
 *
 * The returned pointer may be NULL. In this case, we don't have sufficient
 * information to determine the responsible peer and a lookup is required.
 */
struct peer *dht_responsible(dht_id id);

/**
 * Derive an address for message transmission from a peer
 */
void peer_to_sockaddr(const struct peer peer, struct sockaddr_in *addr);

/**
 * Send a lookup message for the given ID
 */
void dht_lookup(dht_id id);

/**
 * Send a reply message to the given peer
 */
void dht_reply(const struct peer peer, dht_id id);

/**
 * Send a join message to the anchor
 */
void dht_join();

/**
 * Send a notify message to the given peer
*/
void dht_notify(const struct peer peer);

/**
 * Send a stabilize message to the given peer
*/
void dht_stabilize();

/**
 * Receive and process a DHT message
 */
void dht_handle_socket(void);
