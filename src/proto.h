#ifndef PROTO_H
#define PROTO_H

#define PROTO_VERSION 1

typedef enum {
    MESSAGE_TYPE_CHALLENGE_REQUEST,
    MESSAGE_TYPE_CHALLENGE_RESPONSE,
} message_type_t;

typedef struct {
    message_type_t type;
    uint64_t version;
    size_t payload_size;
    char payload[0];
} message_t;

#endif /* PROTO_H */
