# Socket Security Policy

C library for securing local (UNIX domain) sockets.

Local sockets (or UNIX domain sockets) are used for interprocess communication between processes on the same machine. Using local sockets without peer authentication and without securing the connection could result in data leakage, data injection, DoS, and privilege escalation[1]. To avoid these issues it is recommended that each process perform peer authentication before communicating over the socket. This can include, but is not limited to:

- File permission (file-based local sockets)
- Peer UID/GID verification
- Peer User and Group name verification
- Peer Program name verification
- Token-based/Challenge-based verification (experimental, API may change)

## Getting Started

### Building

Dependencies:

- cmake (>=2.8)
- gcc
- C++17 (for tests)

```
$ mkdir build
$ cmake ..
$ make
```

### Integration

The following steps illustrate how to integrate this library into your existing program.

1. Server-side: Define a policy to verify peer connections. Note: A new policy does not need to be created for each client. Depending on your use case, a single policy can be created and saved for the lifetime of the server connection.

    ```
    secpolicy_t *policy = secpolicy_create();
    /* Peer process must be running with uid 1000 and gid 1000 */
    secpolicy_peer(policy, 1000, 1000);
    ```

1. Server-side: When a peer connects, apply the policy and take action.

    ```
    secpolicy_result_t result;
    if (secpolicy_apply(policy, peer, &result)) {
        /* Failed to verify peer due to an error */
        ...
    } else if (result != 0) {
        fprintf(stderr, "Socket security policy failed: 0x%" PRIx64 "\n", result);
        /* Peer failed verification, disconnect the client */
        (void)close(client);
        ...
    }
    ```

1. Server-side: When the server program is shutting down, destroy the policy to avoid memory leaks.

    ```
    secpolicy_destroy(policy);
    ```

1. Client-side: Define a policy to verify server authenticity.

    ```
    secpolicy_t *policy = secpolicy_create();
    /* Check server process executable */
    secpolicy_program("/opt/organization/bin/prog");
    ```

1. Client-side: When connected, apply the policy and take action.

    ```
    secpolicy_result_t result;
    if (secpolicy_apply(policy, peer, &result)) {
        /* Failed to verify peer due to an error */
        ...
    } else if (result != 0) {
        fprintf(stderr, "Socket security policy failed: 0x%" PRIx64 "\n", result);
        /* Server failed verification */
        ...
    }
    ```

1. Client-side: When the client program is shutting down, destroy the policy to avoid memory leaks.

    ```
    secpolicy_destroy(policy);
    ```

See [examples](./examples) for additional details.

## TODO

- Container support

## References

[1] https://jiayunhan.github.io/material/misuse_ccs16.pdf
