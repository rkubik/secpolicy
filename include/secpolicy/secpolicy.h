#ifndef SECPOLICY_H
#define SECPOLICY_H

#include <inttypes.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SECPOLICY_RESULT_PERMS (1 << 0)
#define SECPOLICY_RESULT_PROGRAM (1 << 1)
#define SECPOLICY_RESULT_UID (1 << 2)
#define SECPOLICY_RESULT_GID (1 << 3)
#define SECPOLICY_RESULT_USER (1 << 4)
#define SECPOLICY_RESULT_GROUP (1 << 5)
#define SECPOLICY_RESULT_CALLBACK (1 << 6)
#define SECPOLICY_RESULT_CHALLENGE (1 << 7)
#define SECPOLICY_RESULT_CREDS (1 << 8)

typedef struct secpolicy secpolicy_t;
typedef uint64_t secpolicy_result_t;
typedef struct secpolicy_peer secpolicy_peer_t;
typedef struct secpolicy_challenge secpolicy_challenge_t;

/**
 * @brief Create a new security policy.
 *
 * @return Security policy, or NULL on error
 */
secpolicy_t *secpolicy_create(void);

/**
 * @brief Destroy a security policy.
 *
 * @param[in] policy Pointer to security policy
 */
void secpolicy_destroy(secpolicy_t *policy);

/**
 * @brief Policy for file permissions. If connection is not file-based then this
 * policy is ignored.
 *
 * @note Server-side. Only applicable to file-based local sockets.
 *
 * @param[in] policy Pointer to security policy
 * @param[in] perms Expected file permissions
 */
void secpolicy_rule_perms(secpolicy_t *policy, mode_t perms);

/**
 * @brief Create a challenge to send to the peer to solve.
 *
 * @note The peer must use this library to solve the challenge
 * (secpolicy_challenge_solve).
 *
 * @param[in] policy Pointer to security policy
 * @param[in] create Callback to create challenge
 * @param[in] verify Callback to verify peer response
 * @param[in] ctx User context (optional)
 */
void secpolicy_rule_challenge_send(
    secpolicy_t *policy, bool (*create)(secpolicy_challenge_t *, void *),
    bool (*verify)(const secpolicy_challenge_t *, const secpolicy_challenge_t *,
                   void *),
    void *ctx);

/**
 * @brief Solve a challenge received from a peer.
 *
 * @param[in] policy Pointer to security policy
 * @param[in] solve Callback to solve peer challenge
 * @param[in] ctx User context (optional)
 */
void secpolicy_rule_challenge_receive(
    secpolicy_t *policy,
    bool (*solve)(const secpolicy_challenge_t *, secpolicy_challenge_t *,
                  void *),
    void *ctx);

/**
 * @brief Policy for peer user ID.
 *
 * @param[in] policy Pointer to security policy
 * @param[in] uid User ID
 */
void secpolicy_rule_uid(secpolicy_t *policy, uid_t uid);

/**
 * @brief Policy for peer group ID.
 *
 * @param[in] policy Pointer to security policy
 * @param[in] gid Group ID
 */
void secpolicy_rule_gid(secpolicy_t *policy, gid_t gid);

/**
 * @brief Policy for peer user name.
 *
 * @param[in] policy Pointer to security policy
 * @param[in] user User name
 */
void secpolicy_rule_user(secpolicy_t *policy, const char *user);

/**
 * @brief Policy for peer group name.
 *
 * @param[in] policy Pointer to security policy
 * @param[in] group Group name
 */
void secpolicy_rule_group(secpolicy_t *policy, const char *group);

/**
 * @brief Policy for security credentials.
 *
 * @note See https://lwn.net/Articles/62370/
 *
 * @param[in] policy Pointer to security policy
 * @param[in] creds Credentials
 */
void secpolicy_rule_creds(secpolicy_t *policy, const char *creds);

/**
 * @brief Policy for program path.
 *
 * @param[in] policy Pointer to security policy
 * @param[in] program Program path
 */
void secpolicy_rule_program(secpolicy_t *policy, const char *program);

/**
 * @brief User-provided policy callback.
 *
 * @param[in] policy Pointer to security policy
 * @param[in] cb User callback
 * @param[in] ctx User context (optional)
 */
void secpolicy_rule_callback(secpolicy_t *policy,
                             bool (*func)(const secpolicy_peer_t *, void *),
                             void *ctx);

/**
 * @brief Apply policy to peer connection.
 *
 * @note Users should check that the function succeeds before checking the
 * policy result. A policy result of zero means that the connection is trusted
 * by the policy.
 *
 * @param[in] policy Pointer to security policy
 * @param[in] sock Peer socket
 * @param[out] Pointer to policy result bitmask
 *
 * @return 0 on success and result set, otherwise non-zero on error with errno
 * set
 *
 * EINVAL   Invalid parameters to function
 * EBADF    Could not retrieve peer information from provided socket
 * ENOMEM   Failed to allocate memory
 *
 */
int secpolicy_apply(secpolicy_t *policy, int sock, secpolicy_result_t *result);

/**
 * @brief Return peer socket
 *
 * @param[in] peer Pointer to peer data
 *
 * @return Peer socket
 */
int secpolicy_peer_sock(const secpolicy_peer_t *peer);

/**
 * @brief Return peer pid
 *
 * @param[in] peer Pointer to peer data
 *
 * @return Peer pid
 */
pid_t secpolicy_peer_pid(const secpolicy_peer_t *peer);

/**
 * @brief Return peer program
 *
 * @param[in] peer Pointer to peer data
 *
 * @return Peer program
 */
const char *secpolicy_peer_program(const secpolicy_peer_t *peer);

/**
 * @brief Return peer uid
 *
 * @param[in] peer Pointer to peer data
 *
 * @return Peer uid
 */
uid_t secpolicy_peer_uid(const secpolicy_peer_t *peer);

/**
 * @brief Return peer gid
 *
 * @param[in] peer Pointer to peer data
 *
 * @return Peer gid
 */
gid_t secpolicy_peer_gid(const secpolicy_peer_t *peer);

/**
 * @brief Return peer user
 *
 * @param[in] peer Pointer to peer data
 *
 * @return Peer user
 */
const char *secpolicy_peer_user(const secpolicy_peer_t *peer);

/**
 * @brief Return peer group
 *
 * @param[in] peer Pointer to peer data
 *
 * @return Peer group
 */
const char *secpolicy_peer_group(const secpolicy_peer_t *peer);

/**
 * @brief Return peer perms
 *
 * @param[in] peer Pointer to peer data
 *
 * @return Peer perms
 */
mode_t secpolicy_peer_perms(const secpolicy_peer_t *peer);

/**
 * @brief Return peer creds
 *
 * @param[in] peer Pointer to peer data
 *
 * @return Peer creds
 */
const char *secpolicy_peer_creds(const secpolicy_peer_t *peer);

/**
 * @brief Set challenge data and size
 *
 * @param[in] challenge Pointer to challenge
 * @param[in] data Pointer to data buffer
 * @param[in] size Size of data buffer
 *
 * @return true on success, false on error
 */
bool secpolicy_challenge_set_data(secpolicy_challenge_t *challenge,
                                  const uint8_t *data, size_t size);

/**
 * @brief Return challenge data
 *
 * @param[in] challenge Pointer to challenge
 *
 * @return Challenge data
 */
const uint8_t *secpolicy_challenge_data(const secpolicy_challenge_t *challenge);

/**
 * @brief Return challenge data size
 *
 * @param[in] challenge Pointer to challenge
 *
 * @return Challenge data size
 */
size_t secpolicy_challenge_size(const secpolicy_challenge_t *challenge);

#ifdef __cplusplus
}
#endif

#endif /* SECPOLICY_H */
