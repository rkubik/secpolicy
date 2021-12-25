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

#define SECPOLICY_RESULT_PERMS 0x1
#define SECPOLICY_RESULT_PROGRAM 0x2
#define SECPOLICY_RESULT_PEER 0x4
#define SECPOLICY_RESULT_PEER_NAME 0x8
#define SECPOLICY_RESULT_CB 0x10
#define SECPOLICY_RESULT_CHALLENGE 0x20
#define SECPOLICY_RESULT_PEER_CREDS 0x40

#define USER_MAX 32
#define CREDS_MAX 64

typedef struct secpolicy secpolicy_t;

typedef uint64_t secpolicy_result_t;

typedef struct {
    pid_t pid;
    char program[PATH_MAX];
    uid_t uid;
    char user[USER_MAX];
    gid_t gid;
    char group[USER_MAX];
    mode_t perms;
    char creds[CREDS_MAX];
} secpolicy_peer_t;

typedef struct {
    uint8_t *data;
    size_t size;
} secpolicy_challenge_t;

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
void secpolicy_perms(secpolicy_t *policy, mode_t perms);

/**
 * @brief Generate a challenge for the peer to solve.
 *
 * @note Experimental. API is subject to change.
 *
 * @param[in] policy Pointer to security policy
 * @param[in] create Callback to create challenge
 * @param[in] destroy Callback to destroy challenge
 * @param[in] verify Callback to verify peer response
 * @param[in] solve Callback to solve peer challenge
 * @param[in] ctx User context (optional)
 */
void secpolicy_challenge(secpolicy_t *policy,
                         bool (*create)(secpolicy_challenge_t *, void *),
                         void (*destroy)(secpolicy_challenge_t *, void *),
                         bool (*verify)(const secpolicy_challenge_t *,
                                        const secpolicy_challenge_t *, void *),
                         bool (*solve)(const secpolicy_challenge_t *,
                                       secpolicy_challenge_t *, void *),
                         void *ctx);

/**
 * @brief Policy for peer user ID and group ID.
 *
 * @param[in] policy Pointer to security policy
 * @param[in] uid User ID
 * @param[in] gid Group ID
 */
void secpolicy_peer(secpolicy_t *policy, uid_t uid, gid_t gid);

/**
 * @brief Policy for peer user name and group name.
 *
 * @param[in] policy Pointer to security policy
 * @param[in] user User name
 * @param[in] group Group name
 */
void secpolicy_peer_name(secpolicy_t *policy, const char *user,
                         const char *group);

/**
 * @brief Policy for security credentials.
 *
 * @note See https://lwn.net/Articles/62370/
 *
 * @param[in] policy Pointer to security policy
 * @param[in] creds Credentials
 */
void secpolicy_peer_creds(secpolicy_t *policy, const char *creds);

/**
 * @brief Policy for program path.
 *
 * @param[in] policy Pointer to security policy
 * @param[in] program Program path
 */
void secpolicy_program(secpolicy_t *policy, const char *program);

/**
 * @brief User-provided policy callback.
 *
 * @param[in] policy Pointer to security policy
 * @param[in] cb User callback
 * @param[in] ctx User context (optional)
 */
void secpolicy_cb(secpolicy_t *policy,
                  bool (*verify)(const secpolicy_peer_t *, void *), void *ctx);

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
 *
 */
int secpolicy_apply(secpolicy_t *policy, int sock, secpolicy_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* SECPOLICY_H */
