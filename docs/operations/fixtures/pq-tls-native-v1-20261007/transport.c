/* Loopback-only TLS policy candidate. No mesh, ledger or custody authority.
 * Only public ping/pong markers cross the socket after exact peer and policy
 * verification. The application never reads a Python/OpenSSL object's memory.
 * Compilation and controller pin the exact OpenSSL headers and libraries.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <fcntl.h>

#define GROUP "X25519MLKEM768"
#define CIPHER "TLS_AES_256_GCM_SHA384"
#define LIMIT 65536
#ifndef RLD_TLS_CANDIDATE_SOURCE
#error "Build must bind the actual TLS candidate source SHA-256"
#endif
static const char ping[] = "RLD-PQ-TLS-CANDIDATE-V1:ping";
static const char pong[] = "RLD-PQ-TLS-CANDIDATE-V1:pong";

static double now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}
static int wait_fd(int fd, short events, double deadline) {
    double left = deadline - now();
    if (left <= 0) return 0;
    struct pollfd poller = {fd, events, 0};
    int result;
    do { result = poll(&poller, 1, (int)(left * 1000.0)); }
    while (result < 0 && errno == EINTR && now() < deadline);
    return result > 0 && (poller.revents & events) != 0;
}
static int regular(const char *path, int private_key) {
    struct stat info;
    return lstat(path, &info) == 0 && S_ISREG(info.st_mode)
        && info.st_uid == getuid() && info.st_size > 0 && info.st_size <= LIMIT
        && (!private_key || (info.st_mode & 077) == 0);
}
static int await_ssl(SSL *ssl, int result, double deadline) {
    int error = SSL_get_error(ssl, result);
    if (error == SSL_ERROR_WANT_READ) return wait_fd(SSL_get_fd(ssl), POLLIN, deadline);
    if (error == SSL_ERROR_WANT_WRITE) return wait_fd(SSL_get_fd(ssl), POLLOUT, deadline);
    return 0;
}
static int handshake(SSL *ssl, int server, double deadline) {
    while (now() < deadline) {
        int result = server ? SSL_accept(ssl) : SSL_connect(ssl);
        if (result == 1) return 1;
        if (!await_ssl(ssl, result, deadline)) return 0;
    }
    return 0;
}
static int marker(SSL *ssl, const char *expected, int write_it, double deadline) {
    char bytes[64]; size_t length = strlen(expected), offset = 0;
    if (length >= sizeof(bytes)) return 0;
    while (offset < length && now() < deadline) {
        int result = write_it ? SSL_write(ssl, expected + offset, (int)(length - offset))
            : SSL_read(ssl, bytes + offset, (int)(length - offset));
        if (result > 0) offset += (size_t)result;
        else if (!await_ssl(ssl, result, deadline)) return 0;
    }
    return offset == length && (write_it || CRYPTO_memcmp(bytes, expected, length) == 0);
}
static int peer_policy(SSL *ssl, const unsigned char pin[32]) {
    const char *group = SSL_get0_group_name(ssl);
    if (SSL_version(ssl) != TLS1_3_VERSION || SSL_session_reused(ssl)
        || !group || strcmp(group, GROUP) != 0
        || strcmp(SSL_get_cipher_name(ssl), CIPHER) != 0
        || SSL_get_verify_result(ssl) != X509_V_OK) return 0;
    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (!cert) return 0;
    unsigned char digest[32]; unsigned int length = 0;
    EVP_PKEY *key = X509_get_pubkey(cert);
    int valid = key && EVP_PKEY_is_a(key, "ML-DSA-87")
        && X509_digest(cert, EVP_sha256(), digest, &length) == 1 && length == 32
        && CRYPTO_memcmp(pin, digest, 32) == 0
        && X509_cmp_current_time(X509_get0_notBefore(cert)) < 0
        && X509_cmp_current_time(X509_get0_notAfter(cert)) > 0
        && X509_verify(cert, key) == 1;
    EVP_PKEY_free(key); X509_free(cert); return valid;
}
int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    SSL_CTX *context = NULL; SSL *ssl = NULL; int fd = -1, listener = -1, code = 1;
    const char *failure = "arguments";
    unsigned char pin[32];
    if (argc != 7 || (strcmp(argv[1], "client") && strcmp(argv[1], "server"))
        || strlen(argv[6]) != 64) goto done;
    for (size_t i = 0; i < 32; i++) {
        unsigned int byte;
        for (size_t j = 0; j < 2; j++) {
            char digit = argv[6][i * 2 + j];
            if (!((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f'))) goto done;
        }
        if (sscanf(argv[6] + i * 2, "%2x", &byte) != 1) goto done;
        pin[i] = (unsigned char)byte;
    }
    char *end = NULL; errno = 0; long port = strtol(argv[2], &end, 10);
    int server = !strcmp(argv[1], "server");
    if (errno || !end || *end || port < (server ? 0 : 1) || port > 65535) goto done;
    failure = "bounded owned credentials";
    if (!regular(argv[3], 0) || !regular(argv[4], 1) || !regular(argv[5], 0)) goto done;
    failure = "fixed TLS policy";
    context = SSL_CTX_new_ex(NULL, "provider=default", server ? TLS_server_method() : TLS_client_method());
    if (!context || !SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION)
        || !SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION)
        || !SSL_CTX_set1_groups_list(context, GROUP)
        || !SSL_CTX_set1_sigalgs_list(context, "mldsa87")
        || !SSL_CTX_set_ciphersuites(context, CIPHER)) goto done;
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(context, SSL_OP_NO_TICKET);
    SSL_CTX_set_num_tickets(context, 0);
    SSL_CTX_set_max_cert_list(context, LIMIT);
    SSL_CTX_set_verify_depth(context, 0);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | (server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), NULL);
    failure = "exact peer trust and own identity";
    if (!SSL_CTX_load_verify_locations(context, argv[5], NULL)
        || !SSL_CTX_use_certificate_file(context, argv[3], SSL_FILETYPE_PEM)
        || !SSL_CTX_use_PrivateKey_file(context, argv[4], SSL_FILETYPE_PEM)
        || !SSL_CTX_check_private_key(context)) goto done;
    struct sockaddr_in address; memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((unsigned short)port);
    double deadline = now() + 3.0;
    failure = "loopback socket";
    if (server) {
        listener = socket(AF_INET, SOCK_STREAM, 0);
        if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address))
            || listen(listener, 1)) goto done;
        socklen_t length = sizeof(address);
        if (getsockname(listener, (struct sockaddr *)&address, &length)) goto done;
        printf("READY %u\n", (unsigned int)ntohs(address.sin_port)); fflush(stdout);
        if (!wait_fd(listener, POLLIN, deadline)) goto done;
        fd = accept(listener, NULL, NULL);
        close(listener); listener = -1;
    } else {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0 || fcntl(fd, F_SETFL, O_NONBLOCK)) goto done;
        if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0 && errno != EINPROGRESS) goto done;
        if (!wait_fd(fd, POLLOUT, deadline)) goto done;
        int error = 0; socklen_t length = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) || error) goto done;
    }
    if (fd < 0 || fcntl(fd, F_SETFL, O_NONBLOCK)) goto done;
    ssl = SSL_new(context);
    if (!ssl || !SSL_set_fd(ssl, fd)) goto done;
    failure = "TLS handshake refused";
    if (!handshake(ssl, server, deadline)) goto done;
    failure = "peer or negotiated policy refused";
    if (!peer_policy(ssl, pin)) goto done;
    failure = "public marker exchange";
    if (server) {
        if (!marker(ssl, ping, 0, deadline) || !marker(ssl, pong, 1, deadline)) goto done;
    } else {
        if (!marker(ssl, ping, 1, deadline) || !marker(ssl, pong, 0, deadline)) goto done;
    }
    printf("{\"candidate_only\":true,\"tls\":\"TLSv1.3\",\"group\":\"%s\","
        "\"cipher\":\"%s\",\"peer_algorithm\":\"ML-DSA-87\",\"public_marker_verified\":true,"
        "\"implementation_source\":\"%s\"}\n",
        SSL_get0_group_name(ssl), SSL_get_cipher_name(ssl), RLD_TLS_CANDIDATE_SOURCE);
    code = 0;
done:
    if (code) fprintf(stderr, "TLS candidate refused: %s\n", failure);
    /* SSL_free/close owns only this fresh connection; no unrelated process. */
    SSL_free(ssl); SSL_CTX_free(context);
    if (fd >= 0) close(fd);
    if (listener >= 0) close(listener);
    return code;
}
