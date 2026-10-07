/* TEST-ONLY deterministic encapsulation/known-answer comparator. Never use supplied
 * entropy for production key establishment. No real key generation, network,
 * TLS integration, secret output or authority. A bad ciphertext may correctly
 * yield implicit-rejection bytes; API success is not ciphertext authentication.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#ifndef RLD_MLKEM_CANDIDATE_SOURCE
#error "Build must bind exact ML-KEM candidate source SHA256"
#endif
static int exact_owned(const char *path, unsigned char *out, size_t size) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return 0;
    struct stat info;
    int valid = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == getuid()
        && info.st_size == (off_t)size && (info.st_mode & 077) == 0;
    size_t offset = 0;
    while (valid && offset < size) {
        ssize_t count = read(fd, out + offset, size - offset);
        if (count > 0) offset += (size_t)count;
        else if (count < 0 && errno == EINTR) continue;
        else valid = 0;
    }
    unsigned char extra;
    if (valid && read(fd, &extra, 1) != 0) valid = 0;
    if (close(fd) != 0) valid = 0;
    return valid;
}
int main(int argc, char **argv) {
    unsigned char ek[1184] = {0}, entropy[32] = {0}, expected_c[1088] = {0};
    unsigned char expected_k[32] = {0}, ciphertext[1088] = {0}, secret[32] = {0};
    EVP_PKEY_CTX *import = NULL, *operation = NULL;
    EVP_PKEY *key = NULL;
    int code = 2, check_only = argc == 3 && strcmp(argv[1], "check") == 0;
    const char *reason = "expected check/ek1184 or ek1184/m32/c1088/k32 owned files";
    if ((!check_only && argc != 5)
        || !exact_owned(argv[check_only ? 2 : 1], ek, sizeof(ek))) goto done;
    if (!check_only && (!exact_owned(argv[2], entropy, sizeof(entropy))
        || !exact_owned(argv[3], expected_c, sizeof(expected_c))
        || !exact_owned(argv[4], expected_k, sizeof(expected_k)))) goto done;
    reason = "explicit default ML-KEM-768 import unavailable";
    import = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", "provider=default");
    OSSL_PARAM public_parameters[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, ek, sizeof(ek)),
        OSSL_PARAM_construct_end()
    };
    if (!import || EVP_PKEY_fromdata_init(import) <= 0) goto done;
    if (EVP_PKEY_fromdata(import, &key, EVP_PKEY_PUBLIC_KEY, public_parameters) <= 0) {
        reason = "public key import refused"; code = 1; goto done;
    }
    if (!EVP_PKEY_is_a(key, "ML-KEM-768")) goto done;
    operation = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=default");
    if (!operation) goto done;
    int valid = EVP_PKEY_public_check(operation);
    if (valid != 1) {
        reason = "public key check refused"; code = valid == 0 ? 1 : 2; goto done;
    }
    if (!check_only) {
        reason = "test-only deterministic encapsulation unavailable";
        OSSL_PARAM parameters[] = {
            OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, entropy, sizeof(entropy)),
            OSSL_PARAM_construct_end()
        };
        size_t c_size = sizeof(ciphertext), k_size = sizeof(secret);
        if (EVP_PKEY_encapsulate_init(operation, parameters) <= 0
            || EVP_PKEY_encapsulate(operation, ciphertext, &c_size, secret, &k_size) <= 0
            || c_size != sizeof(ciphertext) || k_size != sizeof(secret)) goto done;
        if (CRYPTO_memcmp(ciphertext, expected_c, sizeof(ciphertext)) != 0
            || CRYPTO_memcmp(secret, expected_k, sizeof(secret)) != 0) {
            reason = "complete known-answer ciphertext or shared bytes differ"; code = 1; goto done;
        }
    }
    printf("{\"candidate_only\":true,\"test_only_entropy\":true,\"expected_bytes_match\":true,"
        "\"api_success_is_authentication\":false,\"implementation_source\":\"%s\"}\n",
        RLD_MLKEM_CANDIDATE_SOURCE);
    code = 0;
done:
    if (code) fprintf(stderr, "ML-KEM encaps candidate refused: %s\n", reason);
    EVP_PKEY_CTX_free(operation); EVP_PKEY_free(key); EVP_PKEY_CTX_free(import);
    OPENSSL_cleanse(entropy, sizeof(entropy)); OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(expected_k, sizeof(expected_k));
    return code;
}
