/* Official known-answer-vector comparator only. No real key generation, network,
 * TLS integration, secret output or authority. A bad ciphertext may correctly
 * yield implicit-rejection bytes; API success is not ciphertext authentication.
 */
#include <fcntl.h>
#include <stdio.h>
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
    unsigned char dk[2400] = {0}, ciphertext[1088] = {0}, expected[32] = {0}, secret[32] = {0};
    EVP_PKEY_CTX *import = NULL, *operation = NULL;
    EVP_PKEY *key = NULL;
    int code = 2;
    const char *reason = "expected exact owned vector files dk2400/c1088/k32";
    if (argc != 4 || !exact_owned(argv[1], dk, sizeof(dk))
        || !exact_owned(argv[2], ciphertext, sizeof(ciphertext))
        || !exact_owned(argv[3], expected, sizeof(expected))) goto done;
    reason = "explicit default ML-KEM-768 import unavailable";
    import = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", "provider=default");
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, dk, sizeof(dk)),
        OSSL_PARAM_construct_end()
    };
    if (!import || EVP_PKEY_fromdata_init(import) <= 0
        || EVP_PKEY_fromdata(import, &key, EVP_PKEY_KEYPAIR, parameters) <= 0
        || !EVP_PKEY_is_a(key, "ML-KEM-768")) goto done;
    reason = "explicit decapsulation unavailable";
    operation = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=default");
    size_t secret_size = sizeof(secret);
    if (!operation || EVP_PKEY_decapsulate_init(operation, NULL) <= 0
        || EVP_PKEY_decapsulate(operation, secret, &secret_size, ciphertext, sizeof(ciphertext)) <= 0
        || secret_size != sizeof(secret)) goto done;
    if (CRYPTO_memcmp(secret, expected, sizeof(secret)) != 0) {
        reason = "known-answer secret differs"; code = 1; goto done;
    }
    printf("{\"candidate_only\":true,\"algorithm\":\"ML-KEM-768\",\"expected_bytes_match\":true,"
        "\"api_success_is_authentication\":false,\"implementation_source\":\"%s\"}\n",
        RLD_MLKEM_CANDIDATE_SOURCE);
    code = 0;
done:
    if (code) fprintf(stderr, "ML-KEM candidate refused: %s\n", reason);
    EVP_PKEY_CTX_free(operation); EVP_PKEY_free(key); EVP_PKEY_CTX_free(import);
    OPENSSL_cleanse(dk, sizeof(dk)); OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(expected, sizeof(expected));
    return code;
}
