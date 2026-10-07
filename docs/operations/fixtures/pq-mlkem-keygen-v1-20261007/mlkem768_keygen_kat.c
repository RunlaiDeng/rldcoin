/* TEST-ONLY known public standard d/z generation and dk-check comparator. No real
 * key generation, network,
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
    unsigned char seed[64] = {0}, expected_ek[1184] = {0}, expected_dk[2400] = {0};
    unsigned char generated_ek[1184] = {0}, generated_dk[2400] = {0};
    EVP_PKEY_CTX *ctx = NULL, *validation = NULL;
    EVP_PKEY *key = NULL;
    int code = 2, check_only = argc == 3 && strcmp(argv[1], "check") == 0;
    const char *reason = "expected check/dk2400 or d32/z32/ek1184/dk2400 owned files";
    if (check_only) {
        if (!exact_owned(argv[2], expected_dk, sizeof(expected_dk))) goto done;
    } else if (argc != 5 || !exact_owned(argv[1], seed, 32)
        || !exact_owned(argv[2], seed + 32, 32)
        || !exact_owned(argv[3], expected_ek, sizeof(expected_ek))
        || !exact_owned(argv[4], expected_dk, sizeof(expected_dk))) goto done;
    reason = "explicit ML-KEM-768 default context unavailable";
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", "provider=default");
    if (!ctx) goto done;
    if (check_only) {
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, expected_dk, sizeof(expected_dk)),
            OSSL_PARAM_construct_end()
        };
        if (EVP_PKEY_fromdata_init(ctx) <= 0) goto done;
        if (EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, params) <= 0) {
            reason = "expanded decapsulation key import refused"; code = 1; goto done;
        }
        validation = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=default");
        if (!validation) goto done;
        int valid = EVP_PKEY_private_check(validation);
        if (valid != 1) {
            reason = "decapsulation key check refused"; code = valid == 0 ? 1 : 2; goto done;
        }
    } else {
        reason = "test-only known-seed generation unavailable";
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, seed, sizeof(seed)),
            OSSL_PARAM_construct_end()
        };
        if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_params(ctx, params) <= 0
            || EVP_PKEY_generate(ctx, &key) <= 0 || !EVP_PKEY_is_a(key, "ML-KEM-768")) goto done;
        size_t ek_size = 0, dk_size = 0;
        if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
            generated_ek, sizeof(generated_ek), &ek_size) <= 0
            || EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY,
            generated_dk, sizeof(generated_dk), &dk_size) <= 0
            || ek_size != sizeof(generated_ek) || dk_size != sizeof(generated_dk)) goto done;
        if (CRYPTO_memcmp(generated_ek, expected_ek, sizeof(expected_ek)) != 0
            || CRYPTO_memcmp(generated_dk, expected_dk, sizeof(expected_dk)) != 0) {
            reason = "complete known standard ek or dk differs"; code = 1; goto done;
        }
    }
    printf("{\"candidate_only\":true,\"expected_bytes_match\":true,"
        "\"api_success_is_authentication\":false,\"implementation_source\":\"%s\"}\n",
        RLD_MLKEM_CANDIDATE_SOURCE);
    code = 0;
done:
    if (code) fprintf(stderr, "ML-KEM known-seed candidate refused: %s\n", reason);
    EVP_PKEY_CTX_free(validation); EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(key);
    OPENSSL_cleanse(seed, sizeof(seed)); OPENSSL_cleanse(expected_dk, sizeof(expected_dk));
    OPENSSL_cleanse(generated_dk, sizeof(generated_dk));
    return code;
}
