
%module oqsphp
%{
#include <oqs/oqs.h>
%}
%include "oqs/oqs.h"
%{
typedef enum {
	OQS_ERROR = -1,
	OQS_SUCCESS = 0,
	OQS_EXTERNAL_LIB_ERROR_OPENSSL = 50,
} OQS_STATUS;
%}
#define OQS_RAND_alg_system "system"
#define OQS_RAND_alg_nist_kat "NIST-KAT"
#define OQS_RAND_alg_openssl "OpenSSL"
extern OQS_STATUS OQS_randombytes_switch_algorithm(const char *algorithm);
extern void OQS_randombytes(uint8_t *random_array, size_t bytes_to_read);
#define OQS_SIG_alg_dilithium_2 "Dilithium2"
#define OQS_SIG_alg_dilithium_3 "Dilithium3"
#define OQS_SIG_alg_dilithium_5 "Dilithium5"
#define OQS_SIG_alg_dilithium_2_aes "Dilithium2-AES"
#define OQS_SIG_alg_dilithium_3_aes "Dilithium3-AES"
#define OQS_SIG_alg_dilithium_5_aes "Dilithium5-AES"
#define OQS_SIG_alg_falcon_512 "Falcon-512"
#define OQS_SIG_alg_falcon_1024 "Falcon-1024"
#define OQS_SIG_alg_sphincs_haraka_128f_robust "SPHINCS+-Haraka-128f-robust"
#define OQS_SIG_alg_sphincs_haraka_128f_simple "SPHINCS+-Haraka-128f-simple"
#define OQS_SIG_alg_sphincs_haraka_128s_robust "SPHINCS+-Haraka-128s-robust"
#define OQS_SIG_alg_sphincs_haraka_128s_simple "SPHINCS+-Haraka-128s-simple"
#define OQS_SIG_alg_sphincs_haraka_192f_robust "SPHINCS+-Haraka-192f-robust"
#define OQS_SIG_alg_sphincs_haraka_192f_simple "SPHINCS+-Haraka-192f-simple"
#define OQS_SIG_alg_sphincs_haraka_192s_robust "SPHINCS+-Haraka-192s-robust"
#define OQS_SIG_alg_sphincs_haraka_192s_simple "SPHINCS+-Haraka-192s-simple"
#define OQS_SIG_alg_sphincs_haraka_256f_robust "SPHINCS+-Haraka-256f-robust"
#define OQS_SIG_alg_sphincs_haraka_256f_simple "SPHINCS+-Haraka-256f-simple"
#define OQS_SIG_alg_sphincs_haraka_256s_robust "SPHINCS+-Haraka-256s-robust"
#define OQS_SIG_alg_sphincs_haraka_256s_simple "SPHINCS+-Haraka-256s-simple"
#define OQS_SIG_alg_sphincs_sha256_128f_robust "SPHINCS+-SHA256-128f-robust"
#define OQS_SIG_alg_sphincs_sha256_128f_simple "SPHINCS+-SHA256-128f-simple"
#define OQS_SIG_alg_sphincs_sha256_128s_robust "SPHINCS+-SHA256-128s-robust"
#define OQS_SIG_alg_sphincs_sha256_128s_simple "SPHINCS+-SHA256-128s-simple"
#define OQS_SIG_alg_sphincs_sha256_192f_robust "SPHINCS+-SHA256-192f-robust"
#define OQS_SIG_alg_sphincs_sha256_192f_simple "SPHINCS+-SHA256-192f-simple"
#define OQS_SIG_alg_sphincs_sha256_192s_robust "SPHINCS+-SHA256-192s-robust"
#define OQS_SIG_alg_sphincs_sha256_192s_simple "SPHINCS+-SHA256-192s-simple"
#define OQS_SIG_alg_sphincs_sha256_256f_robust "SPHINCS+-SHA256-256f-robust"
#define OQS_SIG_alg_sphincs_sha256_256f_simple "SPHINCS+-SHA256-256f-simple"
#define OQS_SIG_alg_sphincs_sha256_256s_robust "SPHINCS+-SHA256-256s-robust"
#define OQS_SIG_alg_sphincs_sha256_256s_simple "SPHINCS+-SHA256-256s-simple"
#define OQS_SIG_alg_sphincs_shake256_128f_robust "SPHINCS+-SHAKE256-128f-robust"
#define OQS_SIG_alg_sphincs_shake256_128f_simple "SPHINCS+-SHAKE256-128f-simple"
#define OQS_SIG_alg_sphincs_shake256_128s_robust "SPHINCS+-SHAKE256-128s-robust"
#define OQS_SIG_alg_sphincs_shake256_128s_simple "SPHINCS+-SHAKE256-128s-simple"
#define OQS_SIG_alg_sphincs_shake256_192f_robust "SPHINCS+-SHAKE256-192f-robust"
#define OQS_SIG_alg_sphincs_shake256_192f_simple "SPHINCS+-SHAKE256-192f-simple"
#define OQS_SIG_alg_sphincs_shake256_192s_robust "SPHINCS+-SHAKE256-192s-robust"
#define OQS_SIG_alg_sphincs_shake256_192s_simple "SPHINCS+-SHAKE256-192s-simple"
#define OQS_SIG_alg_sphincs_shake256_256f_robust "SPHINCS+-SHAKE256-256f-robust"
#define OQS_SIG_alg_sphincs_shake256_256f_simple "SPHINCS+-SHAKE256-256f-simple"
#define OQS_SIG_alg_sphincs_shake256_256s_robust "SPHINCS+-SHAKE256-256s-robust"
#define OQS_SIG_alg_sphincs_shake256_256s_simple "SPHINCS+-SHAKE256-256s-simple"
#define OQS_SIG_algs_length 44
extern const char *OQS_SIG_alg_identifier(size_t i);
extern int OQS_SIG_alg_count(void);
extern int OQS_SIG_alg_is_enabled(const char *method_name);
%{
typedef struct OQS_SIG {
	const char *method_name;
	const char *alg_version;
	uint8_t claimed_nist_level;
	bool euf_cma;
	size_t length_public_key;
	size_t length_secret_key;
	size_t length_signature;
	OQS_STATUS (*keypair)(uint8_t *public_key, uint8_t *secret_key);
	OQS_STATUS (*sign)(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
	OQS_STATUS (*verify)(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
} OQS_SIG;
%}
extern OQS_SIG *OQS_SIG_new(const char *method_name);
extern OQS_STATUS OQS_SIG_keypair(const OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_SIG_sign(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
extern OQS_STATUS OQS_SIG_verify(const OQS_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
extern void OQS_SIG_free(OQS_SIG *sig);
#define OQS_KEM_alg_bike_l1 "BIKE-L1"
#define OQS_KEM_alg_bike_l3 "BIKE-L3"
#define OQS_KEM_alg_bike_l5 "BIKE-L5"
#define OQS_KEM_alg_classic_mceliece_348864 "Classic-McEliece-348864"
#define OQS_KEM_alg_classic_mceliece_348864f "Classic-McEliece-348864f"
#define OQS_KEM_alg_classic_mceliece_460896 "Classic-McEliece-460896"
#define OQS_KEM_alg_classic_mceliece_460896f "Classic-McEliece-460896f"
#define OQS_KEM_alg_classic_mceliece_6688128 "Classic-McEliece-6688128"
#define OQS_KEM_alg_classic_mceliece_6688128f "Classic-McEliece-6688128f"
#define OQS_KEM_alg_classic_mceliece_6960119 "Classic-McEliece-6960119"
#define OQS_KEM_alg_classic_mceliece_6960119f "Classic-McEliece-6960119f"
#define OQS_KEM_alg_classic_mceliece_8192128 "Classic-McEliece-8192128"
#define OQS_KEM_alg_classic_mceliece_8192128f "Classic-McEliece-8192128f"
#define OQS_KEM_alg_hqc_128 "HQC-128"
#define OQS_KEM_alg_hqc_192 "HQC-192"
#define OQS_KEM_alg_hqc_256 "HQC-256"
#define OQS_KEM_alg_kyber_512 "Kyber512"
#define OQS_KEM_alg_kyber_768 "Kyber768"
#define OQS_KEM_alg_kyber_1024 "Kyber1024"
#define OQS_KEM_alg_kyber_512_90s "Kyber512-90s"
#define OQS_KEM_alg_kyber_768_90s "Kyber768-90s"
#define OQS_KEM_alg_kyber_1024_90s "Kyber1024-90s"
#define OQS_KEM_alg_ntruprime_sntrup761 "sntrup761"
#define OQS_KEM_alg_frodokem_640_aes "FrodoKEM-640-AES"
#define OQS_KEM_alg_frodokem_640_shake "FrodoKEM-640-SHAKE"
#define OQS_KEM_alg_frodokem_976_aes "FrodoKEM-976-AES"
#define OQS_KEM_alg_frodokem_976_shake "FrodoKEM-976-SHAKE"
#define OQS_KEM_alg_frodokem_1344_aes "FrodoKEM-1344-AES"
#define OQS_KEM_alg_frodokem_1344_shake "FrodoKEM-1344-SHAKE"
#define OQS_KEM_algs_length 29
extern const char *OQS_KEM_alg_identifier(size_t i);
extern int OQS_KEM_alg_count(void);
extern int OQS_KEM_alg_is_enabled(const char *method_name);
%{
typedef struct OQS_KEM {
	const char *method_name;
	const char *alg_version;
	uint8_t claimed_nist_level;
	bool ind_cca;
	size_t length_public_key;
	size_t length_secret_key;
	size_t length_ciphertext;
	size_t length_shared_secret;
	OQS_STATUS (*keypair)(uint8_t *public_key, uint8_t *secret_key);
	OQS_STATUS (*encaps)(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
	OQS_STATUS (*decaps)(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
} OQS_KEM;
%}
extern OQS_KEM *OQS_KEM_new(const char *method_name);
extern OQS_STATUS OQS_KEM_keypair(const OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_encaps(const OQS_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_decaps(const OQS_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
extern void OQS_KEM_free(OQS_KEM *kem);