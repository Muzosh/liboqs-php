<?php

class OQS_SIGNATURE
{
    /** Printable string representing the name of the signature scheme. */
    public string $method_name;

    /**
     * Printable string representing the version of the cryptographic algorithm.
     *
     * Implementations with the same method_name and same alg_version will be interoperable.
     * See README.md for information about algorithm compatibility.
     */
    public string $alg_version;

    /** The NIST security level (1, 2, 3, 4, 5) claimed in this algorithm's original NIST submission. */
    public int $claimed_nist_level;

    /** Whether the signature offers EUF-CMA security (TRUE) or not (FALSE). */
    public bool $euf_cma;

    /** The (maximum) length, in bytes, of public keys for this signature scheme. */
    public int $length_public_key;
    /** The (maximum) length, in bytes, of private keys for this signature scheme. */
    public int $length_private_key;
    /** The (maximum) length, in bytes, of signatures for this signature scheme. */
    public int $length_signature;

    /**
     * Constructor.
     * @param string $method_name The name of the signature scheme to use
     * @return OQS_SIGNATURE
     */
    public function __construct(string $method_name)
    {
    }
    /**
     * Generates a keypair for the signature scheme.
     * @param string $public_key The public key - will be populated by this function
     * @param string $private_key The private key - will be populated by this function
     * @return int OQS_SUCCESS on success, OQS_ERROR on failure
     */
    public function keypair(string &$public_key, string &$private_key): int
    {
    }
    /**
     * Signs a message.
     * @param string $signature The signature - will be populated by this function
     * @param string $message The message to sign
     * @param string $private_key The private key
     * @return int OQS_SUCCESS on success, OQS_ERROR on failure
     */
    public function sign(string &$signature, string $message, string $private_key): int
    {
    }
    /**
     * Verifies a signature.
     * @param string $message The message to verify
     * @param string $signature The signature
     * @param string $public_key The public key
     * @return int OQS_SUCCESS on success, OQS_ERROR on failure
     */
    public function verify(string $message, string $signature, string $public_key): int
    {
    }
}
class OQS_KEYENCAPSULATION
{
    /** Printable string representing the name of the signature scheme. */
    public string $method_name;

    /**
     * Printable string representing the version of the cryptographic algorithm.
     *
     * Implementations with the same method_name and same alg_version will be interoperable.
     * See README.md for information about algorithm compatibility.
     */
    public string $alg_version;

    /** The NIST security level (1, 2, 3, 4, 5) claimed in this algorithm's original NIST submission. */
    public int $claimed_nist_level;

    /** Whether the signature offers EUF-CMA security (TRUE) or not (FALSE). */
    public bool $ind_cca;

    /** The (maximum) length, in bytes, of public keys for this signature scheme. */
    public int $length_public_key;
    /** The (maximum) length, in bytes, of private keys for this signature scheme. */
    public int $length_private_key;
    /** The (maximum) length, in bytes, of ciphertexts for this signature scheme. */
    public int $length_ciphertext;
    /** The (maximum) length, in bytes, of shared secrets for this signature scheme. */
    public int $length_shared_secret;

    /**
     * Constructor.
     * @param string $method_name The name of the signature scheme to use
     * @return OQS_KEYENCAPSULATION
     */
    public function __construct(string $method_name)
    {
    }
    /**
     * Generates a keypair for the signature scheme.
     * @param string $public_key The public key - will be populated by this function
     * @param string $private_key The private key - will be populated by this function
     * @return int OQS_SUCCESS on success, OQS_ERROR on failure
     */
    public function keypair(string &$public_key, string &$private_key): int
    {
    }
    /**
     * Encapsulates a shared secret.
     * @param string $ciphertext The ciphertext - will be populated by this function
     * @param string $shared_secret The shared secret - will be populated by this function
     * @param string $public_key The public key
     * @return int OQS_SUCCESS on success, OQS_ERROR on failure
     */
    public function encapsulate(string &$ciphertext, string &$shared_secret, string $public_key): int
    {
    }
    /**
     * Decapsulates a shared secret.
     * @param string $shared_secret The shared secret - will be populated by this function
     * @param string $ciphertext The ciphertext
     * @param string $private_key The private key
     * @return int OQS_SUCCESS on success, OQS_ERROR on failure
     */

    public function decapsulate(string &$shared_secret, string $ciphertext, string $private_key): int
    {
    }
}

/**
 * This implementation uses whichever algorithm has been selected by
 * OQS_randombytes_switch_algorithm. The default is OQS_randombytes_system, which
 * reads bytes directly from `/dev/urandom`.
 *
 * The caller is responsible for providing a buffer allocated with sufficient room.
 *
 * @param int $number_of_bytes The number of random bytes to get
 * @return string The random bytes
 */
function OQS_randombytes(int $number_of_bytes): string
{
}
/**
 * Switch the algorithm used by OQS_randombytes. The default is OQS_randombytes_system.
 *
 * @param string $algorithm The algorithm to use
 * @return int 0 on success, -1 on failure
 */
function OQS_randombytes_switch_algorithm(string $algorithm): int
{
}
/**
 * Returns identifiers for available signature schemes in liboqs.  Used with OQS_SIG_new.
 *
 * Note that algorithm identifiers are present in this list even when the algorithm is disabled
 * at compile time.
 *
 * @param int $i Index of the algorithm identifier to return, 0 <= i < OQS_SIG_algs_length
 * @return string Algorithm identifier as a string, or NULL.
 */
function OQS_SIG_alg_identifier(int $i): ?string
{
}
/**
 * Returns the number of signature mechanisms in liboqs.  They can be enumerated with
 * OQS_SIG_alg_identifier.
 *
 * Note that some mechanisms may be disabled at compile time.
 *
 * @return int The number of signature mechanisms.
 */
function OQS_SIG_alg_count(): int
{
}
/**
 * Indicates whether the specified algorithm was enabled at compile-time or not.
 *
 * @param string $method_name Name of the desired algorithm; one of the names in `OQS_SIG_algs`.
 * @return int 1 if enabled, 0 if disabled or not found
 */
function OQS_SIG_alg_is_enabled(string $method_name): int
{
}
/**
 * Returns identifiers for available key encapsulation mechanisms in liboqs.  Used with OQS_KEM_new.
 *
 * Note that algorithm identifiers are present in this list even when the algorithm is disabled
 * at compile time.
 *
 * @param int $i Index of the algorithm identifier to return, 0 <= i < OQS_KEM_algs_length
 * @return string Algorithm identifier as a string, or NULL.
 */
function OQS_KEM_alg_identifier(int $i): ?string
{
}
/**
 * Returns the number of key encapsulation mechanisms in liboqs.  They can be enumerated with
 * OQS_KEM_alg_identifier.
 *
 * Note that some mechanisms may be disabled at compile time.
 *
 * @return int The number of key encapsulation mechanisms.
 */
function OQS_KEM_alg_count(): int
{
}
/**
 * Indicates whether the specified algorithm was enabled at compile-time or not.
 *
 * @param string $method_name Name of the desired algorithm; one of the names in `OQS_KEM_algs`.
 * @return int 1 if enabled, 0 if disabled or not found
 */
function OQS_KEM_alg_is_enabled(string $method_name): int
{
}

\define('swig_runtime_data_type_pointer', 281473607554496);
\define('OQS_ERROR', -1);
\define('OQS_SUCCESS', 0);
\define('OQS_EXTERNAL_LIB_ERROR_OPENSSL', 50);
\define('OQS_RAND_alg_system', 'system');
\define('OQS_RAND_alg_nist_kat', 'NIST-KAT');
\define('OQS_RAND_alg_openssl', 'OpenSSL');
\define('OQS_SIG_alg_dilithium_2', 'Dilithium2');
\define('OQS_SIG_alg_dilithium_3', 'Dilithium3');
\define('OQS_SIG_alg_dilithium_5', 'Dilithium5');
\define('OQS_SIG_alg_dilithium_2_aes', 'Dilithium2-AES');
\define('OQS_SIG_alg_dilithium_3_aes', 'Dilithium3-AES');
\define('OQS_SIG_alg_dilithium_5_aes', 'Dilithium5-AES');
\define('OQS_SIG_alg_falcon_512', 'Falcon-512');
\define('OQS_SIG_alg_falcon_1024', 'Falcon-1024');
\define('OQS_SIG_alg_sphincs_haraka_128f_robust', 'SPHINCS+-Haraka-128f-robust');
\define('OQS_SIG_alg_sphincs_haraka_128f_simple', 'SPHINCS+-Haraka-128f-simple');
\define('OQS_SIG_alg_sphincs_haraka_128s_robust', 'SPHINCS+-Haraka-128s-robust');
\define('OQS_SIG_alg_sphincs_haraka_128s_simple', 'SPHINCS+-Haraka-128s-simple');
\define('OQS_SIG_alg_sphincs_haraka_192f_robust', 'SPHINCS+-Haraka-192f-robust');
\define('OQS_SIG_alg_sphincs_haraka_192f_simple', 'SPHINCS+-Haraka-192f-simple');
\define('OQS_SIG_alg_sphincs_haraka_192s_robust', 'SPHINCS+-Haraka-192s-robust');
\define('OQS_SIG_alg_sphincs_haraka_192s_simple', 'SPHINCS+-Haraka-192s-simple');
\define('OQS_SIG_alg_sphincs_haraka_256f_robust', 'SPHINCS+-Haraka-256f-robust');
\define('OQS_SIG_alg_sphincs_haraka_256f_simple', 'SPHINCS+-Haraka-256f-simple');
\define('OQS_SIG_alg_sphincs_haraka_256s_robust', 'SPHINCS+-Haraka-256s-robust');
\define('OQS_SIG_alg_sphincs_haraka_256s_simple', 'SPHINCS+-Haraka-256s-simple');
\define('OQS_SIG_alg_sphincs_sha256_128f_robust', 'SPHINCS+-SHA256-128f-robust');
\define('OQS_SIG_alg_sphincs_sha256_128f_simple', 'SPHINCS+-SHA256-128f-simple');
\define('OQS_SIG_alg_sphincs_sha256_128s_robust', 'SPHINCS+-SHA256-128s-robust');
\define('OQS_SIG_alg_sphincs_sha256_128s_simple', 'SPHINCS+-SHA256-128s-simple');
\define('OQS_SIG_alg_sphincs_sha256_192f_robust', 'SPHINCS+-SHA256-192f-robust');
\define('OQS_SIG_alg_sphincs_sha256_192f_simple', 'SPHINCS+-SHA256-192f-simple');
\define('OQS_SIG_alg_sphincs_sha256_192s_robust', 'SPHINCS+-SHA256-192s-robust');
\define('OQS_SIG_alg_sphincs_sha256_192s_simple', 'SPHINCS+-SHA256-192s-simple');
\define('OQS_SIG_alg_sphincs_sha256_256f_robust', 'SPHINCS+-SHA256-256f-robust');
\define('OQS_SIG_alg_sphincs_sha256_256f_simple', 'SPHINCS+-SHA256-256f-simple');
\define('OQS_SIG_alg_sphincs_sha256_256s_robust', 'SPHINCS+-SHA256-256s-robust');
\define('OQS_SIG_alg_sphincs_sha256_256s_simple', 'SPHINCS+-SHA256-256s-simple');
\define('OQS_SIG_alg_sphincs_shake256_128f_robust', 'SPHINCS+-SHAKE256-128f-robust');
\define('OQS_SIG_alg_sphincs_shake256_128f_simple', 'SPHINCS+-SHAKE256-128f-simple');
\define('OQS_SIG_alg_sphincs_shake256_128s_robust', 'SPHINCS+-SHAKE256-128s-robust');
\define('OQS_SIG_alg_sphincs_shake256_128s_simple', 'SPHINCS+-SHAKE256-128s-simple');
\define('OQS_SIG_alg_sphincs_shake256_192f_robust', 'SPHINCS+-SHAKE256-192f-robust');
\define('OQS_SIG_alg_sphincs_shake256_192f_simple', 'SPHINCS+-SHAKE256-192f-simple');
\define('OQS_SIG_alg_sphincs_shake256_192s_robust', 'SPHINCS+-SHAKE256-192s-robust');
\define('OQS_SIG_alg_sphincs_shake256_192s_simple', 'SPHINCS+-SHAKE256-192s-simple');
\define('OQS_SIG_alg_sphincs_shake256_256f_robust', 'SPHINCS+-SHAKE256-256f-robust');
\define('OQS_SIG_alg_sphincs_shake256_256f_simple', 'SPHINCS+-SHAKE256-256f-simple');
\define('OQS_SIG_alg_sphincs_shake256_256s_robust', 'SPHINCS+-SHAKE256-256s-robust');
\define('OQS_SIG_alg_sphincs_shake256_256s_simple', 'SPHINCS+-SHAKE256-256s-simple');
\define('OQS_SIG_algs_length', 44);
\define('OQS_KEM_alg_bike_l1', 'BIKE-L1');
\define('OQS_KEM_alg_bike_l3', 'BIKE-L3');
\define('OQS_KEM_alg_bike_l5', 'BIKE-L5');
\define('OQS_KEM_alg_classic_mceliece_348864', 'Classic-McEliece-348864');
\define('OQS_KEM_alg_classic_mceliece_348864f', 'Classic-McEliece-348864f');
\define('OQS_KEM_alg_classic_mceliece_460896', 'Classic-McEliece-460896');
\define('OQS_KEM_alg_classic_mceliece_460896f', 'Classic-McEliece-460896f');
\define('OQS_KEM_alg_classic_mceliece_6688128', 'Classic-McEliece-6688128');
\define('OQS_KEM_alg_classic_mceliece_6688128f', 'Classic-McEliece-6688128f');
\define('OQS_KEM_alg_classic_mceliece_6960119', 'Classic-McEliece-6960119');
\define('OQS_KEM_alg_classic_mceliece_6960119f', 'Classic-McEliece-6960119f');
\define('OQS_KEM_alg_classic_mceliece_8192128', 'Classic-McEliece-8192128');
\define('OQS_KEM_alg_classic_mceliece_8192128f', 'Classic-McEliece-8192128f');
\define('OQS_KEM_alg_hqc_128', 'HQC-128');
\define('OQS_KEM_alg_hqc_192', 'HQC-192');
\define('OQS_KEM_alg_hqc_256', 'HQC-256');
\define('OQS_KEM_alg_kyber_512', 'Kyber512');
\define('OQS_KEM_alg_kyber_768', 'Kyber768');
\define('OQS_KEM_alg_kyber_1024', 'Kyber1024');
\define('OQS_KEM_alg_kyber_512_90s', 'Kyber512-90s');
\define('OQS_KEM_alg_kyber_768_90s', 'Kyber768-90s');
\define('OQS_KEM_alg_kyber_1024_90s', 'Kyber1024-90s');
\define('OQS_KEM_alg_ntruprime_sntrup761', 'sntrup761');
\define('OQS_KEM_alg_frodokem_640_aes', 'FrodoKEM-640-AES');
\define('OQS_KEM_alg_frodokem_640_shake', 'FrodoKEM-640-SHAKE');
\define('OQS_KEM_alg_frodokem_976_aes', 'FrodoKEM-976-AES');
\define('OQS_KEM_alg_frodokem_976_shake', 'FrodoKEM-976-SHAKE');
\define('OQS_KEM_alg_frodokem_1344_aes', 'FrodoKEM-1344-AES');
\define('OQS_KEM_alg_frodokem_1344_shake', 'FrodoKEM-1344-SHAKE');
\define('OQS_KEM_algs_length', 29);
