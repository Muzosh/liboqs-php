<?php
ini_set("xdebug.var_display_max_children", '-1');
ini_set("xdebug.var_display_max_data", '-1');
ini_set("xdebug.var_display_max_depth", '-1');

require_once __DIR__ . '/../apps/twofactor_webeid/vendor/autoload.php';

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\PrivateKeyInfo;
use phpseclib3\File\ASN1\Maps\PublicKeyInfo;

// from openssl public key to raw 
function extractPublicKey(string $publicKey): string
{
    $extractedBER = ASN1::extractBER($publicKey);
    $decodedBER = ASN1::decodeBER($extractedBER);

    $onlySubjectPublicKey = ASN1::asn1map($decodedBER[0], PublicKeyInfo::MAP)['publicKey'];

    // Check if first byte in string is 0
    // If it is, it means that the public key is encoded as a positive integer
    // If it is not, it means that the public key is encoded as a bit string
    $firstByte = unpack('c', $onlySubjectPublicKey)[1];
    if ($firstByte != 0) {
        // Remove first byte from bit string
        $onlySubjectPublicKey = removeFirstByte($onlySubjectPublicKey);
    }

    

    // Integers in ASN1 lead with 0 byte indicating the integer is positive
    // We need to remove this byte so it can be parsed correctly
    return removeFirstByte($onlySubjectPublicKey);
}

// from openssl private key to raw
function extractPrivateKey(string $privateKey, int $max_length): string
{
    $extractedBER = ASN1::extractBER($privateKey);
    $decodedBER = ASN1::decodeBER($extractedBER);

    $private_key_raw = ASN1::asn1map($decodedBER[0], PrivateKeyInfo::MAP)['privateKey'];

    // PQC-OpenSSL encodes privates keys as 0x04 or 0x03 || length || private_key || public_key
    // We need to extract private_key only
    if (strlen($private_key_raw) > $max_length) {
        $bytearray = unpack('c*', $private_key_raw);

        $offset = 0;
        // if it still has ASN1 type and length
        if ($bytearray[1] == 0x04 || $bytearray[1] == 0x03) {
            // 0x80 indicates that second byte encodes number of bytes containing length
            $len_bytes = ($bytearray[2] & 0x80) == 0x80 ? 1 + ($bytearray[2] & 0x7f) : 1;
            // 1 is for type 0x04 or 0x03, rest is length_bytes
            $offset = 1 + $len_bytes;
        }
        $private_key_raw = pack('c*', ...array_slice($bytearray, $offset, $max_length));
    }

    return $private_key_raw;
}

function removeFirstByte($encoded): string
{
    return pack('c*', ...array_slice(unpack('c*', $encoded), 1));
}

ASN1::loadOIDs([
    "dilithium2" => "1.3.6.1.4.1.2.267.7.4.4",
    "p256_dilithium2" => "1.3.9999.2.7.1",
    "rsa3072_dilithium2" => "1.3.9999.2.7.2",
    "dilithium3" => "1.3.6.1.4.1.2.267.7.6.5",
    "p384_dilithium3" => "1.3.9999.2.7.3",
    "dilithium5" => "1.3.6.1.4.1.2.267.7.8.7",
    "p521_dilithium5" => "1.3.9999.2.7.4",
    "dilithium2_aes" => "1.3.6.1.4.1.2.267.11.4.4",
    "p256_dilithium2_aes" => "1.3.9999.2.11.1",
    "rsa3072_dilithium2_aes" => "1.3.9999.2.11.2",
    "dilithium3_aes" => "1.3.6.1.4.1.2.267.11.6.5",
    "p384_dilithium3_aes" => "1.3.9999.2.11.3",
    "dilithium5_aes" => "1.3.6.1.4.1.2.267.11.8.7",
    "p521_dilithium5_aes" => "1.3.9999.2.11.4",
    "falcon512" => "1.3.9999.3.1",
    "p256_falcon512" => "1.3.9999.3.2",
    "rsa3072_falcon512" => "1.3.9999.3.3",
    "falcon1024" => "1.3.9999.3.4",
    "p521_falcon1024" => "1.3.9999.3.5",
    "sphincsharaka128frobust" => "1.3.9999.6.1.1",
    "p256_sphincsharaka128frobust" => "1.3.9999.6.1.2",
    "rsa3072_sphincsharaka128frobust" => "1.3.9999.6.1.3",
    "sphincsharaka128fsimple" => "1.3.9999.6.1.4",
    "p256_sphincsharaka128fsimple" => "1.3.9999.6.1.5",
    "rsa3072_sphincsharaka128fsimple" => "1.3.9999.6.1.6",
    "sphincsharaka128srobust" => "1.3.9999.6.1.7",
    "p256_sphincsharaka128srobust" => "1.3.9999.6.1.8",
    "rsa3072_sphincsharaka128srobust" => "1.3.9999.6.1.9",
    "sphincsharaka128ssimple" => "1.3.9999.6.1.10",
    "p256_sphincsharaka128ssimple" => "1.3.9999.6.1.11",
    "rsa3072_sphincsharaka128ssimple" => "1.3.9999.6.1.12",
    "sphincsharaka192frobust" => "1.3.9999.6.2.1",
    "p384_sphincsharaka192frobust" => "1.3.9999.6.2.2",
    "sphincsharaka192fsimple" => "1.3.9999.6.2.3",
    "p384_sphincsharaka192fsimple" => "1.3.9999.6.2.4",
    "sphincsharaka192srobust" => "1.3.9999.6.2.5",
    "p384_sphincsharaka192srobust" => "1.3.9999.6.2.6",
    "sphincsharaka192ssimple" => "1.3.9999.6.2.7",
    "p384_sphincsharaka192ssimple" => "1.3.9999.6.2.8",
    "sphincsharaka256frobust" => "1.3.9999.6.3.1",
    "p521_sphincsharaka256frobust" => "1.3.9999.6.3.2",
    "sphincsharaka256fsimple" => "1.3.9999.6.3.3",
    "p521_sphincsharaka256fsimple" => "1.3.9999.6.3.4",
    "sphincsharaka256srobust" => "1.3.9999.6.3.5",
    "p521_sphincsharaka256srobust" => "1.3.9999.6.3.6",
    "sphincsharaka256ssimple" => "1.3.9999.6.3.7",
    "p521_sphincsharaka256ssimple" => "1.3.9999.6.3.8",
    "sphincssha256128frobust" => "1.3.9999.6.4.1",
    "p256_sphincssha256128frobust" => "1.3.9999.6.4.2",
    "rsa3072_sphincssha256128frobust" => "1.3.9999.6.4.3",
    "sphincssha256128fsimple" => "1.3.9999.6.4.4",
    "p256_sphincssha256128fsimple" => "1.3.9999.6.4.5",
    "rsa3072_sphincssha256128fsimple" => "1.3.9999.6.4.6",
    "sphincssha256128srobust" => "1.3.9999.6.4.7",
    "p256_sphincssha256128srobust" => "1.3.9999.6.4.8",
    "rsa3072_sphincssha256128srobust" => "1.3.9999.6.4.9",
    "sphincssha256128ssimple" => "1.3.9999.6.4.10",
    "p256_sphincssha256128ssimple" => "1.3.9999.6.4.11",
    "rsa3072_sphincssha256128ssimple" => "1.3.9999.6.4.12",
    "sphincssha256192frobust" => "1.3.9999.6.5.1",
    "p384_sphincssha256192frobust" => "1.3.9999.6.5.2",
    "sphincssha256192fsimple" => "1.3.9999.6.5.3",
    "p384_sphincssha256192fsimple" => "1.3.9999.6.5.4",
    "sphincssha256192srobust" => "1.3.9999.6.5.5",
    "p384_sphincssha256192srobust" => "1.3.9999.6.5.6",
    "sphincssha256192ssimple" => "1.3.9999.6.5.7",
    "p384_sphincssha256192ssimple" => "1.3.9999.6.5.8",
    "sphincssha256256frobust" => "1.3.9999.6.6.1",
    "p521_sphincssha256256frobust" => "1.3.9999.6.6.2",
    "sphincssha256256fsimple" => "1.3.9999.6.6.3",
    "p521_sphincssha256256fsimple" => "1.3.9999.6.6.4",
    "sphincssha256256srobust" => "1.3.9999.6.6.5",
    "p521_sphincssha256256srobust" => "1.3.9999.6.6.6",
    "sphincssha256256ssimple" => "1.3.9999.6.6.7",
    "p521_sphincssha256256ssimple" => "1.3.9999.6.6.8",
    "sphincsshake256128frobust" => "1.3.9999.6.7.1",
    "p256_sphincsshake256128frobust" => "1.3.9999.6.7.2",
    "rsa3072_sphincsshake256128frobust" => "1.3.9999.6.7.3",
    "sphincsshake256128fsimple" => "1.3.9999.6.7.4",
    "p256_sphincsshake256128fsimple" => "1.3.9999.6.7.5",
    "rsa3072_sphincsshake256128fsimple" => "1.3.9999.6.7.6",
    "sphincsshake256128srobust" => "1.3.9999.6.7.7",
    "p256_sphincsshake256128srobust" => "1.3.9999.6.7.8",
    "rsa3072_sphincsshake256128srobust" => "1.3.9999.6.7.9",
    "sphincsshake256128ssimple" => "1.3.9999.6.7.10",
    "p256_sphincsshake256128ssimple" => "1.3.9999.6.7.11",
    "rsa3072_sphincsshake256128ssimple" => "1.3.9999.6.7.12",
    "sphincsshake256192frobust" => "1.3.9999.6.8.1",
    "p384_sphincsshake256192frobust" => "1.3.9999.6.8.2",
    "sphincsshake256192fsimple" => "1.3.9999.6.8.3",
    "p384_sphincsshake256192fsimple" => "1.3.9999.6.8.4",
    "sphincsshake256192srobust" => "1.3.9999.6.8.5",
    "p384_sphincsshake256192srobust" => "1.3.9999.6.8.6",
    "sphincsshake256192ssimple" => "1.3.9999.6.8.7",
    "p384_sphincsshake256192ssimple" => "1.3.9999.6.8.8",
    "sphincsshake256256frobust" => "1.3.9999.6.9.1",
    "p521_sphincsshake256256frobust" => "1.3.9999.6.9.2",
    "sphincsshake256256fsimple" => "1.3.9999.6.9.3",
    "p521_sphincsshake256256fsimple" => "1.3.9999.6.9.4",
    "sphincsshake256256srobust" => "1.3.9999.6.9.5",
    "p521_sphincsshake256256srobust" => "1.3.9999.6.9.6",
    "sphincsshake256256ssimple" => "1.3.9999.6.9.7",
    "p521_sphincsshake256256ssimple" => "1.3.9999.6.9.8",
]);

$data = file_get_contents('/tmp/example.txt');

// DIL5 verify signature created by console
$dil5_verification_public_key = file_get_contents('/tmp/dil5.pem');
$dil5_verification_signature = file_get_contents('/tmp/dil5.sig');
$dil5_verification_results = openssl_verify($data, $dil5_verification_signature, $dil5_verification_public_key, OPENSSL_ALGO_SHA256);

// DIL5 create signature and verify it in code
$dil5_signing_private_key = file_get_contents('/tmp/dil5.key');
$dil5_signing_signature = null;
$dil5_signing_result = openssl_sign($data, $dil5_signing_signature, $dil5_signing_private_key, OPENSSL_ALGO_SHA256);
$dil5_signing_verify_result = openssl_verify($data, $dil5_signing_signature, $dil5_verification_public_key, OPENSSL_ALGO_SHA256);

// Test interoperability between openssl extension and liboqs extension
$sig = new OQS_SIGNATURE("Dilithium5");
// Convert openssl (pem) keys to liboqs (raw) keys
$raw_public_key = extractPublicKey($dil5_verification_public_key);
$raw_private_key = extractPrivateKey($dil5_signing_private_key, $sig->length_private_key);
// verify openssl signature with liboqs private key
$status = $sig->verify(hex2bin(hash('sha256', $data)), $dil5_signing_signature, $raw_public_key);

// verify liboqs signature with openssl public key
$status = $sig->sign($new_signature, hex2bin(hash('sha256', $data)), $raw_private_key);
$verify_result = openssl_verify($data, $new_signature, $dil5_verification_public_key, OPENSSL_ALGO_SHA256);


// -------------------------------------------------------------------------------------
// Test LibOQS extension
for ($i = 0; $i < OQS_SIG_algs_length; $i++) {
    $alg = OQS_SIG_alg_identifier($i);
    $enabled = OQS_SIG_alg_is_enabled($alg);
    echo $alg . " - " . $enabled . "\n";
}
$bytes = OQS_randombytes(32);

$sig = new OQS_SIGNATURE("Dilithium2");
$message = "Hello World";

// All operations should return $status = 0 = OQS_SUCCESS
$status = $sig->keypair($public_key, $private_key);
assert($status == OQS_SUCCESS, $alg);
$status = $sig->sign($signature, $message, $private_key);
assert($status == OQS_SUCCESS, $alg);
$status = $sig->verify($message, $signature, $public_key);
assert($status == OQS_SUCCESS, $alg);

for ($i = 0; $i < OQS_KEM_algs_length; $i++) {
    $alg = OQS_KEM_alg_identifier($i);
    $enabled = OQS_KEM_alg_is_enabled($alg);
    echo $alg . " - " . $enabled . "\n";
}

$kem = new OQS_KEYENCAPSULATION("Kyber1024");

// All operations should return $status = 0 = OQS_SUCCESS
$status = $kem->keypair($public_key, $private_key);
assert($status == OQS_SUCCESS, $alg);
$status = $kem->encapsulate($ciphertext, $shared_secret, $public_key);
assert($status == OQS_SUCCESS, $alg);
$status = $kem->decapsulate($shared_secret2, $ciphertext, $private_key);
assert($status == OQS_SUCCESS, $alg);