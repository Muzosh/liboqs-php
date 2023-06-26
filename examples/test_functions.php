<?php
// Test LibOQS extension
for ($i = 0; $i < OQS_SIG_algs_length; $i++) {
    $alg = OQS_SIG_alg_identifier($i);
    $enabled = OQS_SIG_alg_is_enabled($alg);
    echo $alg . " - " . $enabled . "\n";
}
$bytes = OQS_randombytes(32);

// Choose what algorithm to test
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

// Choose what algorithm to test
$kem = new OQS_KEYENCAPSULATION("Kyber1024");

// All operations should return $status = 0 = OQS_SUCCESS
$status = $kem->keypair($public_key, $private_key);
assert($status == OQS_SUCCESS, $alg);
$status = $kem->encapsulate($ciphertext, $shared_secret, $public_key);
assert($status == OQS_SUCCESS, $alg);
$status = $kem->decapsulate($shared_secret2, $ciphertext, $private_key);
assert($status == OQS_SUCCESS, $alg);