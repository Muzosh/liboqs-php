<?php
// -------------------------------------------------------------------------------------
$sig_algs = [];

for ($i = 0; $i < OQS_SIG_algs_length; $i++) {
    $alg = OQS_SIG_alg_identifier($i);
    if (OQS_SIG_alg_is_enabled($alg)) {
        $sig_algs[$alg] = [];
    }
}

foreach ($sig_algs as $alg => &$alg_info) {
    echo $alg . " (" . array_search($alg, array_keys($sig_algs))+1 . "/" . OQS_SIG_algs_length . ")\n";

    if (strpos($alg, 'Falcon') !== false) {
        // skip Falcon-512 and Falcon-1024
        // PQClean builds are failing
        continue;
    }

    $sig = new OQS_SIGNATURE($alg);
    $alg_info['public_key_length[B]'] = $sig->length_public_key;
    $alg_info['private_key_length[B]'] = $sig->length_private_key;
    $alg_info['signature_length[B]'] = $sig->length_signature;

    $message = "Hello World";
    $start = microtime(true);
    $status = $sig->keypair($public_key, $private_key);
    $alg_info['keypair_time[ms]'] = (microtime(true) - $start) / 1000;
    assert($status == OQS_SUCCESS, $alg);
    assert(strlen($public_key) == $alg_info['public_key_length[B]'], $alg);
    assert(strlen($private_key) == $alg_info['private_key_length[B]'], $alg);

    $start = microtime(true);
    $status = $sig->sign($signature, $message, $private_key);
    $alg_info['sign_time[ms]'] = (microtime(true) - $start) / 1000;
    assert($status == OQS_SUCCESS, $alg);
    assert(strlen($signature) == $alg_info['signature_length[B]'], $alg);

    $start = microtime(true);
    $status = $sig->verify($message, $signature, $public_key);
    $alg_info['verify_time[ms]'] = (microtime(true) - $start) / 1000;
    assert($status == OQS_SUCCESS, $alg);
}

$fp = fopen('signature.csv', 'w');
$header = array_keys($sig_algs[array_key_first($sig_algs)]);
array_unshift($header, 'algorithm');
fputcsv($fp, $header, ";");
foreach ($sig_algs as $alg => $fields) {
    if (strpos($alg, 'Falcon') !== false) {
        // skip Falcon-512 and Falcon-1024
        // PQClean builds are failing
        continue;
    }
    array_unshift($fields, $alg);
    fputcsv($fp, $fields, ";");
}
fclose($fp);

$kem_algs = [];

for ($i = 0; $i < OQS_KEM_algs_length; $i++) {
    $alg = OQS_KEM_alg_identifier($i);
    if (OQS_KEM_alg_is_enabled($alg)) {
        $kem_algs[$alg] = [];
    }
}

foreach ($kem_algs as $alg => &$alg_info) {
    echo $alg . " (" . array_search($alg, array_keys($kem_algs))+1 . "/" . OQS_KEM_algs_length . ")\n";

    $kem = new OQS_KEYENCAPSULATION($alg);
    $alg_info['public_key_length[B]'] = $kem->length_public_key;
    $alg_info['private_key_length[B]'] = $kem->length_private_key;
    $alg_info['ciphertext_length[B]'] = $kem->length_ciphertext;
    $alg_info['shared_secret_length[B]'] = $kem->length_shared_secret;

    $start = microtime(true);
    $status = $kem->keypair($public_key, $private_key);
    $alg_info['keypair_time[ms]'] = (microtime(true) - $start) / 1000;
    assert($status == OQS_SUCCESS, $alg);
    assert(strlen($public_key) == $alg_info['public_key_length[B]'], $alg);
    assert(strlen($private_key) == $alg_info['private_key_length[B]'], $alg);

    $start = microtime(true);
    $status = $kem->encapsulate($ciphertext, $shared_secret, $public_key);
    $alg_info['encapsulate_time[ms]'] = (microtime(true) - $start) / 1000;
    assert($status == OQS_SUCCESS, $alg);
    assert(strlen($ciphertext) == $alg_info['ciphertext_length[B]'], $alg);
    assert(strlen($shared_secret) == $alg_info['shared_secret_length[B]'], $alg);

    $start = microtime(true);
    $status = $kem->decapsulate($shared_secret2, $ciphertext, $private_key);
    $alg_info['decapsulate_time[ms]'] = (microtime(true) - $start) / 1000;
    assert($status == OQS_SUCCESS, $alg);
    assert(strlen($shared_secret2) == $alg_info['shared_secret_length[B]'], $alg);
    assert($shared_secret == $shared_secret2, $alg);
}

$fp = fopen('encapsulation.csv', 'w');
$header = array_keys($kem_algs[array_key_first($kem_algs)]);
array_unshift($header, 'algorithm');
fputcsv($fp, $header, ";");
foreach ($kem_algs as $alg => $fields) {
    array_unshift($fields, $alg);
    fputcsv($fp, $fields, ";");
}
fclose($fp);