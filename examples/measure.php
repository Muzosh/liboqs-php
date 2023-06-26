<?php
// Measure signature schemes
$sig_algs = [];
define("ITERATIONS", 30);

for ($i = 0; $i < OQS_SIG_algs_length; $i++) {
    $alg = OQS_SIG_alg_identifier($i);
    if (OQS_SIG_alg_is_enabled($alg)) {
        $sig_algs[$alg] = [];
    }
}

foreach ($sig_algs as $alg => &$alg_info) {
    $sig = new OQS_SIGNATURE($alg);

    for ($i = 1; $i <= ITERATIONS; $i++) {
        echo $alg . " (" . array_search($alg, array_keys($sig_algs)) + 1 . "/" . OQS_SIG_algs_length . ") - cycle " . $i . "/" . ITERATIONS . "\n";

        $message = "Hello World";
        $start = microtime(true);
        $status = $sig->keypair($public_key, $private_key);
        $alg_info['keypair_time[ms]'][] = (microtime(true) - $start) / 1000;
        assert($status == OQS_SUCCESS, $alg);

        $start = microtime(true);
        $status = $sig->sign($signature, $message, $private_key);
        $alg_info['sign_time[ms]'][] = (microtime(true) - $start) / 1000;
        assert($status == OQS_SUCCESS, $alg);

        $start = microtime(true);
        $status = $sig->verify($message, $signature, $public_key);
        $alg_info['verify_time[ms]'][] = (microtime(true) - $start) / 1000;
        assert($status == OQS_SUCCESS, $alg);
    }
}

// save results as json
file_put_contents('signature.json', json_encode($sig_algs));

// save results as csv
$fp = fopen('signature.csv', 'w');
$header = array_keys($sig_algs[array_key_first($sig_algs)]);
array_unshift($header, 'algorithm');
fputcsv($fp, $header, ";");
foreach ($sig_algs as $alg => $fields) {
    array_unshift($fields, $alg);
    fputcsv($fp, $fields, ";");
}
fclose($fp);


// measure KEM algorithms
$kem_algs = [];

for ($i = 0; $i < OQS_KEM_algs_length; $i++) {
    $alg = OQS_KEM_alg_identifier($i);
    if (OQS_KEM_alg_is_enabled($alg)) {
        $kem_algs[$alg] = [];
    }
}

foreach ($kem_algs as $alg => &$alg_info) {
    for ($i = 1; $i <= ITERATIONS; $i++) {
        echo $alg . " (" . array_search($alg, array_keys($kem_algs)) + 1 . "/" . OQS_KEM_algs_length . ") - cycle " . $i . "/" . ITERATIONS . "\n";

        $kem = new OQS_KEYENCAPSULATION($alg);

        $start = microtime(true);
        $status = $kem->keypair($public_key, $private_key);
        $alg_info['keypair_time[ms]'][] = (microtime(true) - $start) / 1000;
        assert($status == OQS_SUCCESS, $alg);

        $start = microtime(true);
        $status = $kem->encapsulate($ciphertext, $shared_secret, $public_key);
        $alg_info['encapsulate_time[ms]'][] = (microtime(true) - $start) / 1000;
        assert($status == OQS_SUCCESS, $alg);

        $start = microtime(true);
        $status = $kem->decapsulate($shared_secret2, $ciphertext, $private_key);
        $alg_info['decapsulate_time[ms]'][] = (microtime(true) - $start) / 1000;
        assert($status == OQS_SUCCESS, $alg);
        assert($shared_secret == $shared_secret2, $alg);
    }
}

// save results as json
file_put_contents('encapsulation.json', json_encode($kem_algs));

// save results as csv
$fp = fopen('encapsulation.csv', 'w');
$header = array_keys($kem_algs[array_key_first($kem_algs)]);
array_unshift($header, 'algorithm');
fputcsv($fp, $header, ";");
foreach ($kem_algs as $alg => $fields) {
    array_unshift($fields, $alg);
    fputcsv($fp, $fields, ";");
}
fclose($fp);

echo "Finished!";
