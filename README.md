# liboqs-php
This repository documents the process of building the PHP extension of [libOQS](https://github.com/open-quantum-safe/liboqs) library from OpenQuantumSafe organization. Very similar one for Python is [here](https://github.com/Muzosh/liboqs-python).

## Prerequisites
You will need to build liboqs itself. Basically follow the steps in https://github.com/open-quantum-safe/liboqs#quickstart (no need to build with some modified -D arguments).

## Installation
1. Clone this repository
1. Define liboqs root directory environment variable: `export LIBOQS_ROOT_DIR=/home/user/liboqs`
1. Run compile.sh
1. Add this line to your php.ini file: `extension=/path/to/this/repository/build/oqsphp.so`
1. (Optional) Copy `oqsphp_stub.php` to your project directory in order to expose classes and functions to your PHP code
    - this step is purely for developer's convenience, you can still use the extension without it (but your IDE will throw undefined class/function warnings)

## Exposed classes and functions
See `oqsphp_stub.php`

## Example
```php
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
assert($status == OQS_SUCCESS);
$status = $sig->sign($signature, $message, $private_key);
assert($status == OQS_SUCCESS);
$status = $sig->verify($message, $signature, $public_key);
assert($status == OQS_SUCCESS);

for ($i = 0; $i < OQS_KEM_algs_length; $i++) {
    $alg = OQS_KEM_alg_identifier($i);
    $enabled = OQS_KEM_alg_is_enabled($alg);
    echo $alg . " - " . $enabled . "\n";
}

$kem = new OQS_KEYENCAPSULATION("Kyber1024");

// All operations should return $status = 0 = OQS_SUCCESS
$status = $kem->keypair($public_key, $private_key);
assert($status == OQS_SUCCESS);
$status = $kem->encapsulate($ciphertext, $shared_secret, $public_key);
assert($status == OQS_SUCCESS);
$status = $kem->decapsulate($shared_secret2, $ciphertext, $private_key);
assert($status == OQS_SUCCESS);


echo "Done";
```
