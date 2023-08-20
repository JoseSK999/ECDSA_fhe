# ECDSA_fhe

Welcome to the ECDSA_fhe repository! Here you will find a Fully Homomorphic Encryption ECDSA signing implementation for the secp256k1 curve.

The provided FHE signing function takes as inputs:
* A cleartext ``message`` of 32 bytes (which should be a hash)
* An encrypted ``private key``
* An encrypted ``nonce`` modular inverse
* And the corresponding nonce curve point ``R`` (only x coordinate)

And produces as output the ``s`` component of the signature, which is computed as:
```
s = ((private key * R + message) * nonce^-1) mod N
```
Where N is the order of the generator point, a 256-bit prime number: 115792089237316195423570985008687907852837564279074904382605163141518161494337.

The resulting signature is the pair of values ``R``, ``s``.

### Notes about pre-computed values
The first pre-computed value is the nonce curve point ``R``. The client performs the elliptic curve operations (i.e. public key computation) on the cleartext ``nonce``.

The second pre-computed value is the ``nonce`` modular inverse, which can be efficiently computed using Fermat's Little Theorem:

```a^(p-1) ≡ 1 mod p```, where ``p`` is prime and ``a`` is not multiple of ``p``. 

We multiply both sides by ``a^-1`` and get: ```a^-1 ≡ a^(p-2) mod p```. We can solve this using the fast exponentiation method.

In other words we can compute the ``nonce`` modular inverse as: ```nonce^(N-2) mod N```.

This is very fast in cleartext, but in FHE it would require many homomorphic multiplications and reductions which makes it impractical.