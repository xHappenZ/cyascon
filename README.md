Cython implementation of Ascon
==============================

This is a Cython implementation of Ascon v1.2, an authenticated cipher and hash function.

https://github.com/xHappenZ/cyascon

Ascon
-----

Ascon is a family of [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) (AEAD) and [hashing](https://en.wikipedia.org/wiki/Cryptographic_hash_function) algorithms designed to be lightweight and easy to implement, even with added countermeasures against side-channel attacks.
It was designed by a team of cryptographers from Graz University of Technology, Infineon Technologies, and Radboud University: Christoph Dobraunig, Maria Eichlseder, Florian Mendel, and Martin Schläffer.

Ascon has been selected as the standard for lightweight cryptography in the [NIST Lightweight Cryptography competition (2019–2023)](https://csrc.nist.gov/projects/lightweight-cryptography) and as the primary choice for lightweight authenticated encryption in the final portfolio of the [CAESAR competition (2014–2019)](https://competitions.cr.yp.to/caesar-submissions.html).

Find more information, including the specification and more implementations here:

https://ascon.iaik.tugraz.at/


Algorithms
----------

This is a Cython implementation of Ascon, which makes use of efficiently implemented C algorithms and can be compiled and used as a Python module.

The authenticated encryption aswell as the hashing algorithms provide a streaming mode of operation and intermediate hashes/tags.

Authenticated encryption:

  * Initialization: `c = asconAead.new(key, variant=AEAD128, nonce=None, tag_len=ASCON_AEAD_TAG_MIN_SECURE_LEN)` with the following 3 family members:
  
    - `Ascon-128`
    - `Ascon-128a`
    - `Ascon-80pq`
  
  * Associated data: `c.update(self, const uint8_t[::1] data)`
  
  * Encryption (streaming): `c.encrypt(self, const uint8_t[::1] plaintext = None)`
  
  * Encryption (complete - only directly after initialization): `c.encrypt_and_digest_complete(self, const uint8_t[::1] data, const uint8_t[::1] plaintext)`
  
  * Tag generation: `c.digest(self)`
  
Decryption operations after encryption operations are not possible and vice versa.

  * Decryption (streaming): `c.decrypt(self, const uint8_t[::1] ciphertext = None)`
  
  * Decryption (complete - only directly after initialization): `c.decrypt_and_verify_complete(self, const uint8_t[::1] data, const uint8_t[::1] ciphertext, const uint8_t[::1] tag)`
  
  * Tag verification: `c.verify(self, const uint8_t[::1] tag)`
  
Hashing:

  * Initialization: `h = asconHash.new(variant="Ascon-Hash")` with the following 3 family members:
  
    - `Ascon-Hash`
    - `Ascon-Hasha`
    - `Ascon-Xof`
    - `Ascon-Xofa`
    
  * Updating the state with the message: `h.update(self, const uint8_t[::1] message)`
  
  * Hash generation (intermediate): `h.digest(self, hashlength=ASCON_HASH_DIGEST_LEN)`


Files
-----

  * `asconAead.pyx`: 
    Contains the Cython implementation of the authenticated encryption.
    
  * `ascon_aead_common.c`, `ascon_aead80pq.c`, `ascon_aead128.c`, `ascon_aead128a.c`:
    Contain the C APIs for the authenticated encryptions which are used in the Cython wrapper.
    
  * `setupAead`:
    The setup file to create a python module for the authenticated encryption.
    
  * `asconHash.pyx`: 
    Contains the Cython implementation of Ascon hashing.
    
  * `ascon_hash.c`:
    Contains the C APIs for Ascon hashing wich are used in the Cython wrapper.

  * `setupAead`:
    The setup file to create a python module for Ascon hashing.


Command for the setup of the Python module: `python3 setup.py build_ext --inplace`

