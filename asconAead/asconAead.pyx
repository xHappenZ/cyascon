from libc.stdint cimport uint8_t
from libcpp cimport bool
from Cryptodome import Random
import threading
from enum import Enum

cdef extern from "ascon_aead_common.c":
  ctypedef struct ascon_aead_ctx_t:
    uint8_t flow_state
    pass

  cdef const int ASCON_AEAD80pq_KEY_LEN
  cdef const int ASCON_AEAD128_KEY_LEN
  cdef const int ASCON_AEAD128a_KEY_LEN
  cdef const int ASCON_AEAD_NONCE_LEN
  cdef const int ASCON_RATE
  cdef const int ASCON_DOUBLE_RATE
  cdef const int ASCON_AEAD_TAG_MIN_SECURE_LEN

  ascon_aead_ctx_t* new_aead_ctx()

  void ascon_aead80pq_init(ascon_aead_ctx_t* const ctx,
                            const uint8_t key[ASCON_AEAD80pq_KEY_LEN],
                            const uint8_t nonce[ASCON_AEAD_NONCE_LEN])

  void ascon_aead128_init(ascon_aead_ctx_t* const ctx,
                            const uint8_t key[ASCON_AEAD128_KEY_LEN],
                            const uint8_t nonce[ASCON_AEAD_NONCE_LEN])

  void ascon_aead128a_init(ascon_aead_ctx_t* const ctx,
                            const uint8_t key[ASCON_AEAD128a_KEY_LEN],
                            const uint8_t nonce[ASCON_AEAD_NONCE_LEN])

  void ascon_aead128_assoc_data_update(ascon_aead_ctx_t* const ctx,
                                        const uint8_t* assoc_data,
                                        size_t assoc_data_len)
  void ascon_aead128a_assoc_data_update(ascon_aead_ctx_t* const ctx,
                                        const uint8_t* assoc_data,
                                        size_t assoc_data_len)
  void ascon_aead80pq_assoc_data_update(ascon_aead_ctx_t* ctx,
                                        const uint8_t* assoc_data,
                                        size_t assoc_data_len)

  size_t ascon_aead128_encrypt_update(ascon_aead_ctx_t* const ctx,
                                        uint8_t* ciphertext,
                                        const uint8_t* plaintext,
                                        size_t plaintext_len)
  size_t ascon_aead128a_encrypt_update(ascon_aead_ctx_t* const ctx,
                                        uint8_t* ciphertext,
                                        const uint8_t* plaintext,
                                        size_t plaintext_len)
  size_t ascon_aead80pq_encrypt_update(ascon_aead_ctx_t* const ctx,
                                        uint8_t* ciphertext,
                                        const uint8_t* plaintext,
                                        size_t plaintext_len)

  void ascon_aead128_encrypt(ascon_aead_ctx_t* const ctx,
                              const uint8_t* assoc_data,
                              const uint8_t* plaintext,
                              size_t assoc_data_len,
                              size_t plaintext_len,
                              uint8_t* ciphertext,
                              uint8_t* tag,
                              size_t tag_len)

  void ascon_aead128a_encrypt(ascon_aead_ctx_t* const ctx,
                              const uint8_t* assoc_data,
                              const uint8_t* plaintext,
                              size_t assoc_data_len,
                              size_t plaintext_len,
                              uint8_t* ciphertext,
                              uint8_t* tag,
                              size_t tag_len)

  void ascon_aead80pq_encrypt(ascon_aead_ctx_t* const ctx,
                              const uint8_t* assoc_data,
                              const uint8_t* plaintext,
                              size_t assoc_data_len,
                              size_t plaintext_len,
                              uint8_t* ciphertext,
                              uint8_t* tag,
                              size_t tag_len)

  size_t ascon_aead128_encrypt_intermediate(ascon_aead_ctx_t* const ctx,
                                            uint8_t* const ciphertext,
                                            uint8_t* tag,
                                            size_t tag_len)

  size_t ascon_aead128a_encrypt_intermediate(ascon_aead_ctx_t* const ctx,
                                              uint8_t* const ciphertext,
                                              uint8_t* tag,
                                              size_t tag_len)

  size_t ascon_aead80pq_encrypt_intermediate(ascon_aead_ctx_t* const ctx,
                                              uint8_t* const ciphertext,
                                              uint8_t* tag,
                                              size_t tag_len)

  size_t ascon_aead128_decrypt_update(ascon_aead_ctx_t* const ctx,
                                      uint8_t* plaintext,
                                      const uint8_t* ciphertext,
                                      size_t ciphertext_len)

  size_t ascon_aead128a_decrypt_update(ascon_aead_ctx_t* const ctx,
                                        uint8_t* plaintext,
                                        const uint8_t* ciphertext,
                                        size_t ciphertext_len)

  size_t ascon_aead80pq_decrypt_update(ascon_aead_ctx_t* ctx,
                                        uint8_t* plaintext,
                                        const uint8_t* ciphertext,
                                        size_t ciphertext_len)

  size_t ascon_aead128_decrypt_intermediate(ascon_aead_ctx_t* const ctx,
                                            uint8_t* plaintext,
                                            uint8_t* expected_tag,
                                            size_t expected_tag_len)

  size_t ascon_aead128a_decrypt_intermediate(ascon_aead_ctx_t* const ctx,
                                              uint8_t* plaintext,
                                              uint8_t* expected_tag,
                                              size_t expected_tag_len)

  size_t ascon_aead80pq_decrypt_intermediate(ascon_aead_ctx_t* const ctx,
                                              uint8_t* plaintext,
                                              uint8_t* expected_tag,
                                              size_t expected_tag_len)

  bool ascon_aead128_decrypt(ascon_aead_ctx_t* ctx,
                              uint8_t* plaintext,
                              const uint8_t* assoc_data,
                              const uint8_t* ciphertext,
                              const uint8_t* expected_tag,
                              size_t assoc_data_len,
                              size_t ciphertext_len,
                              size_t expected_tag_len)

  bool ascon_aead128a_decrypt(ascon_aead_ctx_t* ctx,
                              uint8_t* plaintext,
                              const uint8_t* assoc_data,
                              const uint8_t* ciphertext,
                              const uint8_t* expected_tag,
                              size_t assoc_data_len,
                              size_t ciphertext_len,
                              size_t expected_tag_len)

  bool ascon_aead80pq_decrypt(ascon_aead_ctx_t* ctx,
                              uint8_t* plaintext,
                              const uint8_t* assoc_data,
                              const uint8_t* ciphertext,
                              const uint8_t* expected_tag,
                              size_t assoc_data_len,
                              size_t ciphertext_len,
                              size_t expected_tag_len)

  bool ascon_aead_is_tag_valid_intermediate(const uint8_t* expected_tag,
                                            size_t expected_tag_len,
                                            const uint8_t* actual_tag,
                                            size_t actual_tag_len)



  void ascon_aead_cleanup(ascon_aead_ctx_t* const ctx)

  void ascon_aead_free(ascon_aead_ctx_t* const ctx)


AEAD80PQ = 0
AEAD128 = 1
AEAD128A = 2

# Internal enum for control flow
class _AsconFlow(Enum):
  ASCON_FLOW_INVALID = 0,
  ASCON_FLOW_AEAD_INITIALIZED = 1,
  ASCON_FLOW_ASSOC_DATA_UPDATED = 2,
  ASCON_FLOW_ENCRYPT_DATA_UPDATED = 3,
  ASCON_FLOW_DECRYPT_DATA_UPDATED = 4,
  ASCON_FLOW_ENCRYPT_DATA_FINALIZED = 5,
  ASCON_FLOW_DECRYPT_DATA_FINALIZED = 6,

cdef class AeadObj:
  cdef ascon_aead_ctx_t* ctx
  cdef current_tag
  cdef num_generated_cipher_bytes
  cdef num_generated_plaintext_bytes
  cdef bytes_returned_on_last_encryption
  cdef bytes_returned_on_last_decryption

  cdef public nonce
  cdef tag_len
  cdef ciphertext 
  cdef plaintext 
  cdef variant
  cdef num_processed_plaintext_bytes
  cdef num_processed_ciphertext_bytes
  cdef lock
  cdef flow_state

  def __init__(self):
    self.ctx = new_aead_ctx()
    self.current_tag = None
    self.num_generated_cipher_bytes = 0
    self.num_generated_plaintext_bytes = 0
    self.bytes_returned_on_last_encryption = 0
    self.bytes_returned_on_last_decryption = 0


    self.nonce = None
    self.tag_len = None
    self.ciphertext = bytearray()
    self.plaintext = bytearray()
    self.num_processed_plaintext_bytes = 0
    self.num_processed_ciphertext_bytes = 0
    self.lock = threading.Lock()
    self.flow_state = _AsconFlow.ASCON_FLOW_INVALID



  # This method initializes the state and creates the cipher context and
  # stores it for future operations.
  # The actual initialization is realized via C APIs.

  # @param key: Secret key of #ASCON_AEAD128_KEY_LEN bytes. Not NULL
  # @param variant: The chosen ascon variant. The default variant is AEAD128.
  # @param nonce: Public unique nonce of #ASCON_AEAD_NONCE_LEN bytes.
  #               A random Nonce is generated in case no nonce is passed.
  # @param tag_len: The desired length of the tag. Needs to be atleast 16 bytes.

  # @return: None
  cdef init_state(self, const uint8_t[::1] key, variant, const uint8_t[::1] nonce, tag_len):
    if variant not in [AEAD80PQ, AEAD128, AEAD128A]:
      variant_str = str(variant)
      raise ValueError("unsupported Ascon variant " + variant_str)

    

    if nonce == None:
      nonce = Random.get_random_bytes(ASCON_AEAD_NONCE_LEN)

    nonce_length = len(nonce)
    key_length = len(key)
    if nonce_length != ASCON_AEAD_NONCE_LEN:
      raise ValueError("Incorrect nonce length (required nonce length: " + str(ASCON_AEAD_NONCE_LEN) + ")")

    self.variant = variant
    self.nonce = nonce
    self.tag_len = tag_len

    if self.tag_len < ASCON_AEAD_TAG_MIN_SECURE_LEN:
      raise ValueError("Length of the tag too short (minimum required tag length: " + str(ASCON_AEAD_TAG_MIN_SECURE_LEN) + ")")

    if self.variant == AEAD128:
      if key_length != ASCON_AEAD128_KEY_LEN:
        raise KeyError("Incorrect key length for selected variant (required key length for Ascon-128: " + str(ASCON_AEAD128_KEY_LEN) + ")")
      ascon_aead128_init(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> &key[0], <uint8_t*> &nonce[0])
    elif self.variant == AEAD128A:
      if key_length != ASCON_AEAD128a_KEY_LEN:
        raise KeyError("Incorrect key length for selected variant (required key length for Ascon-128a: " + str(ASCON_AEAD128a_KEY_LEN) + ")")
      ascon_aead128a_init(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> &key[0], <uint8_t*> &nonce[0])
    else:
      if key_length != ASCON_AEAD80pq_KEY_LEN:
        raise KeyError("Incorrect key length for selected variant (required key length for Ascon-80pq: " + str(ASCON_AEAD80pq_KEY_LEN) + ")")
      ascon_aead80pq_init(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> &key[0], <uint8_t*> &nonce[0])

    self.flow_state = _AsconFlow.ASCON_FLOW_AEAD_INITIALIZED
    

  # This method updates the state with an associated data chunk.
  # It can only be called after initialization or another update() call, as a call to encrypt() or decrypt()
  # finalizes the absorption of associated data.

  # This method can be called an arbitrary number of times to update the state with associated data.

  # @param data: Associated data in bytes.

  # @return: None
  def update(self, const uint8_t[::1] data) -> None: 

    self.lock.acquire()
    if (self.flow_state != _AsconFlow.ASCON_FLOW_AEAD_INITIALIZED and
        self.flow_state != _AsconFlow.ASCON_FLOW_ASSOC_DATA_UPDATED):
      self.lock.release()
      raise TypeError("update() can only be called after initialization or "
                        "another update() call")
    if len(data) == 0:
      self.lock.release()
      return
        

    length_data = len(data)

    if self.variant == AEAD128:
      ascon_aead128_assoc_data_update(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> &data[0], <size_t> length_data)
    elif self.variant == AEAD128A:
      ascon_aead128a_assoc_data_update(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> &data[0], <size_t> length_data)
    else:
      ascon_aead80pq_assoc_data_update(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> &data[0], <size_t> length_data)

    self.flow_state = _AsconFlow.ASCON_FLOW_ASSOC_DATA_UPDATED
    self.lock.release()


  
  # This method updates the state with a plaintext chunk after any
  # optional associated data has been processed. In case enough plaintext
  # was processed to cause an absorption into the state, the absorbed part 
  # will be encrypted and returned in chunks of ASCON_RATE bytes.
  # 
  # This method can be called an arbitrary number of times to update the
  # state with plaintext.
  # It will automatically finalize the absorption of any associated data,
  # so no new associated data could be processed after this function is called.

  # An empty call to encrypt(), returns any remaining buffered ciphertext and generates
  # the tag, but every other consecutive empty call to encrypt(), returns an empty bytestring.
  # Calling this function after a call to decrypt() results in an exception

  # @param plaintext: (partial) plaintext in bytes.

  # @return: The ciphertext for the absorbed plaintext in bytes. Empty if no ciphertext
  #           was absorbed.
  
  def encrypt(self, const uint8_t[::1] plaintext = None) -> bytes: 
    self.lock.acquire()
    if (self.flow_state == _AsconFlow.ASCON_FLOW_DECRYPT_DATA_UPDATED or 
      self.flow_state == _AsconFlow.ASCON_FLOW_DECRYPT_DATA_FINALIZED):
      self.lock.release()
      raise TypeError("encrypt() can't be called after state was updated with ciphertext")
    
    self.flow_state = _AsconFlow.ASCON_FLOW_ENCRYPT_DATA_UPDATED 

    num_bytes = 0
    if plaintext != None:
      if len(plaintext) == 0:
        self.lock.release()
        return b""
      length_plaintext = len(plaintext)

      rate = ASCON_DOUBLE_RATE if self.variant == AEAD128A else ASCON_RATE
 
      not_absorbed_plaintext_bytes = self.num_processed_plaintext_bytes % rate
      length_plaintext_to_absorb = length_plaintext + not_absorbed_plaintext_bytes
      length_ciphertext = length_plaintext_to_absorb - (length_plaintext_to_absorb % rate)

      
      self.num_processed_plaintext_bytes += length_plaintext

      ciphertext = bytearray(length_ciphertext) 

      if self.variant == AEAD128:
        num_bytes = ascon_aead128_encrypt_update(<ascon_aead_ctx_t*> self.ctx, 
                                                  <uint8_t*> ciphertext, 
                                                  <uint8_t*> &plaintext[0], <size_t> length_plaintext)
      elif self.variant == AEAD128A:
        num_bytes = ascon_aead128a_encrypt_update(<ascon_aead_ctx_t*> self.ctx, 
                                                  <uint8_t*> ciphertext, 
                                                  <uint8_t*> &plaintext[0], <size_t> length_plaintext)
      else:
        num_bytes = ascon_aead80pq_encrypt_update(<ascon_aead_ctx_t*> self.ctx, 
                                                  <uint8_t*> ciphertext, 
                                                  <uint8_t*> &plaintext[0], <size_t> length_plaintext)


      self.num_generated_cipher_bytes += num_bytes
     
      length_ciphertext_before = len(ciphertext)
      ciphertext = ciphertext[self.bytes_returned_on_last_encryption:]
      length_ciphertext_after = len(ciphertext)
      self.bytes_returned_on_last_encryption -= (length_ciphertext_before - length_ciphertext_after)

      self.lock.release()
      if num_bytes != 0:  
        return bytes(ciphertext)  
      else:
        return b""
    
    else: 
      if self.flow_state == _AsconFlow.ASCON_FLOW_ENCRYPT_DATA_FINALIZED:
        self.lock.release()
        return b""
      num_bytes = 0
      tag = bytearray(self.tag_len)
     
      ciphertext = bytearray(self.num_processed_plaintext_bytes - self.num_generated_cipher_bytes)

      if self.variant == AEAD128:
        num_bytes = ascon_aead128_encrypt_intermediate(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> ciphertext, <uint8_t*> tag, 
                                    <size_t> self.tag_len)
      elif self.variant == AEAD128A:
        num_bytes = ascon_aead128a_encrypt_intermediate(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> ciphertext, <uint8_t*> tag, 
                                      <size_t> self.tag_len)
      else:
        num_bytes = ascon_aead80pq_encrypt_intermediate(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> ciphertext, <uint8_t*> tag, 
                                      <size_t> self.tag_len)


      self.flow_state = _AsconFlow.ASCON_FLOW_ENCRYPT_DATA_FINALIZED 
      self.current_tag = tag 
      
      length_ciphertext_before = len(ciphertext)
      ciphertext = ciphertext[self.bytes_returned_on_last_encryption:]
      length_ciphertext_after = len(ciphertext)

      if num_bytes != 0:
        self.bytes_returned_on_last_encryption += len(ciphertext)
        self.lock.release()
        return bytes(ciphertext)
      else:
        self.lock.release()
        return b""

  
  # This method returns the authentication tag for the generated ciphertext up to this point.
 
  # It can only be called after an empty call to encrypt().

  # @return: The authentication tag for the generated ciphertext.
  
  def digest(self) -> bytes:
    self.lock.acquire()
    if self.flow_state != _AsconFlow.ASCON_FLOW_ENCRYPT_DATA_FINALIZED:
      self.lock.release()
      raise TypeError("digest() can only be called after an empty call to encrypt()")
    ret_tag = self.current_tag
    self.lock.release()
    return bytes(ret_tag)
    


  
  # This method encrypts the whole message and generates the tag, but leaves the state unaltered.
  # It can be used if all the data (associated data, message), is known in advance and all the
  # data can be stored at once. (memory capacity of the system)
 
  # It may only be used immediately after initialization

  # @param data: Associated data in bytes.
  # @param plaintext: Full plaintext in bytes.

  # @return: The ciphertext for the corresponding plaintext and the authentication tag.
  
  def encrypt_and_digest_complete(self, const uint8_t[::1] data, const uint8_t[::1] plaintext) -> tuple[bytes, bytes]: #update function header in ascon.h
    self.lock.acquire()
    if self.flow_state != _AsconFlow.ASCON_FLOW_AEAD_INITIALISED:
      self.lock.release()
      raise TypeError("This function may only be called immediately after initialization.")
    

    tag = bytearray(self.tag_len)
    length_plaintext = len(plaintext)

    length_data = len(data)

    ciphertext = bytearray(length_plaintext)

    if self.variant == AEAD128:
      ascon_aead128_encrypt(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> &data[0], <uint8_t*> &plaintext[0], <size_t> length_data, 
                            <size_t> length_plaintext, <uint8_t*> ciphertext, <uint8_t*> tag, <size_t> self.tag_len)
    elif self.variant == AEAD128A:
      ascon_aead128a_encrypt(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> &data[0], <uint8_t*> &plaintext[0], <size_t> length_data, 
                            <size_t> length_plaintext, <uint8_t*> ciphertext, <uint8_t*> tag, <size_t> self.tag_len)
    else:
      ascon_aead80pq_encrypt(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> &data[0], <uint8_t*> &plaintext[0], <size_t> length_data, 
                            <size_t> length_plaintext, <uint8_t*> ciphertext, <uint8_t*> tag, <size_t> self.tag_len)
                          
    self.lock.release()
    return bytes(ciphertext), bytes(tag)


  
  # This method updates the state with a ciphertext chunk after any
  # optional associated data has been processed. In case enough ciphertext
  # was processed to cause an absorption into the state, the absorbed part 
  # will be decrypted and returned in chunks of ASCON_RATE bytes.
 
  # This method can be called an arbitrary number of times to update the
  # state with ciphertext.
  # It will automatically finalize the absorption of any associated data,
  # so no new associated data could be processed after this function is called.

  # An empty call to decrypt(), returns any remaining buffered plaintext and
  # generates the expected tag but every other consecutive empty call to decrypt(), 
  # returns an empty bytestring. Calling this function after a call to encrypt() 
  # results in an exception.

  # @param ciphertext: (partial) ciphertext in bytes.

  # @return: The plaintext for the absorbed ciphertext in bytes. Empty if no ciphertext
  #           was absorbed.
  
  def decrypt(self, const uint8_t[::1] ciphertext = None) -> bytes:
    self.lock.acquire()
    if self.flow_state == _AsconFlow.ASCON_FLOW_ENCRYPT_DATA_UPDATED or self.flow_state == _AsconFlow.ASCON_FLOW_ENCRYPT_DATA_FINALIZED:
      self.lock.release()
      raise TypeError("decrypt() can't be called after state was updated with plaintext")

    self.flow_state = _AsconFlow.ASCON_FLOW_DECRYPT_DATA_UPDATED
    num_bytes = 0
    if ciphertext != None:
      if len(ciphertext) == 0:
        self.lock.release()
        return b""
      length_ciphertext = len(ciphertext)

      rate = ASCON_DOUBLE_RATE if self.variant == AEAD128A else ASCON_RATE
      
      not_absorbed_ciphertext_bytes = self.num_processed_ciphertext_bytes % rate
      length_ciphertext_to_absorb = length_ciphertext + not_absorbed_ciphertext_bytes
      length_plaintext = length_ciphertext_to_absorb - (length_ciphertext_to_absorb % rate)
      
      self.num_processed_ciphertext_bytes += length_ciphertext
      
      plaintext = bytearray(length_plaintext) 
      
      if self.variant == AEAD128:
        num_bytes = ascon_aead128_decrypt_update(<ascon_aead_ctx_t*> self.ctx, 
                                                  <uint8_t*> plaintext, 
                                                  <uint8_t*> &ciphertext[0], <size_t> length_ciphertext)
      elif self.variant == AEAD128A:
        num_bytes = ascon_aead128a_decrypt_update(<ascon_aead_ctx_t*> self.ctx, 
                                                  <uint8_t*> plaintext, 
                                                  <uint8_t*> &ciphertext[0], <size_t> length_ciphertext)
      else:
        num_bytes = ascon_aead80pq_decrypt_update(<ascon_aead_ctx_t*> self.ctx, 
                                                  <uint8_t*> plaintext, 
                                                  <uint8_t*> &ciphertext[0], <size_t> length_ciphertext)

      
      self.num_generated_plaintext_bytes += num_bytes
    
      length_plaintext_before = len(plaintext)

      plaintext = plaintext[self.bytes_returned_on_last_decryption:]
      length_plaintext_after = len(plaintext)
 
      self.bytes_returned_on_last_decryption -= (length_plaintext_before - length_plaintext_after)


      self.lock.release()
      if num_bytes != 0:
        return bytes(plaintext)
      else:
        return b""

    else:
      if self.flow_state == _AsconFlow.ASCON_FLOW_DECRYPT_DATA_FINALIZED:
        self.lock.release()
        return b""
      tag = bytearray(self.tag_len) 
      plaintext = bytearray(self.num_processed_ciphertext_bytes - self.num_generated_plaintext_bytes)
    
      if self.variant == AEAD128:
        num_bytes = ascon_aead128_decrypt_intermediate(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> plaintext, 
                                                       <uint8_t*> tag, <size_t> self.tag_len)
      elif self.variant == AEAD128A:
        num_bytes = ascon_aead128a_decrypt_intermediate(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> plaintext, 
                                                        <uint8_t*> tag, <size_t> self.tag_len)
      else:
        num_bytes = ascon_aead80pq_decrypt_intermediate(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> plaintext, 
                                                        <uint8_t*> tag, <size_t> self.tag_len)

      
      self.current_tag = tag
      self.flow_state = _AsconFlow.ASCON_FLOW_DECRYPT_DATA_FINALIZED

      length_plaintext_before = len(plaintext)
 
      plaintext = plaintext[self.bytes_returned_on_last_decryption:]
      length_plaintext_after = len(plaintext)
   
      if num_bytes != 0:
        self.bytes_returned_on_last_decryption += len(plaintext)
        self.lock.release()
        return bytes(plaintext)
      else:
        self.lock.release()
        return b""

  
  # This method verifies if the returned tag from digest() during the encryption process
  # matches the expected tag which was generated in the decryption process.
 
  # It can only be called after an empty call to decrypt().

  # @return: "true" if the tag ist valid, "false" otherwise.
  
  def verify(self, const uint8_t[::1] tag) -> None:
    
    self.lock.acquire()
    if self.flow_state != _AsconFlow.ASCON_FLOW_DECRYPT_DATA_FINALIZED:
      self.lock.release()
      raise TypeError("verify() can only be called after an empty call to decrypt()")
    actual_tag_len = len(tag)
    
    is_tag_valid = ascon_aead_is_tag_valid_intermediate(<uint8_t*> self.current_tag, <size_t> self.tag_len, <uint8_t*> &tag[0], <size_t> actual_tag_len)

    self.lock.release()
    return is_tag_valid


  
  # This method decrypts the whole ciphertext and verifies the tag, but leaves the state unaltered.
  # It can be used if all the data (associated data, ciphertext), is known in advance and all the
  # data can be stored at once. (memory capacity of the system)
 
  # It may only be used immediately after initialization.
  # An invalid tag results in an exception and no plaintext is returned.

  # @param data: Associated data in bytes.
  # @param ciphertext: Full ciphertext in bytes.
  # @param tag: The authentication tag for the ciphertext.

  # @return: The ciphertext for the corresponding plaintext and the authentication tag.
  
  def decrypt_and_verify_complete(self, const uint8_t[::1] data, const uint8_t[::1] ciphertext, const uint8_t[::1] tag) -> bytes:
    self.lock.acquire()
    if self.flow_state != _AsconFlow.ASCON_FLOW_AEAD_INITIALIZED:
      self.lock.release()
      raise TypeError("This function may only be called immediately after initialization.")
    

    length_ciphertext = len(ciphertext)
    length_data = len(data)
    expected_tag_len = len(tag)
    

    plaintext = bytearray(length_ciphertext)
    cdef bool tag_valid = False
    if self.variant == AEAD128:
      tag_valid = ascon_aead128_decrypt(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> plaintext, <uint8_t*> &data[0], 
                            <uint8_t*> &ciphertext[0], <uint8_t*> &tag[0], <size_t> length_data, 
                            <size_t> length_ciphertext, <size_t> expected_tag_len)
    elif self.variant == AEAD128A:
      tag_valid = ascon_aead128a_decrypt(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> plaintext, <uint8_t*> &data[0], 
                            <uint8_t*> &ciphertext[0], <uint8_t*> &tag[0], <size_t> length_data, 
                            <size_t> length_ciphertext, <size_t> expected_tag_len)
    else:
      tag_valid = ascon_aead80pq_decrypt(<ascon_aead_ctx_t*> self.ctx, <uint8_t*> plaintext, <uint8_t*> &data[0], 
                            <uint8_t*> &ciphertext[0], <uint8_t*> &tag[0], <size_t> length_data, 
                            <size_t> length_ciphertext, <size_t> expected_tag_len)
                          
    if tag_valid == False:
      self.lock.release()
      raise ValueError("Invalid tag! - Authentication failed!")
    self.lock.release()
    return bytes(plaintext)

  # Destructor of the AeadObj class, clears and frees the memory of the cipher context.
  def __del__(self):
    ascon_aead_cleanup(<ascon_aead_ctx_t*> self.ctx)
    ascon_aead_free(<ascon_aead_ctx_t*> self.ctx)



# This function is called to initialize a AeadObj, which implements the authenticated encryption
# of the Ascon suite.

# It creates a new object and calls the initialization function, see init_state for parameter details.

# @return: The initialized AEAD object.
def new(key, variant=AEAD128, nonce=None, tag_len=ASCON_AEAD_TAG_MIN_SECURE_LEN) -> AeadObj:
  if key == None or len(key) == 0:
    raise KeyError("Key can't be empty for AEAD!")
  m = AeadObj()
  m.init_state(key, variant, nonce, tag_len)
  return m