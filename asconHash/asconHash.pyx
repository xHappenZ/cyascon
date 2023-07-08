cimport cython
from libc.stdint cimport uint8_t
import threading


cdef extern from "ascon_hash.c":
  ctypedef struct ascon_hash_ctx_t:
    uint8_t flow_state
    pass

  ctypedef enum ascon_variant_t:
    ASCON_HASH = 0,
    ASCON_HASHA,
    ASCON_XOF,
    ASCON_XOFA

  cdef const int ASCON_HASH_DIGEST_LEN

  ctypedef struct AsconHashObj:
    pass

  void ascon_hash_cleanup(ascon_hash_ctx_t* const ctx)

  void ascon_hash_free(ascon_hash_ctx_t* const ctx)

  ascon_hash_ctx_t* new_hash_ctx()

  void ascon_hash_init(ascon_hash_ctx_t* const ctx)

  void ascon_hasha_init(ascon_hash_ctx_t* const ctx)

  void ascon_hash_xof_init(ascon_hash_ctx_t* const ctx)

  void ascon_hasha_xof_init(ascon_hash_ctx_t* const ctx)

  void ascon_hash_update(ascon_hash_ctx_t* const ctx,
                          const uint8_t* data,
                          size_t data_len)
  void ascon_hasha_update(ascon_hash_ctx_t* const ctx,
                          const uint8_t* data,
                          size_t data_len)
  void ascon_hash_xof_update(ascon_hash_ctx_t* const ctx,
                              const uint8_t* data,
                              size_t data_len)
  void ascon_hasha_xof_update(ascon_hash_ctx_t* const ctx,
                              const uint8_t* data,
                              size_t data_len)

  void ascon_hash_xof_final(ascon_hash_ctx_t* const ctx,
                            uint8_t* digest,
                            size_t digest_len)
  void ascon_hasha_xof_final(ascon_hash_ctx_t* const ctx,
                            uint8_t* digest,
                            size_t digest_len)
  void ascon_hash_final(ascon_hash_ctx_t* const ctx,
                        uint8_t digest[ASCON_HASH_DIGEST_LEN])
  void ascon_hasha_final(ascon_hash_ctx_t* const ctx,
                          uint8_t digest[ASCON_HASH_DIGEST_LEN])

cdef class HashObj:
  cdef ascon_hash_ctx_t* ctx
  cdef variant
  cdef lock

  def __init__(self):
    self.ctx = new_hash_ctx()
    self.variant = ASCON_HASH
    self.lock = threading.Lock()

  # This method initializes the state and creates the cipher context for
  # Ascon hashing and stores it for future operations.
  # The actual initialization is realized via C APIs.

  # @param variant: The chosen ascon variant. The default variant is ASCON_HASH.

  # @return: None
  cdef init_state(self, variant):
    if variant not in ["Ascon-Hash", "Ascon-Hasha", "Ascon-Xof", "Ascon-Xofa"]:
      variant_str = str(variant)
      raise ValueError("unsupported Ascon variant " + variant_str)

    self.variant = variant
    if self.variant == "Ascon-Hash":
      ascon_hash_init(<ascon_hash_ctx_t*> self.ctx)
    elif self.variant == "Ascon-Hasha":
      ascon_hasha_init(<ascon_hash_ctx_t*> self.ctx)
    elif self.variant == "Ascon-Xof":
      ascon_hash_xof_init(<ascon_hash_ctx_t*> self.ctx)
    else:
      ascon_hasha_xof_init(<ascon_hash_ctx_t*> self.ctx)

  # This method updates the state with a message chunk.
  # 
  # This method can be called an arbitrary number of times to update the
  # state with the message.

  # @param plaintext: (partial) message in bytes.

  # @return: None
  def update(self, const uint8_t[::1] message) -> None:
    l_m = len(message)
    self.lock.acquire()

    if self.variant == "Ascon-Hash":
      ascon_hash_update(<ascon_hash_ctx_t*> self.ctx, <uint8_t*> &message[0], <size_t> l_m)
    elif self.variant == "Ascon-Hasha":
      ascon_hasha_update(<ascon_hash_ctx_t*> self.ctx, <uint8_t*> &message[0], <size_t> l_m)
    elif self.variant == "Ascon-Xof":
      ascon_hash_xof_update(<ascon_hash_ctx_t*> self.ctx, <uint8_t*> &message[0], <size_t> l_m)
    else:
      ascon_hasha_xof_update(<ascon_hash_ctx_t*> self.ctx, <uint8_t*> &message[0], <size_t> l_m)

    self.lock.release()

  # This method returns the hash for the absorbed message.
  # 
  # The remaining buffered part of the message is absorbed into a disposable copy of the state.
  # The stored state remains unaltered and subsequent calls to update() are possible and a call
  # to digest has no effect on the result on a later generated hash.

  # Consequtive calls to digest() result in the same hash output.

  # The hashlength for ASCON_HASH and ASCON_HASHA is ASCON_HASH_DIGEST_LEN.

  # @param hashlength: The desired length of the hash (only for ASCON_XOF and ASCON_XOFA)

  # @return: The hash output in bytes.
  def digest(self, hashlength=ASCON_HASH_DIGEST_LEN) -> bytes:
    self.lock.acquire()
    if hashlength != ASCON_HASH_DIGEST_LEN and self.variant not in ["Ascon-Xof", "Ascon-Xofa"]:
      raise ValueError("Wrong length for Ascon variant")

    digest = bytearray(hashlength)

    if self.variant == "Ascon-Hash":
      ascon_hash_final(<ascon_hash_ctx_t*> self.ctx, <uint8_t*> digest)
    elif self.variant == "Ascon-Hasha":
      ascon_hasha_final(<ascon_hash_ctx_t*> self.ctx, <uint8_t*> digest)
    elif self.variant == "Ascon-Xof":
      ascon_hash_xof_final(<ascon_hash_ctx_t*> self.ctx, <uint8_t*> digest, <size_t> hashlength)
    else:
      ascon_hasha_xof_final(<ascon_hash_ctx_t*> self.ctx, <uint8_t*> digest, <size_t> hashlength)
    
    self.lock.release()
    return bytes(digest)

  # Destructor of the HashObj class, clears and frees the memory of the cipher context.
  def __del__(self):
      ascon_hash_cleanup(<ascon_hash_ctx_t*> self.ctx)
      ascon_hash_free(<ascon_hash_ctx_t*> self.ctx)


# This function is called to initialize a HashObj, which implements Ascon hashing

# It creates a new object and calls the initialization function, see init_state for parameter details.

# @return: The initialized hash object.
def new(variant="Ascon-Hash"):
  m = HashObj()
  m.init_state(variant)
  return m
