//  Delphi Wrapper for libsodium.dll
//    should work with most versions of 32-bit and 64-bit Delphi/FreePascal
//    for 64-bit, tries to load libsodium64.dll instead of libsodium.dll, if available
//
//  by Alexander Paul Morris, 2015-08-08
//
//  based on libsodium 1.0.3 C DLL header files
//    sodium_increment() should also work once libsodium 1.0.4 is released
//
//  a bit of the initial grunt work performed by the very helpful
//  HeadConv 4.20 (c) 2000 by Bob Swart (aka Dr.Bob - www.drbob42.com)
//
//  This unit is still a work in progress.  I'm sure I still missed
//  or misunderstood a few things along the way, so feel free to submit
//  corrections or updates.
//
//  for more details of the inner workings of this API, see the docs at:
//  http://doc.libsodium.org/
//
//  for a better understand of why this encryption library is useful:
//  https://blog.cloudflare.com/do-the-chacha-better-mobile-performance-with-cryptography/
//  https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/
//
//  complete libsodium implementation in javascript using Emscripten:
//  https://github.com/jedisct1/libsodium.js
//
//  the latest libsodium library releases can be found here:
//  http://download.libsodium.org/libsodium/releases/
//
//  v0.11 - 2015-08-08, a few minor changes for 64-bit compatibility
//  v0.10 - 2015-08-06, initial release
//

{$IFDEF fpc}
  {$MODE delphi}{$H+}
{$ENDIF}

unit libsodium;


interface

uses SysUtils, Wintypes, WinProcs;

{=> LIBSODIUM.H <=}

// unsigned long long = UINT64
{$IF CompilerVersion <= 15.0} { Delphi 7+ }
type
  //SIZE_T = DWORD;
  UINT8 = Byte;
  UINT16 = WORD;
  UINT32 = DWORD;
  INT16 = SmallInt;
  INT32 = LongInt;
{$IFEND}

type
  dwSIZE_T = DWORD;
  crypto_hash_sha256_state = packed record
    state: Array[0..7] of UINT32;
    count: Array[0..1] of UINT32;
    buf: Array[0..63] of Byte;
  end {crypto_hash_sha256_state};

  crypto_hash_sha512_state = packed record
    state: Array[0..7] of UINT64;
    count: Array[0..1] of UINT64;
    buf: Array[0..127] of Byte;
  end {crypto_hash_sha512_state};

  crypto_auth_hmacsha256_state = packed record
    ictx: CRYPTO_HASH_SHA256_STATE;
    octx: CRYPTO_HASH_SHA256_STATE;
  end {crypto_auth_hmacsha256_state};

  crypto_auth_hmacsha512_state = packed record
    ictx: CRYPTO_HASH_SHA512_STATE;
    octx: CRYPTO_HASH_SHA512_STATE;
  end {crypto_auth_hmacsha512_state};
  crypto_auth_hmacsha512256_state = CRYPTO_AUTH_HMACSHA512_STATE;

  { //#pragma pack(push, 1) CRYPTO_ALIGN(64) = __declspec(align(64)) }
  crypto_generichash_blake2b_state = packed record
      h: Array[0..7] of UINT64;
      t: Array[0..1] of UINT64;
      f: Array[0..1] of UINT64;
      buf: Array[0..255] of UINT8;
      buflen: dwSIZE_T;
      last_node: UINT8;
      padding64: array[0..26] of byte;
    end {CRYPTO_ALIGN(64) crypto_generichash_blake2b_state};
  { //#pragma pack(pop) }
  crypto_generichash_state = CRYPTO_GENERICHASH_BLAKE2B_STATE;

  crypto_onetimeauth_poly1305_state = packed record
    aligner: UINT64;
    opaque: Array[0..135] of Byte;
  end {crypto_onetimeauth_poly1305_state};

  crypto_int32 = INT32;
  crypto_int64 = INT64;
  crypto_onetimeauth_state = CRYPTO_ONETIMEAUTH_POLY1305_STATE;

  crypto_uint16 = UINT16;
  crypto_uint32 = UINT32;
  crypto_uint64 = UINT64;
  crypto_uint8 = UINT8;

  PUINT8 = ^UINT8;


const
  ls_crypto_aead_chacha20poly1305_KEYBYTES = 32;
  ls_crypto_aead_chacha20poly1305_NSECBYTES = 0;
  ls_crypto_aead_chacha20poly1305_NPUBBYTES = 8;
  ls_crypto_aead_chacha20poly1305_ABYTES = 16;

  ls_crypto_auth_hmacsha512256_BYTES = 32;
  ls_crypto_auth_hmacsha512256_KEYBYTES = 32;
  ls_crypto_auth_BYTES = ls_crypto_auth_hmacsha512256_BYTES;
  ls_crypto_auth_KEYBYTES = ls_crypto_auth_hmacsha512256_KEYBYTES;
  ls_crypto_auth_PRIMITIVE = 'hmacsha512256';
  ls_crypto_auth_hmacsha256_BYTES = 32;
  ls_crypto_auth_hmacsha256_KEYBYTES = 32;
  ls_crypto_auth_hmacsha512_BYTES = 64;
  ls_crypto_auth_hmacsha512_KEYBYTES = 32;

  ls_crypto_box_curve25519xsalsa20poly1305_SEEDBYTES = 32;
  ls_crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES = 32;
  ls_crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES = 32;
  ls_crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES = 32;
  ls_crypto_box_curve25519xsalsa20poly1305_NONCEBYTES = 24;
  ls_crypto_box_curve25519xsalsa20poly1305_ZEROBYTES = 32;
  ls_crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES = 16;
  ls_crypto_box_curve25519xsalsa20poly1305_MACBYTES = (ls_crypto_box_curve25519xsalsa20poly1305_ZEROBYTES - ls_crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES);
  ls_crypto_box_SEEDBYTES = ls_crypto_box_curve25519xsalsa20poly1305_SEEDBYTES;
  ls_crypto_box_PUBLICKEYBYTES = ls_crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES;
  ls_crypto_box_SECRETKEYBYTES = ls_crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES;
  ls_crypto_box_NONCEBYTES = ls_crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
  ls_crypto_box_MACBYTES = ls_crypto_box_curve25519xsalsa20poly1305_MACBYTES;
  ls_crypto_box_PRIMITIVE = 'curve25519xsalsa20poly1305';
  ls_crypto_box_BEFORENMBYTES = ls_crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES;
  ls_crypto_box_SEALBYTES = (ls_crypto_box_PUBLICKEYBYTES + ls_crypto_box_MACBYTES);
  ls_crypto_box_ZEROBYTES = ls_crypto_box_curve25519xsalsa20poly1305_ZEROBYTES;
  ls_crypto_box_BOXZEROBYTES = ls_crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;

  ls_crypto_core_hsalsa20_OUTPUTBYTES = 32;
  ls_crypto_core_hsalsa20_INPUTBYTES = 16;
  ls_crypto_core_hsalsa20_KEYBYTES = 32;
  ls_crypto_core_hsalsa20_CONSTBYTES = 16;
  ls_crypto_core_salsa20_OUTPUTBYTES = 64;
  ls_crypto_core_salsa20_INPUTBYTES = 16;
  ls_crypto_core_salsa20_KEYBYTES = 32;
  ls_crypto_core_salsa20_CONSTBYTES = 16;
  ls_crypto_core_salsa2012_OUTPUTBYTES = 64;
  ls_crypto_core_salsa2012_INPUTBYTES = 16;
  ls_crypto_core_salsa2012_KEYBYTES = 32;
  ls_crypto_core_salsa2012_CONSTBYTES = 16;
  ls_crypto_core_salsa208_OUTPUTBYTES = 64;
  ls_crypto_core_salsa208_INPUTBYTES = 16;
  ls_crypto_core_salsa208_KEYBYTES = 32;
  ls_crypto_core_salsa208_CONSTBYTES = 16;

  ls_crypto_generichash_blake2b_BYTES_MIN = 16;
  ls_crypto_generichash_blake2b_BYTES_MAX = 64;
  ls_crypto_generichash_blake2b_BYTES = 32;
  ls_crypto_generichash_blake2b_KEYBYTES_MIN = 16;
  ls_crypto_generichash_blake2b_KEYBYTES_MAX = 64;
  ls_crypto_generichash_blake2b_KEYBYTES = 32;
  ls_crypto_generichash_blake2b_SALTBYTES = 16;
  ls_crypto_generichash_blake2b_PERSONALBYTES = 16;

  ls_crypto_generichash_BYTES_MIN = ls_crypto_generichash_blake2b_BYTES_MIN;
  ls_crypto_generichash_BYTES_MAX = ls_crypto_generichash_blake2b_BYTES_MAX;
  ls_crypto_generichash_BYTES = ls_crypto_generichash_blake2b_BYTES;
  ls_crypto_generichash_KEYBYTES_MIN = ls_crypto_generichash_blake2b_KEYBYTES_MIN;
  ls_crypto_generichash_KEYBYTES_MAX = ls_crypto_generichash_blake2b_KEYBYTES_MAX;
  ls_crypto_generichash_KEYBYTES = ls_crypto_generichash_blake2b_KEYBYTES;
  ls_crypto_generichash_PRIMITIVE = 'blake2b';

  ls_crypto_hash_sha256_BYTES = 32;
  ls_crypto_hash_sha512_BYTES = 64;

  ls_crypto_hash_BYTES = ls_crypto_hash_sha512_BYTES;
  ls_crypto_hash_PRIMITIVE = 'sha512';

  ls_crypto_onetimeauth_poly1305_BYTES = 16;
  ls_crypto_onetimeauth_poly1305_KEYBYTES = 32;

  ls_crypto_onetimeauth_BYTES = ls_crypto_onetimeauth_poly1305_BYTES;
  ls_crypto_onetimeauth_KEYBYTES = ls_crypto_onetimeauth_poly1305_KEYBYTES;
  ls_crypto_onetimeauth_PRIMITIVE = 'poly1305';

  ls_crypto_pwhash_scryptsalsa208sha256_SALTBYTES = 32;
  ls_crypto_pwhash_scryptsalsa208sha256_STRBYTES = 102;
  ls_crypto_pwhash_scryptsalsa208sha256_STRPREFIX = '$7$';
  ls_crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE = 524288;
  ls_crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE = 16777216;
  ls_crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE = 33554432;
  ls_crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE = 1073741824;

  ls_crypto_scalarmult_curve25519_BYTES = 32;
  ls_crypto_scalarmult_curve25519_SCALARBYTES = 32;

  ls_crypto_scalarmult_BYTES = ls_crypto_scalarmult_curve25519_BYTES;
  ls_crypto_scalarmult_SCALARBYTES = ls_crypto_scalarmult_curve25519_SCALARBYTES;
  ls_crypto_scalarmult_PRIMITIVE = 'curve25519';

  ls_crypto_secretbox_xsalsa20poly1305_KEYBYTES = 32;
  ls_crypto_secretbox_xsalsa20poly1305_NONCEBYTES = 24;
  ls_crypto_secretbox_xsalsa20poly1305_ZEROBYTES = 32;
  ls_crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES = 16;
  ls_crypto_secretbox_xsalsa20poly1305_MACBYTES = (ls_crypto_secretbox_xsalsa20poly1305_ZEROBYTES - ls_crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);

  ls_crypto_secretbox_KEYBYTES = ls_crypto_secretbox_xsalsa20poly1305_KEYBYTES;
  ls_crypto_secretbox_NONCEBYTES = ls_crypto_secretbox_xsalsa20poly1305_NONCEBYTES;
  ls_crypto_secretbox_MACBYTES = ls_crypto_secretbox_xsalsa20poly1305_MACBYTES;
  ls_crypto_secretbox_ZEROBYTES = ls_crypto_secretbox_xsalsa20poly1305_ZEROBYTES;
  ls_crypto_secretbox_BOXZEROBYTES = ls_crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES;
  ls_crypto_secretbox_PRIMITIVE = 'xsalsa20poly1305';

  ls_crypto_shorthash_siphash24_BYTES = 8;
  ls_crypto_shorthash_siphash24_KEYBYTES = 16;

  ls_crypto_shorthash_BYTES = ls_crypto_shorthash_siphash24_BYTES;
  ls_crypto_shorthash_KEYBYTES = ls_crypto_shorthash_siphash24_KEYBYTES;
  ls_crypto_shorthash_PRIMITIVE = 'siphash24';

  ls_crypto_sign_ed25519_BYTES = 64;
  ls_crypto_sign_ed25519_SEEDBYTES = 32;
  ls_crypto_sign_ed25519_PUBLICKEYBYTES = 32;
  ls_crypto_sign_ed25519_SECRETKEYBYTES = (32 + 32);

  ls_crypto_sign_BYTES = ls_crypto_sign_ed25519_BYTES;
  ls_crypto_sign_SEEDBYTES = ls_crypto_sign_ed25519_SEEDBYTES;
  ls_crypto_sign_PUBLICKEYBYTES = ls_crypto_sign_ed25519_PUBLICKEYBYTES;
  ls_crypto_sign_SECRETKEYBYTES = ls_crypto_sign_ed25519_SECRETKEYBYTES;
  ls_crypto_sign_PRIMITIVE = 'ed25519';

  ls_crypto_sign_edwards25519sha512batch_BYTES = 64;
  ls_crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES = 32;
  ls_crypto_sign_edwards25519sha512batch_SECRETKEYBYTES = (32 + 32);

  ls_crypto_stream_aes128ctr_KEYBYTES = 16;
  ls_crypto_stream_aes128ctr_NONCEBYTES = 16;
  ls_crypto_stream_aes128ctr_BEFORENMBYTES = 1408;
  ls_crypto_stream_chacha20_KEYBYTES = 32;
  ls_crypto_stream_chacha20_NONCEBYTES = 8;
  ls_crypto_stream_salsa20_KEYBYTES = 32;
  ls_crypto_stream_salsa20_NONCEBYTES = 8;
  ls_crypto_stream_salsa2012_KEYBYTES = 32;
  ls_crypto_stream_salsa2012_NONCEBYTES = 8;
  ls_crypto_stream_salsa208_KEYBYTES = 32;
  ls_crypto_stream_salsa208_NONCEBYTES = 8;
  ls_crypto_stream_xsalsa20_KEYBYTES = 32;
  ls_crypto_stream_xsalsa20_NONCEBYTES = 24;

  ls_crypto_stream_KEYBYTES = ls_crypto_stream_xsalsa20_KEYBYTES;
  ls_crypto_stream_NONCEBYTES = ls_crypto_stream_xsalsa20_NONCEBYTES;
  ls_crypto_stream_PRIMITIVE = 'xsalsa20';

  ls_crypto_verify_16_BYTES = 16;
  ls_crypto_verify_32_BYTES = 32;
  ls_crypto_verify_64_BYTES = 64;
  ls_SODIUM_VERSION_STRING = '1.0.3';
  ls_SODIUM_LIBRARY_VERSION_MAJOR = 7;
  ls_SODIUM_LIBRARY_VERSION_MINOR = 5;


type

  Tcrypto_aead_chacha20poly1305_keybytes = function: dwSIZE_T cdecl;
  Tcrypto_aead_chacha20poly1305_nsecbytes = function: dwSIZE_T cdecl;
  Tcrypto_aead_chacha20poly1305_npubbytes = function: dwSIZE_T cdecl;
  Tcrypto_aead_chacha20poly1305_abytes = function: dwSIZE_T cdecl;

  Tcrypto_aead_chacha20poly1305_encrypt = function(const c: PAnsiChar;
                                                   out clen: UINT64;
                                                   const m: PAnsiChar;
                                                   mlen: UINT64;
                                                   const ad: PAnsiChar;
                                                   adlen: UINT64;
                                                   const nsec: PAnsiChar;
                                                   const npub: PAnsiChar;
                                                   const k: PAnsiChar): Integer cdecl;

  Tcrypto_aead_chacha20poly1305_decrypt = function(const m: PAnsiChar;
                                                   out mlen: UINT64;
                                                   const nsec: PAnsiChar;
                                                   const c: PAnsiChar;
                                                   clen: UINT64;
                                                   const ad: PAnsiChar;
                                                   adlen: UINT64;
                                                   const npub: PAnsiChar;
                                                   const k: PAnsiChar): Integer cdecl;

  Tcrypto_auth_bytes = function: dwSIZE_T cdecl;

  Tcrypto_auth_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_auth_primitive = function: PAnsiChar cdecl;

  Tcrypto_auth = function(const outBuf: PAnsiChar;
                          const inBuf: PAnsiChar;
                          inlen: UINT64;
                          const k: PAnsiChar): Integer cdecl;

  Tcrypto_auth_verify = function(const h: PAnsiChar;
                                 const inBuf: PAnsiChar;
                                 inlen: UINT64;
                                 const k: PAnsiChar): Integer cdecl;

  Tcrypto_auth_hmacsha256_bytes = function: dwSIZE_T cdecl;

  Tcrypto_auth_hmacsha256_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_auth_hmacsha256 = function(const outBuf: PAnsiChar;
                                     const inBuf: PAnsiChar;
                                     inlen: UINT64;
                                     const k: PAnsiChar): Integer cdecl;

  Tcrypto_auth_hmacsha256_verify = function(const h: PAnsiChar;
                                            const inBuf: PAnsiChar;
                                            inlen: UINT64;
                                            const k: PAnsiChar): Integer cdecl;

  Tcrypto_auth_hmacsha256_statebytes = function: dwSIZE_T cdecl;

  Tcrypto_auth_hmacsha256_init = function(var state: CRYPTO_AUTH_HMACSHA256_STATE;
                                          const key: PAnsiChar;
                                          keylen: dwSIZE_T): Integer cdecl;

  Tcrypto_auth_hmacsha256_update = function(var state: CRYPTO_AUTH_HMACSHA256_STATE;
                                            const inBuf: PAnsiChar;
                                            inlen: UINT64): Integer cdecl;

  Tcrypto_auth_hmacsha256_final = function(var state: CRYPTO_AUTH_HMACSHA256_STATE;
                                           const outBuf: PAnsiChar): Integer cdecl;

  Tcrypto_auth_hmacsha512_bytes = function: dwSIZE_T cdecl;

  Tcrypto_auth_hmacsha512_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_auth_hmacsha512 = function(const outBuf: PAnsiChar;
                                     const inBuf: PAnsiChar;
                                     inlen: UINT64;
                                     const k: PAnsiChar): Integer cdecl;

  Tcrypto_auth_hmacsha512_verify = function(const h: PAnsiChar;
                                            const inBuf: PAnsiChar;
                                            inlen: UINT64;
                                            const k: PAnsiChar): Integer cdecl;

  Tcrypto_auth_hmacsha512_statebytes = function: dwSIZE_T cdecl;

  Tcrypto_auth_hmacsha512_init = function(var state: CRYPTO_AUTH_HMACSHA512_STATE;
                                          const key: PAnsiChar;
                                          keylen: dwSIZE_T): Integer cdecl;

  Tcrypto_auth_hmacsha512_update = function(var state: CRYPTO_AUTH_HMACSHA512_STATE;
                                            const inBuf: PAnsiChar;
                                            inlen: UINT64): Integer cdecl;

  Tcrypto_auth_hmacsha512_final = function(var state: CRYPTO_AUTH_HMACSHA512_STATE;
                                           const outBuf: PAnsiChar): Integer cdecl;

  Tcrypto_auth_hmacsha512256_bytes = function: dwSIZE_T cdecl;

  Tcrypto_auth_hmacsha512256_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_auth_hmacsha512256 = function(const outBuf: PAnsiChar;
                                        const inBuf: PAnsiChar;
                                        inlen: UINT64;
                                        const k: PAnsiChar): Integer cdecl;

  Tcrypto_auth_hmacsha512256_verify = function(const h: PAnsiChar;
                                               const inBuf: PAnsiChar;
                                               inlen: UINT64;
                                               const k: PAnsiChar): Integer cdecl;

  Tcrypto_auth_hmacsha512256_statebytes = function: dwSIZE_T cdecl;

  Tcrypto_auth_hmacsha512256_init = function(var state: CRYPTO_AUTH_HMACSHA512256_STATE;
                                             const key: PAnsiChar;
                                             keylen: dwSIZE_T): Integer cdecl;

  Tcrypto_auth_hmacsha512256_update = function(var state: CRYPTO_AUTH_HMACSHA512256_STATE;
                                               const inBuf: PAnsiChar;
                                               inlen: UINT64): Integer cdecl;

  Tcrypto_auth_hmacsha512256_final = function(var state: CRYPTO_AUTH_HMACSHA512256_STATE;
                                              const outBuf: PAnsiChar): Integer cdecl;

  // * THREAD SAFETY: crypto_box_keypair() is thread-safe, }
  // * provided that you called sodium_init() once before using any }
  // * other libsodium function. }
  // * Other functions are always thread-safe. }

  Tcrypto_box_seedbytes = function: dwSIZE_T cdecl;

  Tcrypto_box_publickeybytes = function: dwSIZE_T cdecl;

  Tcrypto_box_secretkeybytes = function: dwSIZE_T cdecl;

  tcrypto_box_noncebytes = function: dwSIZE_T cdecl;

  Tcrypto_box_macbytes = function: dwSIZE_T cdecl;

  Tcrypto_box_primitive = function: PAnsiChar cdecl;

  Tcrypto_box_seed_keypair = function(const pk: PAnsiChar;
                                      const sk: PAnsiChar;
                                      const seed: PAnsiChar): Integer cdecl;

  Tcrypto_box_keypair = function(const pk: PAnsiChar;
                                 const sk: PAnsiChar): Integer cdecl;

  Tcrypto_box_easy = function(const c: PAnsiChar;
                              const m: PAnsiChar;
                              mlen: UINT64;
                              const n: PAnsiChar;
                              const pk: PAnsiChar;
                              const sk: PAnsiChar): Integer cdecl;

  Tcrypto_box_open_easy = function(const m: PAnsiChar;
                                   const c: PAnsiChar;
                                   clen: UINT64;
                                   const n: PAnsiChar;
                                   const pk: PAnsiChar;
                                   const sk: PAnsiChar): Integer cdecl;

  Tcrypto_box_detached = function(const c: PAnsiChar;
                                  const mac: PAnsiChar;
                                  const m: PAnsiChar;
                                  mlen: UINT64;
                                  const n: PAnsiChar;
                                  const pk: PAnsiChar;
                                  const sk: PAnsiChar): Integer cdecl;

  Tcrypto_box_open_detached = function(const m: PAnsiChar;
                                       const c: PAnsiChar;
                                       const mac: PAnsiChar;
                                       clen: UINT64;
                                       const n: PAnsiChar;
                                       const pk: PAnsiChar;
                                       const sk: PAnsiChar): Integer cdecl;

  //  -- Precomputation interface -- }

  Tcrypto_box_beforenmbytes = function: dwSIZE_T cdecl;

  Tcrypto_box_beforenm = function(const k: PAnsiChar;
                                  const pk: PAnsiChar;
                                  const sk: PAnsiChar): Integer cdecl;

  Tcrypto_box_easy_afternm = function(const c: PAnsiChar;
                                      const m: PAnsiChar;
                                      mlen: UINT64;
                                      const n: PAnsiChar;
                                      const k: PAnsiChar): Integer cdecl;

  Tcrypto_box_open_easy_afternm = function(const m: PAnsiChar;
                                           const c: PAnsiChar;
                                           clen: UINT64;
                                           const n: PAnsiChar;
                                           const k: PAnsiChar): Integer cdecl;

  Tcrypto_box_detached_afternm = function(const c: PAnsiChar;
                                          const mac: PAnsiChar;
                                          const m: PAnsiChar;
                                          mlen: UINT64;
                                          const n: PAnsiChar;
                                          const k: PAnsiChar): Integer cdecl;

  Tcrypto_box_open_detached_afternm = function(const m: PAnsiChar;
                                               const c: PAnsiChar;
                                               const mac: PAnsiChar;
                                               clen: UINT64;
                                               const n: PAnsiChar;
                                               const k: PAnsiChar): Integer cdecl;

  //  -- Ephemeral SK interface -- }

  Tcrypto_box_sealbytes = function: dwSIZE_T cdecl;

  Tcrypto_box_seal = function(const c: PAnsiChar;
                              const m: PAnsiChar;
                              mlen: UINT64;
                              const pk: PAnsiChar): Integer cdecl;

  Tcrypto_box_seal_open = function(const m: PAnsiChar;
                                   const c: PAnsiChar;
                                   clen: UINT64;
                                   const pk: PAnsiChar;
                                   const sk: PAnsiChar): Integer cdecl;

  //  -- NaCl compatibility interface ; Requires padding -- }

  Tcrypto_box_zerobytes = function: dwSIZE_T cdecl;

  Tcrypto_box_boxzerobytes = function: dwSIZE_T cdecl;

  Tcrypto_box = function(const c: PAnsiChar;
                         const m: PAnsiChar;
                         mlen: UINT64;
                         const n: PAnsiChar;
                         const pk: PAnsiChar;
                         const sk: PAnsiChar): Integer cdecl;

  Tcrypto_box_open = function(const m: PAnsiChar;
                              const c: PAnsiChar;
                              clen: UINT64;
                              const n: PAnsiChar;
                              const pk: PAnsiChar;
                              const sk: PAnsiChar): Integer cdecl;

  Tcrypto_box_afternm = function(const c: PAnsiChar;
                                 const m: PAnsiChar;
                                 mlen: UINT64;
                                 const n: PAnsiChar;
                                 const k: PAnsiChar): Integer cdecl;

  Tcrypto_box_open_afternm = function(const m: PAnsiChar;
                                      const c: PAnsiChar;
                                      clen: UINT64;
                                      const n: PAnsiChar;
                                      const k: PAnsiChar): Integer cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305_seedbytes = function: dwSIZE_T cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305_publickeybytes = function: dwSIZE_T cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305_secretkeybytes = function: dwSIZE_T cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305_beforenmbytes = function: dwSIZE_T cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305_noncebytes = function: dwSIZE_T cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305_zerobytes = function: dwSIZE_T cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305_boxzerobytes = function: dwSIZE_T cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305_macbytes = function: dwSIZE_T cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305 = function(const c: PAnsiChar;
                                                    const m: PAnsiChar;
                                                    mlen: UINT64;
                                                    const n: PAnsiChar;
                                                    const pk: PAnsiChar;
                                                    const sk: PAnsiChar): Integer cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305_open = function(const m: PAnsiChar;
                                                         const c: PAnsiChar;
                                                         clen: UINT64;
                                                         const n: PAnsiChar;
                                                         const pk: PAnsiChar;
                                                         const sk: PAnsiChar): Integer cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305_seed_keypair = function(var pk: Byte;
                                                               var sk: Byte;
                                                               const seed: PAnsiChar): Integer cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305_keypair = function(const pk: PAnsiChar;
                                                            const sk: PAnsiChar): Integer cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305_beforenm = function(const k: PAnsiChar;
                                                             const pk: PAnsiChar;
                                                             const sk: PAnsiChar): Integer cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305_afternm = function(const c: PAnsiChar;
                                                            const m: PAnsiChar;
                                                            mlen: UINT64;
                                                            const n: PAnsiChar;
                                                            const k: PAnsiChar): Integer cdecl;

  Tcrypto_box_curve25519xsalsa20poly1305_open_afternm = function(const m: PAnsiChar;
                                                                 const c: PAnsiChar;
                                                                 clen: UINT64;
                                                                 const n: PAnsiChar;
                                                                 const k: PAnsiChar): Integer cdecl;

  Tcrypto_core_hsalsa20_outputbytes = function: dwSIZE_T cdecl;

  Tcrypto_core_hsalsa20_inputbytes = function: dwSIZE_T cdecl;

  Tcrypto_core_hsalsa20_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_core_hsalsa20_constbytes = function: dwSIZE_T cdecl;

  Tcrypto_core_hsalsa20 = function(const outBuf: PAnsiChar;
                                   const inBuf: PAnsiChar;
                                   const k: PAnsiChar;
                                   const c: PAnsiChar): Integer cdecl;

  Tcrypto_core_salsa20_outputbytes = function: dwSIZE_T cdecl;

  Tcrypto_core_salsa20_inputbytes = function: dwSIZE_T cdecl;

  Tcrypto_core_salsa20_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_core_salsa20_constbytes = function: dwSIZE_T cdecl;

  Tcrypto_core_salsa20 = function(const outBuf: PAnsiChar;
                                  const inBuf: PAnsiChar;
                                  const k: PAnsiChar;
                                  const c: PAnsiChar): Integer cdecl;

  Tcrypto_core_salsa2012_outputbytes = function: dwSIZE_T cdecl;

  Tcrypto_core_salsa2012_inputbytes = function: dwSIZE_T cdecl;

  Tcrypto_core_salsa2012_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_core_salsa2012_constbytes = function: dwSIZE_T cdecl;

  Tcrypto_core_salsa2012 = function(const outBuf: PAnsiChar;
                                    const inBuf: PAnsiChar;
                                    const k: PAnsiChar;
                                    const c: PAnsiChar): Integer cdecl;

  Tcrypto_core_salsa208_outputbytes = function: dwSIZE_T cdecl;

  Tcrypto_core_salsa208_inputbytes = function: dwSIZE_T cdecl;

  Tcrypto_core_salsa208_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_core_salsa208_constbytes = function: dwSIZE_T cdecl;

  Tcrypto_core_salsa208 = function(const outBuf: PAnsiChar;
                                   const inBuf: PAnsiChar;
                                   const k: PAnsiChar;
                                   const c: PAnsiChar): Integer cdecl;

  Tcrypto_generichash_bytes_min = function: dwSIZE_T cdecl;

  Tcrypto_generichash_bytes_max = function: dwSIZE_T cdecl;

  Tcrypto_generichash_bytes = function: dwSIZE_T cdecl;

  Tcrypto_generichash_keybytes_min = function: dwSIZE_T cdecl;

  Tcrypto_generichash_keybytes_max = function: dwSIZE_T cdecl;

  Tcrypto_generichash_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_generichash_primitive = function: PAnsiChar cdecl;

  Tcrypto_generichash_statebytes = function: dwSIZE_T cdecl;

  Tcrypto_generichash = function(const outBuf: PAnsiChar;
                                 outlen: dwSIZE_T;
                                 const inBuf: PAnsiChar;
                                 inlen: UINT64;
                                 const key: PAnsiChar;
                                 keylen: dwSIZE_T): Integer cdecl;

  Tcrypto_generichash_init = function(var state: CRYPTO_GENERICHASH_STATE;
                                      const key: PAnsiChar;
                                      const keylen: dwSIZE_T;
                                      const outlen: dwSIZE_T): Integer cdecl;

  Tcrypto_generichash_update = function(var state: CRYPTO_GENERICHASH_STATE;
                                        const inBuf: PAnsiChar;
                                        inlen: UINT64): Integer cdecl;

  Tcrypto_generichash_final = function(var state: CRYPTO_GENERICHASH_STATE;
                                       const outBuf: PAnsiChar;
                                       const outlen: dwSIZE_T): Integer cdecl;

  Tcrypto_generichash_blake2b_bytes_min = function: dwSIZE_T cdecl;

  Tcrypto_generichash_blake2b_bytes_max = function: dwSIZE_T cdecl;

  Tcrypto_generichash_blake2b_bytes = function: dwSIZE_T cdecl;

  Tcrypto_generichash_blake2b_keybytes_min = function: dwSIZE_T cdecl;

  Tcrypto_generichash_blake2b_keybytes_max = function: dwSIZE_T cdecl;

  Tcrypto_generichash_blake2b_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_generichash_blake2b_saltbytes = function: dwSIZE_T cdecl;

  Tcrypto_generichash_blake2b_personalbytes = function: dwSIZE_T cdecl;

  Tcrypto_generichash_blake2b = function(const outBuf: PAnsiChar;
                                         outlen: dwSIZE_T;
                                         const inBuf: PAnsiChar;
                                         inlen: UINT64;
                                         const key: PAnsiChar;
                                         keylen: dwSIZE_T): Integer cdecl;

  Tcrypto_generichash_blake2b_salt_personal = function(const outBuf: PAnsiChar;
                                                       outlen: dwSIZE_T;
                                                       const inBuf: PAnsiChar;
                                                       inlen: UINT64;
                                                       const key: PAnsiChar;
                                                       keylen: dwSIZE_T;
                                                       const salt: PAnsiChar;
                                                       const personal: PAnsiChar): Integer cdecl;

  Tcrypto_generichash_blake2b_init = function(var state: CRYPTO_GENERICHASH_BLAKE2B_STATE;
                                              const key: PAnsiChar;
                                              const keylen: dwSIZE_T;
                                              const outlen: dwSIZE_T): Integer cdecl;

  Tcrypto_generichash_blake2b_init_salt_personal = function(var state: CRYPTO_GENERICHASH_BLAKE2B_STATE;
                                                            const key: PAnsiChar;
                                                            const keylen: dwSIZE_T;
                                                            const outlen: dwSIZE_T;
                                                            const salt: PAnsiChar;
                                                            const personal: PAnsiChar): Integer cdecl;

  Tcrypto_generichash_blake2b_update = function(var state: CRYPTO_GENERICHASH_BLAKE2B_STATE;
                                                const inBuf: PAnsiChar;
                                                inlen: UINT64): Integer cdecl;

  Tcrypto_generichash_blake2b_final = function(var state: CRYPTO_GENERICHASH_BLAKE2B_STATE;
                                               const outBuf: PAnsiChar;
                                               const outlen: dwSIZE_T): Integer cdecl;

  // * WARNING: Unless you absolutely need to use SHA512 for interoperatibility, }
  // * purposes, you might want to consider crypto_generichash() instead. }
  // * Unlike SHA512, crypto_generichash() is not vulnerable to length }
  // * extension attacks. }

  Tcrypto_hash_bytes = function: dwSIZE_T cdecl;

  Tcrypto_hash = function(const outBuf: PAnsiChar;
                          const inBuf: PAnsiChar;
                          inlen: UINT64): Integer cdecl;

  Tcrypto_hash_primitive = function: PAnsiChar cdecl;

  // * WARNING: Unless you absolutely need to use SHA256 for interoperatibility, }
  // * purposes, you might want to consider crypto_generichash() instead. }
  // * Unlike SHA256, crypto_generichash() is not vulnerable to length }
  // * extension attacks. }

  Tcrypto_hash_sha256_statebytes = function: dwSIZE_T cdecl;

  Tcrypto_hash_sha256_bytes = function: dwSIZE_T cdecl;

  Tcrypto_hash_sha256 = function(const outBuf: PAnsiChar;
                                 const inBuf: PAnsiChar;
                                 inlen: UINT64): Integer cdecl;

  Tcrypto_hash_sha256_init = function(var state: CRYPTO_HASH_SHA256_STATE): Integer cdecl;

  Tcrypto_hash_sha256_update = function(var state: CRYPTO_HASH_SHA256_STATE;
                                        const inBuf: PAnsiChar;
                                        inlen: UINT64): Integer cdecl;

  Tcrypto_hash_sha256_final = function(var state: CRYPTO_HASH_SHA256_STATE;
                                       const outBuf: PAnsiChar): Integer cdecl;

  // * WARNING: Unless you absolutely need to use SHA512 for interoperatibility, }
  // * purposes, you might want to consider crypto_generichash() instead. }
  // * Unlike SHA512, crypto_generichash() is not vulnerable to length }
  // * extension attacks. }

  Tcrypto_hash_sha512_statebytes = function: dwSIZE_T cdecl;

  Tcrypto_hash_sha512_bytes = function: dwSIZE_T cdecl;

  Tcrypto_hash_sha512 = function(const outBuf: PAnsiChar;
                                 const inBuf: PAnsiChar;
                                 inlen: UINT64): Integer cdecl;

  Tcrypto_hash_sha512_init = function(var state: CRYPTO_HASH_SHA512_STATE): Integer cdecl;

  Tcrypto_hash_sha512_update = function(var state: CRYPTO_HASH_SHA512_STATE;
                                        const inBuf: PAnsiChar;
                                        inlen: UINT64): Integer cdecl;

  Tcrypto_hash_sha512_final = function(var state: CRYPTO_HASH_SHA512_STATE;
                                       const outBuf: PAnsiChar): Integer cdecl;

  Tcrypto_onetimeauth_statebytes = function: dwSIZE_T cdecl;

  Tcrypto_onetimeauth_bytes = function: dwSIZE_T cdecl;

  Tcrypto_onetimeauth_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_onetimeauth_primitive = function: PAnsiChar cdecl;

  Tcrypto_onetimeauth = function(const outBuf: PAnsiChar;
                                 const inBuf: PAnsiChar;
                                 inlen: UINT64;
                                 const k: PAnsiChar): Integer cdecl;

  Tcrypto_onetimeauth_verify = function(const h: PAnsiChar;
                                        const inBuf: PAnsiChar;
                                        inlen: UINT64;
                                        const k: PAnsiChar): Integer cdecl;

  Tcrypto_onetimeauth_init = function(var state: CRYPTO_ONETIMEAUTH_STATE;
                                      const key: PAnsiChar): Integer cdecl;

  Tcrypto_onetimeauth_update = function(var state: CRYPTO_ONETIMEAUTH_STATE;
                                        const inBuf: PAnsiChar;
                                        inlen: UINT64): Integer cdecl;

  Tcrypto_onetimeauth_final = function(var state: CRYPTO_ONETIMEAUTH_STATE;
                                       const outBuf: PAnsiChar): Integer cdecl;

  Tcrypto_onetimeauth_poly1305_bytes = function: dwSIZE_T cdecl;

  Tcrypto_onetimeauth_poly1305_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_onetimeauth_poly1305_implementation_name = function: PAnsiChar cdecl;

  Tcrypto_onetimeauth_poly1305 = function(const outBuf: PAnsiChar;
                                          const inBuf: PAnsiChar;
                                          inlen: UINT64;
                                          const k: PAnsiChar): Integer cdecl;

  Tcrypto_onetimeauth_poly1305_verify = function(const h: PAnsiChar;
                                                 const inBuf: PAnsiChar;
                                                 inlen: UINT64;
                                                 const k: PAnsiChar): Integer cdecl;

  Tcrypto_onetimeauth_poly1305_init = function(var state: CRYPTO_ONETIMEAUTH_POLY1305_STATE;
                                               const key: PAnsiChar): Integer cdecl;

  Tcrypto_onetimeauth_poly1305_update = function(var state: CRYPTO_ONETIMEAUTH_POLY1305_STATE;
                                                 const inBuf: PAnsiChar;
                                                 inlen: UINT64): Integer cdecl;

  Tcrypto_onetimeauth_poly1305_final = function(var state: CRYPTO_ONETIMEAUTH_POLY1305_STATE;
                                                const outBuf: PAnsiChar): Integer cdecl;

  crypto_onetimeauth_poly1305_implementation = packed record
    implementation_name: Tcrypto_onetimeauth_poly1305_implementation_name;
    onetimeauth: Tcrypto_onetimeauth;
    onetimeauth_verify: Tcrypto_onetimeauth_verify;
    onetimeauth_init: Tcrypto_onetimeauth_init;
    onetimeauth_update: Tcrypto_onetimeauth_update;
    onetimeauth_final: Tcrypto_onetimeauth_final;
  end {crypto_onetimeauth_poly1305_implementation};


  Tcrypto_onetimeauth_poly1305_set_implementation = function(var impl: CRYPTO_ONETIMEAUTH_POLY1305_IMPLEMENTATION): Integer cdecl;

  Tcrypto_onetimeauth_pick_best_implementation = function: CRYPTO_ONETIMEAUTH_POLY1305_IMPLEMENTATION cdecl;

  Tcrypto_pwhash_scryptsalsa208sha256_saltbytes = function: dwSIZE_T cdecl;

  Tcrypto_pwhash_scryptsalsa208sha256_strbytes = function: dwSIZE_T cdecl;

  Tcrypto_pwhash_scryptsalsa208sha256_strprefix = function: PAnsiChar cdecl;

  Tcrypto_pwhash_scryptsalsa208sha256_opslimit_interactive = function: dwSIZE_T cdecl;

  Tcrypto_pwhash_scryptsalsa208sha256_memlimit_interactive = function: dwSIZE_T cdecl;

  Tcrypto_pwhash_scryptsalsa208sha256_opslimit_sensitive = function: dwSIZE_T cdecl;

  Tcrypto_pwhash_scryptsalsa208sha256_memlimit_sensitive = function: dwSIZE_T cdecl;

  Tcrypto_pwhash_scryptsalsa208sha256 = function(const outBuf: PAnsiChar;
                                                 outlen: UINT64;
                                                 const passwd: PAnsiChar;
                                                 passwdlen: UINT64;
                                                 const salt: PAnsiChar;
                                                 opslimit: UINT64;
                                                 memlimit: dwSIZE_T): Integer cdecl;

  Tcrypto_pwhash_scryptsalsa208sha256_str = function(outBuf: PAnsiChar{ls_crypto_pwhash_scryptsalsa208sha256_STRBYTES};
                                                   const passwd: PAnsiChar;
                                                   passwdlen: UINT64;
                                                   opslimit: UINT64;
                                                   memlimit: UINT64): Integer cdecl;

  Tcrypto_pwhash_scryptsalsa208sha256_str_verify = function(const str: PAnsiChar{ls_crypto_pwhash_scryptsalsa208sha256_STRBYTES};
                                                            const passwd: PAnsiChar;
                                                            passwdlen: UINT64): Integer cdecl;

  Tcrypto_pwhash_scryptsalsa208sha256_ll = function(const passwd: PUINT8;
                                                    passwdlen: dwSIZE_T;
                                                    const salt: PUINT8;
                                                    saltlen: dwSIZE_T;
                                                    N: UINT64;
                                                    r: UINT32;
                                                    p: UINT32;
                                                    var buf: UINT8;
                                                    buflen: dwSIZE_T): Integer cdecl;

  Tcrypto_scalarmult_bytes = function: dwSIZE_T cdecl;

  Tcrypto_scalarmult_scalarbytes = function: dwSIZE_T cdecl;

  Tcrypto_scalarmult_primitive = function: PAnsiChar cdecl;

  Tcrypto_scalarmult_base = function(const q: PAnsiChar;
                                     const n: PAnsiChar): Integer cdecl;

  Tcrypto_scalarmult = function(const q: PAnsiChar;
                                const n: PAnsiChar;
                                const p: PAnsiChar): Integer cdecl;

  Tcrypto_scalarmult_curve25519_bytes = function: dwSIZE_T cdecl;

  Tcrypto_scalarmult_curve25519_scalarbytes = function: dwSIZE_T cdecl;

  Tcrypto_scalarmult_curve25519 = function(const q: PAnsiChar;
                                           const n: PAnsiChar;
                                           const p: PAnsiChar): Integer cdecl;

  Tcrypto_scalarmult_curve25519_base = function(const q: PAnsiChar;
                                                const n: PAnsiChar): Integer cdecl;

  Tcrypto_secretbox_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_secretbox_noncebytes = function: dwSIZE_T cdecl;

  Tcrypto_secretbox_macbytes = function: dwSIZE_T cdecl;

  Tcrypto_secretbox_primitive = function: PAnsiChar cdecl;

  Tcrypto_secretbox_easy = function(const c: PAnsiChar;
                                    const m: PAnsiChar;
                                    mlen: UINT64;
                                    const n: PAnsiChar;
                                    const k: PAnsiChar): Integer cdecl;

  Tcrypto_secretbox_open_easy = function(const m: PAnsiChar;
                                         const c: PAnsiChar;
                                         clen: UINT64;
                                         const n: PAnsiChar;
                                         const k: PAnsiChar): Integer cdecl;

  Tcrypto_secretbox_detached = function(const c: PAnsiChar;
                                        const mac: PAnsiChar;
                                        const m: PAnsiChar;
                                        mlen: UINT64;
                                        const n: PAnsiChar;
                                        const k: PAnsiChar): Integer cdecl;

  Tcrypto_secretbox_open_detached = function(const m: PAnsiChar;
                                             const c: PAnsiChar;
                                             const mac: PAnsiChar;
                                             clen: UINT64;
                                             const n: PAnsiChar;
                                             const k: PAnsiChar): Integer cdecl;

  //  -- NaCl compatibility interface ; Requires padding -- }

  Tcrypto_secretbox_zerobytes = function: dwSIZE_T cdecl;

  Tcrypto_secretbox_boxzerobytes = function: dwSIZE_T cdecl;

  Tcrypto_secretbox = function(const c: PAnsiChar;
                               const m: PAnsiChar;
                               mlen: UINT64;
                               const n: PAnsiChar;
                               const k: PAnsiChar): Integer cdecl;

  Tcrypto_secretbox_open = function(const m: PAnsiChar;
                                    const c: PAnsiChar;
                                    clen: UINT64;
                                    const n: PAnsiChar;
                                    const k: PAnsiChar): Integer cdecl;

  Tcrypto_secretbox_xsalsa20poly1305_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_secretbox_xsalsa20poly1305_noncebytes = function: dwSIZE_T cdecl;

  Tcrypto_secretbox_xsalsa20poly1305_zerobytes = function: dwSIZE_T cdecl;

  Tcrypto_secretbox_xsalsa20poly1305_boxzerobytes = function: dwSIZE_T cdecl;

  Tcrypto_secretbox_xsalsa20poly1305_macbytes = function: dwSIZE_T cdecl;

  Tcrypto_secretbox_xsalsa20poly1305 = function(const c: PAnsiChar;
                                                const m: PAnsiChar;
                                                mlen: UINT64;
                                                const n: PAnsiChar;
                                                const k: PAnsiChar): Integer cdecl;

  Tcrypto_secretbox_xsalsa20poly1305_open = function(const m: PAnsiChar;
                                                     const c: PAnsiChar;
                                                     clen: UINT64;
                                                     const n: PAnsiChar;
                                                     const k: PAnsiChar): Integer cdecl;

  Tcrypto_shorthash_bytes = function: dwSIZE_T cdecl;

  Tcrypto_shorthash_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_shorthash_primitive = function: PAnsiChar cdecl;

  Tcrypto_shorthash = function(const outBuf: PAnsiChar;
                               const inBuf: PAnsiChar;
                               inlen: UINT64;
                               const k: PAnsiChar): Integer cdecl;

  Tcrypto_shorthash_siphash24_bytes = function: dwSIZE_T cdecl;

  Tcrypto_shorthash_siphash24_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_shorthash_siphash24 = function(const outBuf: PAnsiChar;
                                         const inBuf: PAnsiChar;
                                         inlen: UINT64;
                                         const k: PAnsiChar): Integer cdecl;

  // * THREAD SAFETY: crypto_sign_keypair() is thread-safe, }
  // * provided that you called sodium_init() once before using any }
  // * other libsodium function. }
  // * Other functions, including crypto_sign_seed_keypair() are always thread-safe. }

  Tcrypto_sign_bytes = function: dwSIZE_T cdecl;

  Tcrypto_sign_seedbytes = function: dwSIZE_T cdecl;

  Tcrypto_sign_publickeybytes = function: dwSIZE_T cdecl;

  Tcrypto_sign_secretkeybytes = function: dwSIZE_T cdecl;

  Tcrypto_sign_primitive = function: PAnsiChar cdecl;

  Tcrypto_sign_seed_keypair = function(const pk: PAnsiChar;
                                       const sk: PAnsiChar;
                                       const seed: PAnsiChar): Integer cdecl;

  Tcrypto_sign_keypair = function(const pk: PAnsiChar;
                                  const sk: PAnsiChar): Integer cdecl;

  Tcrypto_sign = function(const sm: PAnsiChar;
                          var smlen_p: UINT64;
                          const m: PAnsiChar;
                          mlen: UINT64;
                          const sk: PAnsiChar): Integer cdecl;

  Tcrypto_sign_open = function(const m: PAnsiChar;
                               var mlen_p: UINT64;
                               const sm: PAnsiChar;
                               smlen: UINT64;
                               const pk: PAnsiChar): Integer cdecl;

  Tcrypto_sign_detached = function(const sig: PAnsiChar;
                                   var siglen_p: UINT64;
                                   const m: PAnsiChar;
                                   mlen: UINT64;
                                   const sk: PAnsiChar): Integer cdecl;

  Tcrypto_sign_verify_detached = function(const sig: PAnsiChar;
                                          const m: PAnsiChar;
                                          mlen: UINT64;
                                          const pk: PAnsiChar): Integer cdecl;

  Tcrypto_sign_ed25519_bytes = function: dwSIZE_T cdecl;

  Tcrypto_sign_ed25519_seedbytes = function: dwSIZE_T cdecl;

  Tcrypto_sign_ed25519_publickeybytes = function: dwSIZE_T cdecl;

  Tcrypto_sign_ed25519_secretkeybytes = function: dwSIZE_T cdecl;

  Tcrypto_sign_ed25519 = function(const sm: PAnsiChar;
                                  var smlen_p: UINT64;
                                  const m: PAnsiChar;
                                  mlen: UINT64;
                                  const sk: PAnsiChar): Integer cdecl;

  Tcrypto_sign_ed25519_open = function(const m: PAnsiChar;
                                       var mlen_p: UINT64;
                                       const sm: PAnsiChar;
                                       smlen: UINT64;
                                       const pk: PAnsiChar): Integer cdecl;

  Tcrypto_sign_ed25519_detached = function(const sig: PAnsiChar;
                                           var siglen_p: UINT64;
                                           const m: PAnsiChar;
                                           mlen: UINT64;
                                           const sk: PAnsiChar): Integer cdecl;

  Tcrypto_sign_ed25519_verify_detached = function(const sig: PAnsiChar;
                                                  const m: PAnsiChar;
                                                  mlen: UINT64;
                                                  const pk: PAnsiChar): Integer cdecl;

  Tcrypto_sign_ed25519_keypair = function(const pk: PAnsiChar;
                                          const sk: PAnsiChar): Integer cdecl;

  Tcrypto_sign_ed25519_seed_keypair = function(const pk: PAnsiChar;
                                               const sk: PAnsiChar;
                                               const seed: PAnsiChar): Integer cdecl;

  Tcrypto_sign_ed25519_pk_to_curve25519 = function(const curve25519_pk: PAnsiChar;
                                                   const ed25519_pk: PAnsiChar): Integer cdecl;

  Tcrypto_sign_ed25519_sk_to_curve25519 = function(const curve25519_sk: PAnsiChar;
                                                   const ed25519_sk: PAnsiChar): Integer cdecl;

  Tcrypto_sign_ed25519_sk_to_seed = function(const seed: PAnsiChar;
                                             const sk: PAnsiChar): Integer cdecl;

  Tcrypto_sign_ed25519_sk_to_pk = function(const pk: PAnsiChar;
                                           const sk: PAnsiChar): Integer cdecl;

  // * WARNING: This construction was a prototype, which should not be used }
  // * any more in new projects. }
  // * }
  // * crypto_sign_edwards25519sha512batch is provided for applications }
  // * initially built with NaCl, but as recommended by the author of this }
  // * construction, new applications should use ed25519 instead. }
  // * }
  // * In Sodium, you should use the high-level crypto_sign_*() functions instead. }

  Tcrypto_sign_edwards25519sha512batch_bytes = function: dwSIZE_T cdecl;

  Tcrypto_sign_edwards25519sha512batch_publickeybytes = function: dwSIZE_T cdecl;

  Tcrypto_sign_edwards25519sha512batch_secretkeybytes = function: dwSIZE_T cdecl;

  Tcrypto_sign_edwards25519sha512batch = function(const sm: PAnsiChar;
                                                  var smlen_p: UINT64;
                                                  const m: PAnsiChar;
                                                  mlen: UINT64;
                                                  const sk: PAnsiChar): Integer cdecl;

  Tcrypto_sign_edwards25519sha512batch_open = function(const m: PAnsiChar;
                                                       var mlen_p: UINT64;
                                                       const sm: PAnsiChar;
                                                       smlen: UINT64;
                                                       const pk: PAnsiChar): Integer cdecl;

  Tcrypto_sign_edwards25519sha512batch_keypair = function(const pk: PAnsiChar;
                                                          const sk: PAnsiChar): Integer cdecl;


  // * WARNING: This is just a stream cipher. It is NOT authenticated encryption. }
  // * While it provides some protection against eavesdropping, it does NOT }
  // * provide any security against active attacks. }
  // * Unless you know what you're doing, what you are looking for is probably }
  // * the crypto_box functions. }

  Tcrypto_stream_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_noncebytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_primitive = function: PAnsiChar cdecl;

  Tcrypto_stream = function(const c: PAnsiChar;
                            clen: UINT64;
                            const n: PAnsiChar;
                            const k: PAnsiChar): Integer cdecl;

  Tcrypto_stream_xor = function(const c: PAnsiChar;
                                const m: PAnsiChar;
                                mlen: UINT64;
                                const n: PAnsiChar;
                                const k: PAnsiChar): Integer cdecl;

  // * WARNING: This is just a stream cipher. It is NOT authenticated encryption. }
  // * While it provides some protection against eavesdropping, it does NOT }
  // * provide any security against active attacks. }
  // * Unless you know what you're doing, what you are looking for is probably }
  // * the crypto_box functions. }

  Tcrypto_stream_aes128ctr_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_aes128ctr_noncebytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_aes128ctr_beforenmbytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_aes128ctr = function(const outBuf: PAnsiChar;
                                      outlen: UINT64;
                                      const n: PAnsiChar;
                                      const k: PAnsiChar): Integer cdecl;

  Tcrypto_stream_aes128ctr_xor = function(const outBuf: PAnsiChar;
                                          const inBuf: PAnsiChar;
                                          inlen: UINT64;
                                          const n: PAnsiChar;
                                          const k: PAnsiChar): Integer cdecl;

  Tcrypto_stream_aes128ctr_beforenm = function(const c: PAnsiChar;
                                               const k: PAnsiChar): Integer cdecl;

  Tcrypto_stream_aes128ctr_afternm = function(const outBuf: PAnsiChar;
                                              len: UINT64;
                                              const nonce: PAnsiChar;
                                              const c: PAnsiChar): Integer cdecl;

  Tcrypto_stream_aes128ctr_xor_afternm = function(const outBuf: PAnsiChar;
                                                  const inBuf: PAnsiChar;
                                                  len: UINT64;
                                                  const nonce: PAnsiChar;
                                                  const c: PAnsiChar): Integer cdecl;

  // * WARNING: This is just a stream cipher. It is NOT authenticated encryption. }
  // * While it provides some protection against eavesdropping, it does NOT }
  // * provide any security against active attacks. }
  // * Unless you know what you're doing, what you are looking for is probably }
  // * the crypto_box functions. }

  Tcrypto_stream_chacha20_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_chacha20_noncebytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_chacha20 = function(const c: PAnsiChar;
                                     clen: UINT64;
                                     const n: PAnsiChar;
                                     const k: PAnsiChar): Integer cdecl;

  Tcrypto_stream_chacha20_xor = function(const c: PAnsiChar;
                                         const m: PAnsiChar;
                                         mlen: UINT64;
                                         const n: PAnsiChar;
                                         const k: PAnsiChar): Integer cdecl;

  Tcrypto_stream_chacha20_xor_ic = function(const c: PAnsiChar;
                                            const m: PAnsiChar;
                                            mlen: UINT64;
                                            const n: PAnsiChar;
                                            ic: UINT64;
                                            const k: PAnsiChar): Integer cdecl;

  // * WARNING: This is just a stream cipher. It is NOT authenticated encryption. }
  // * While it provides some protection against eavesdropping, it does NOT }
  // * provide any security against active attacks. }
  // * Unless you know what you're doing, what you are looking for is probably }
  // * the crypto_box functions. }

  Tcrypto_stream_salsa20_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_salsa20_noncebytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_salsa20 = function(const c: PAnsiChar;
                                    clen: UINT64;
                                    const n: PAnsiChar;
                                    const k: PAnsiChar): Integer cdecl;

  Tcrypto_stream_salsa20_xor = function(const c: PAnsiChar;
                                        const m: PAnsiChar;
                                        mlen: UINT64;
                                        const n: PAnsiChar;
                                        const k: PAnsiChar): Integer cdecl;

  Tcrypto_stream_salsa20_xor_ic = function(const c: PAnsiChar;
                                           const m: PAnsiChar;
                                           mlen: UINT64;
                                           const n: PAnsiChar;
                                           ic: UINT64;
                                           const k: PAnsiChar): Integer cdecl;

  // * WARNING: This is just a stream cipher. It is NOT authenticated encryption. }
  // * While it provides some protection against eavesdropping, it does NOT }
  // * provide any security against active attacks. }
  // * Unless you know what you're doing, what you are looking for is probably }
  // * the crypto_box functions. }

  Tcrypto_stream_salsa2012_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_salsa2012_noncebytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_salsa2012 = function(const c: PAnsiChar;
                                      clen: UINT64;
                                      const n: PAnsiChar;
                                      const k: PAnsiChar): Integer cdecl;

  Tcrypto_stream_salsa2012_xor = function(const c: PAnsiChar;
                                          const m: PAnsiChar;
                                          mlen: UINT64;
                                          const n: PAnsiChar;
                                          const k: PAnsiChar): Integer cdecl;

  // * WARNING: This is just a stream cipher. It is NOT authenticated encryption. }
  // * While it provides some protection against eavesdropping, it does NOT }
  // * provide any security against active attacks. }
  // * Unless you know what you're doing, what you are looking for is probably }
  // * the crypto_box functions. }

  Tcrypto_stream_salsa208_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_salsa208_noncebytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_salsa208 = function(const c: PAnsiChar;
                                     clen: UINT64;
                                     const n: PAnsiChar;
                                     const k: PAnsiChar): Integer cdecl;

  Tcrypto_stream_salsa208_xor = function(const c: PAnsiChar;
                                         const m: PAnsiChar;
                                         mlen: UINT64;
                                         const n: PAnsiChar;
                                         const k: PAnsiChar): Integer cdecl;

  // * WARNING: This is just a stream cipher. It is NOT authenticated encryption. }
  // * While it provides some protection against eavesdropping, it does NOT }
  // * provide any security against active attacks. }
  // * Unless you know what you're doing, what you are looking for is probably }
  // * the crypto_box functions. }

  Tcrypto_stream_xsalsa20_keybytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_xsalsa20_noncebytes = function: dwSIZE_T cdecl;

  Tcrypto_stream_xsalsa20 = function(const c: PAnsiChar;
                                     clen: UINT64;
                                     const n: PAnsiChar;
                                     const k: PAnsiChar): Integer cdecl;

  Tcrypto_stream_xsalsa20_xor = function(const c: PAnsiChar;
                                         const m: PAnsiChar;
                                         mlen: UINT64;
                                         const n: PAnsiChar;
                                         const k: PAnsiChar): Integer cdecl;

  Tcrypto_stream_xsalsa20_xor_ic = function(const c: PAnsiChar;
                                            const m: PAnsiChar;
                                            mlen: UINT64;
                                            const n: PAnsiChar;
                                            ic: UINT64;
                                            const k: PAnsiChar): Integer cdecl;

  Tcrypto_verify_16_bytes = function: dwSIZE_T cdecl;

  Tcrypto_verify_16 = function(const x: PAnsiChar;
                               const y: PAnsiChar): Integer cdecl;

  Tcrypto_verify_32_bytes = function: dwSIZE_T cdecl;

  Tcrypto_verify_32 = function(const x: PAnsiChar;
                               const y: PAnsiChar): Integer cdecl;

  Tcrypto_verify_64_bytes = function: dwSIZE_T cdecl;

  Tcrypto_verify_64 = function(const x: PAnsiChar;
                               const y: PAnsiChar): Integer cdecl;

  Trandombytes_buf = procedure(const buf: Pointer;
                               const size: dwSIZE_T) cdecl;

  Trandombytes_random = function: UINT32 cdecl;

  Trandombytes_uniform = function(const upper_bound: UINT32): UINT32 cdecl;

  Trandombytes_stir = procedure cdecl;

  Trandombytes_close = function: Integer cdecl;

  Trandombytes_implementation_name = function: PAnsiChar cdecl;

  randombytes_implementation = packed record
    implementation_name: Trandombytes_implementation_name;
    random: Trandombytes_random;
    stir: Trandombytes_stir;
    uniform: Trandombytes_uniform;
    buf: Trandombytes_buf;
    close: Trandombytes_close;
  end {randombytes_implementation};

  Trandombytes_set_implementation = function(var impl: RANDOMBYTES_IMPLEMENTATION): Integer cdecl;

  //  -- NaCl compatibility interface -- }

  Trandombytes = procedure(const buf: PAnsiChar;
                           const buf_len: UINT64) cdecl;

  // * THREAD SAFETY: randombytes_salsa20_random*() functions are }
  // * fork()-safe but not thread-safe. }
  // * Always wrap them in a mutex if you need thread safety. }

  Trandombytes_salsa20_implementation_name = function: PAnsiChar cdecl;

  Trandombytes_salsa20_random = function: UINT32 cdecl;

  Trandombytes_salsa20_random_stir = procedure cdecl;

  Trandombytes_salsa20_random_uniform = function(const upper_bound: UINT32): UINT32 cdecl;

  Trandombytes_salsa20_random_buf = procedure(const buf: Pointer;
                                                const size: dwSIZE_T) cdecl;

  Trandombytes_salsa20_random_close = function: Integer cdecl;

  // * THREAD SAFETY: randombytes_sysrandom() functions are thread-safe, }
  // * provided that you called sodium_init() once before using any }
  // * other libsodium function. }

  Trandombytes_sysrandom_implementation_name = function: PAnsiChar cdecl;

  Trandombytes_sysrandom = function: UINT32 cdecl;

  Trandombytes_sysrandom_stir = procedure cdecl;

  Trandombytes_sysrandom_uniform = function(const upper_bound: UINT32): UINT32 cdecl;

  Trandombytes_sysrandom_buf = procedure(const buf: Pointer;
                                         const size: dwSIZE_T) cdecl;

  Trandombytes_sysrandom_close = function: Integer cdecl;

  Tsodium_runtime_get_cpu_features = function: Integer cdecl;

  Tsodium_runtime_has_neon = function: Integer cdecl;

  Tsodium_runtime_has_sse2 = function: Integer cdecl;

  Tsodium_runtime_has_sse3 = function: Integer cdecl;

  Tsodium_memzero = procedure(const pnt: Pointer;
                              const len: dwSIZE_T) cdecl;

  // * WARNING: sodium_memcmp() must be used to verify if two secret keys
  // * are equal, in constant time.
  // * It returns 0 if the keys are equal, and -1 if they differ.
  // * This function is not designed for lexicographical comparisons.

  // http://codahale.com/a-lesson-in-timing-attacks/

  Tsodium_memcmp = function(const b1_: PAnsiChar;
                            const b2_: PAnsiChar;
                            len: dwSIZE_T): Integer cdecl;

  Tsodium_bin2hex = function(const hex: PAnsiChar;
                             const hex_maxlen: dwSIZE_T;
                             const bin: PAnsiChar;
                             const bin_len: dwSIZE_T): PAnsiChar cdecl;

  Tsodium_hex2bin = function(const bin: PAnsiChar;
                             const bin_maxlen: dwSIZE_T;
                             const hex: PAnsiChar;
                             const hex_len: dwSIZE_T;
                             const ignore: PAnsiChar;
                             out bin_len: dwSIZE_T;
                             const hex_end: PAnsiChar): Integer cdecl;

  Tsodium_mlock = function(const addr: Pointer;
                           const len: dwSIZE_T): Integer cdecl;

  Tsodium_munlock = function(const addr: Pointer;
                             const len: dwSIZE_T): Integer cdecl;

  // * WARNING: sodium_malloc() and sodium_allocarray() are not general-purpose
  // * allocation functions.
  // *
  // * They return a pointer to a region filled with 0xd0 bytes, immediately
  // * followed by a guard page.
  // * As a result, accessing a single byte after the requested allocation size
  // * will intentionally trigger a segmentation fault.
  // *
  // * A canary and an additional guard page placed before the beginning of the
  // * region may also kill the process if a buffer underflow is detected.
  // *
  // * The memory layout is:
  // * [unprotected region size (read only)][guard page (no access)][unprotected pages (read/write)][guard page (no access)]
  // * With the layout of the unprotected pages being:
  // * [optional padding][16-bytes canary][user region]
  // *
  // * However:
  // * - These functions are significantly slower than standard functions
  // * - Each allocation requires 3 or 4 additional pages
  // * - The returned address will not be aligned if the allocation size is not
  // * a multiple of the required alignment. For this reason, these functions
  // * are designed to store data, such as secret keys and messages.
  // *
  // * sodium_malloc() can be used to allocate any libsodium data structure,
  // * with the exception of crypto_generichash_state.
  // *
  // * The crypto_generichash_state structure is packed and its length is
  // * either 357 or 361 bytes. For this reason, when using sodium_malloc() to
  // * allocate a crypto_generichash_state structure, padding must be added in
  // * order to ensure proper alignment:
  // * state = sodium_malloc((crypto_generichash_statebytes() + (dwSIZE_T) 63U)
  // * & ~(dwSIZE_T) 63U);

  Tsodium_malloc = function(const size: dwSIZE_T): Pointer cdecl;

  Tsodium_allocarray = function(count: dwSIZE_T;
                                size: dwSIZE_T): Pointer cdecl;

  Tsodium_mprotect_noaccess = function(ptr: Pointer): Integer cdecl;

  Tsodium_mprotect_readonly = function(ptr: Pointer): Integer cdecl;

  Tsodium_mprotect_readwrite = function(ptr: Pointer): Integer cdecl;

  T_sodium_alloc_init = function: Integer cdecl;

  Tsodium_version_string = function: PAnsiChar cdecl;

  Tsodium_library_version_major = function: Integer cdecl;

  Tsodium_library_version_minor = function: Integer cdecl;

  Tsodium_init = function: Integer cdecl;

  Tsodium_free = procedure(ptr: Pointer) cdecl;

  //libsodium 1.0.4
  Tsodium_increment = procedure(const bin: PAnsiChar;
                                const bin_len: dwSIZE_T) cdecl;


var
  sodium_init: Tsodium_init;
  crypto_aead_chacha20poly1305_keybytes: Tcrypto_aead_chacha20poly1305_keybytes;
  crypto_aead_chacha20poly1305_nsecbytes: Tcrypto_aead_chacha20poly1305_nsecbytes;
  crypto_aead_chacha20poly1305_npubbytes: Tcrypto_aead_chacha20poly1305_npubbytes;
  crypto_aead_chacha20poly1305_abytes: Tcrypto_aead_chacha20poly1305_abytes;
  crypto_aead_chacha20poly1305_encrypt: Tcrypto_aead_chacha20poly1305_encrypt;
  crypto_aead_chacha20poly1305_decrypt: Tcrypto_aead_chacha20poly1305_decrypt;
  crypto_auth_bytes: Tcrypto_auth_bytes;
  crypto_auth_keybytes: Tcrypto_auth_keybytes;
  crypto_auth_primitive: Tcrypto_auth_primitive;
  crypto_auth: Tcrypto_auth;
  crypto_auth_verify: Tcrypto_auth_verify;
  crypto_auth_hmacsha256_bytes: Tcrypto_auth_hmacsha256_bytes;
  crypto_auth_hmacsha256_keybytes: Tcrypto_auth_hmacsha256_keybytes;
  crypto_auth_hmacsha256: Tcrypto_auth_hmacsha256;
  crypto_auth_hmacsha256_verify: Tcrypto_auth_hmacsha256_verify;
  crypto_auth_hmacsha256_statebytes: Tcrypto_auth_hmacsha256_statebytes;
  crypto_auth_hmacsha256_init: Tcrypto_auth_hmacsha256_init;
  crypto_auth_hmacsha256_update: Tcrypto_auth_hmacsha256_update;
  crypto_auth_hmacsha256_final: Tcrypto_auth_hmacsha256_final;
  crypto_auth_hmacsha512_bytes: Tcrypto_auth_hmacsha512_bytes;
  crypto_auth_hmacsha512_keybytes: Tcrypto_auth_hmacsha512_keybytes;
  crypto_auth_hmacsha512: Tcrypto_auth_hmacsha512;
  crypto_auth_hmacsha512_verify: Tcrypto_auth_hmacsha512_verify;
  crypto_auth_hmacsha512_statebytes: Tcrypto_auth_hmacsha512_statebytes;
  crypto_auth_hmacsha512_init: Tcrypto_auth_hmacsha512_init;
  crypto_auth_hmacsha512_update: Tcrypto_auth_hmacsha512_update;
  crypto_auth_hmacsha512_final: Tcrypto_auth_hmacsha512_final;
  crypto_auth_hmacsha512256_bytes: Tcrypto_auth_hmacsha512256_bytes;
  crypto_auth_hmacsha512256_keybytes: Tcrypto_auth_hmacsha512256_keybytes;
  crypto_auth_hmacsha512256: Tcrypto_auth_hmacsha512256;
  crypto_auth_hmacsha512256_verify: Tcrypto_auth_hmacsha512256_verify;
  crypto_auth_hmacsha512256_statebytes: Tcrypto_auth_hmacsha512256_statebytes;
  crypto_auth_hmacsha512256_init: Tcrypto_auth_hmacsha512256_init;
  crypto_auth_hmacsha512256_update: Tcrypto_auth_hmacsha512256_update;
  crypto_auth_hmacsha512256_final: Tcrypto_auth_hmacsha512256_final;
  crypto_box_seedbytes: Tcrypto_box_seedbytes;
  crypto_box_publickeybytes: Tcrypto_box_publickeybytes;
  crypto_box_secretkeybytes: Tcrypto_box_secretkeybytes;
  crypto_box_noncebytes: Tcrypto_box_noncebytes;
  crypto_box_macbytes: Tcrypto_box_macbytes;
  crypto_box_primitive: Tcrypto_box_primitive;
  crypto_box_seed_keypair: Tcrypto_box_seed_keypair;
  crypto_box_keypair: Tcrypto_box_keypair;
  crypto_box_easy: Tcrypto_box_easy;
  crypto_box_open_easy: Tcrypto_box_open_easy;
  crypto_box_detached: Tcrypto_box_detached;
  crypto_box_open_detached: Tcrypto_box_open_detached;
  crypto_box_beforenmbytes: Tcrypto_box_beforenmbytes;
  crypto_box_beforenm: Tcrypto_box_beforenm;
  crypto_box_easy_afternm: Tcrypto_box_easy_afternm;
  crypto_box_open_easy_afternm: Tcrypto_box_open_easy_afternm;
  crypto_box_detached_afternm: Tcrypto_box_detached_afternm;
  crypto_box_open_detached_afternm: Tcrypto_box_open_detached_afternm;
  crypto_box_sealbytes: Tcrypto_box_sealbytes;
  crypto_box_seal: Tcrypto_box_seal;
  crypto_box_seal_open: Tcrypto_box_seal_open;
  crypto_box_zerobytes: Tcrypto_box_zerobytes;
  crypto_box_boxzerobytes: Tcrypto_box_boxzerobytes;
  crypto_box: Tcrypto_box;
  crypto_box_open: Tcrypto_box_open;
  crypto_box_afternm: Tcrypto_box_afternm;
  crypto_box_open_afternm: Tcrypto_box_open_afternm;
  crypto_box_curve25519xsalsa20poly1305_seedbytes: Tcrypto_box_curve25519xsalsa20poly1305_seedbytes;
  crypto_box_curve25519xsalsa20poly1305_publickeybytes: Tcrypto_box_curve25519xsalsa20poly1305_publickeybytes;
  crypto_box_curve25519xsalsa20poly1305_secretkeybytes: Tcrypto_box_curve25519xsalsa20poly1305_secretkeybytes;
  crypto_box_curve25519xsalsa20poly1305_beforenmbytes: Tcrypto_box_curve25519xsalsa20poly1305_beforenmbytes;
  crypto_box_curve25519xsalsa20poly1305_noncebytes: Tcrypto_box_curve25519xsalsa20poly1305_noncebytes;
  crypto_box_curve25519xsalsa20poly1305_zerobytes: Tcrypto_box_curve25519xsalsa20poly1305_zerobytes;
  crypto_box_curve25519xsalsa20poly1305_boxzerobytes: Tcrypto_box_curve25519xsalsa20poly1305_boxzerobytes;
  crypto_box_curve25519xsalsa20poly1305_macbytes: Tcrypto_box_curve25519xsalsa20poly1305_macbytes;
  crypto_box_curve25519xsalsa20poly1305: Tcrypto_box_curve25519xsalsa20poly1305;
  crypto_box_curve25519xsalsa20poly1305_open: Tcrypto_box_curve25519xsalsa20poly1305_open;
  crypto_box_curve25519xsalsa20poly1305_seed_keypair: Tcrypto_box_curve25519xsalsa20poly1305_seed_keypair;
  crypto_box_curve25519xsalsa20poly1305_keypair: Tcrypto_box_curve25519xsalsa20poly1305_keypair;
  crypto_box_curve25519xsalsa20poly1305_beforenm: Tcrypto_box_curve25519xsalsa20poly1305_beforenm;
  crypto_box_curve25519xsalsa20poly1305_afternm: Tcrypto_box_curve25519xsalsa20poly1305_afternm;
  crypto_box_curve25519xsalsa20poly1305_open_afternm: Tcrypto_box_curve25519xsalsa20poly1305_open_afternm;
  crypto_core_hsalsa20_outputbytes: Tcrypto_core_hsalsa20_outputbytes;
  crypto_core_hsalsa20_inputbytes: Tcrypto_core_hsalsa20_inputbytes;
  crypto_core_hsalsa20_keybytes: Tcrypto_core_hsalsa20_keybytes;
  crypto_core_hsalsa20_constbytes: Tcrypto_core_hsalsa20_constbytes;
  crypto_core_hsalsa20: Tcrypto_core_hsalsa20;
  crypto_core_salsa20_outputbytes: Tcrypto_core_salsa20_outputbytes;
  crypto_core_salsa20_inputbytes: Tcrypto_core_salsa20_inputbytes;
  crypto_core_salsa20_keybytes: Tcrypto_core_salsa20_keybytes;
  crypto_core_salsa20_constbytes: Tcrypto_core_salsa20_constbytes;
  crypto_core_salsa20: Tcrypto_core_salsa20;
  crypto_core_salsa2012_outputbytes: Tcrypto_core_salsa2012_outputbytes;
  crypto_core_salsa2012_inputbytes: Tcrypto_core_salsa2012_inputbytes;
  crypto_core_salsa2012_keybytes: Tcrypto_core_salsa2012_keybytes;
  crypto_core_salsa2012_constbytes: Tcrypto_core_salsa2012_constbytes;
  crypto_core_salsa2012: Tcrypto_core_salsa2012;
  crypto_core_salsa208_outputbytes: Tcrypto_core_salsa208_outputbytes;
  crypto_core_salsa208_inputbytes: Tcrypto_core_salsa208_inputbytes;
  crypto_core_salsa208_keybytes: Tcrypto_core_salsa208_keybytes;
  crypto_core_salsa208_constbytes: Tcrypto_core_salsa208_constbytes;
  crypto_core_salsa208: Tcrypto_core_salsa208;
  crypto_generichash_bytes_min: Tcrypto_generichash_bytes_min;
  crypto_generichash_bytes_max: Tcrypto_generichash_bytes_max;
  crypto_generichash_bytes: Tcrypto_generichash_bytes;
  crypto_generichash_keybytes_min: Tcrypto_generichash_keybytes_min;
  crypto_generichash_keybytes_max: Tcrypto_generichash_keybytes_max;
  crypto_generichash_keybytes: Tcrypto_generichash_keybytes;
  crypto_generichash_primitive: Tcrypto_generichash_primitive;
  crypto_generichash_statebytes: Tcrypto_generichash_statebytes;
  crypto_generichash: Tcrypto_generichash;
  crypto_generichash_init: Tcrypto_generichash_init;
  crypto_generichash_update: Tcrypto_generichash_update;
  crypto_generichash_final: Tcrypto_generichash_final;
  crypto_generichash_blake2b_bytes_min: Tcrypto_generichash_blake2b_bytes_min;
  crypto_generichash_blake2b_bytes_max: Tcrypto_generichash_blake2b_bytes_max;
  crypto_generichash_blake2b_bytes: Tcrypto_generichash_blake2b_bytes;
  crypto_generichash_blake2b_keybytes_min: Tcrypto_generichash_blake2b_keybytes_min;
  crypto_generichash_blake2b_keybytes_max: Tcrypto_generichash_blake2b_keybytes_max;
  crypto_generichash_blake2b_keybytes: Tcrypto_generichash_blake2b_keybytes;
  crypto_generichash_blake2b_saltbytes: Tcrypto_generichash_blake2b_saltbytes;
  crypto_generichash_blake2b_personalbytes: Tcrypto_generichash_blake2b_personalbytes;
  crypto_generichash_blake2b: Tcrypto_generichash_blake2b;
  crypto_generichash_blake2b_salt_personal: Tcrypto_generichash_blake2b_salt_personal;
  crypto_generichash_blake2b_init: Tcrypto_generichash_blake2b_init;
  crypto_generichash_blake2b_init_salt_personal: Tcrypto_generichash_blake2b_init_salt_personal;
  crypto_generichash_blake2b_update: Tcrypto_generichash_blake2b_update;
  crypto_generichash_blake2b_final: Tcrypto_generichash_blake2b_final;
  crypto_hash_bytes: Tcrypto_hash_bytes;
  crypto_hash: Tcrypto_hash;
  crypto_hash_primitive: Tcrypto_hash_primitive;
  crypto_hash_sha256_statebytes: Tcrypto_hash_sha256_statebytes;
  crypto_hash_sha256_bytes: Tcrypto_hash_sha256_bytes;
  crypto_hash_sha256: Tcrypto_hash_sha256;
  crypto_hash_sha256_init: Tcrypto_hash_sha256_init;
  crypto_hash_sha256_update: Tcrypto_hash_sha256_update;
  crypto_hash_sha256_final: Tcrypto_hash_sha256_final;
  crypto_hash_sha512_statebytes: Tcrypto_hash_sha512_statebytes;
  crypto_hash_sha512_bytes: Tcrypto_hash_sha512_bytes;
  crypto_hash_sha512: Tcrypto_hash_sha512;
  crypto_hash_sha512_init: Tcrypto_hash_sha512_init;
  crypto_hash_sha512_update: Tcrypto_hash_sha512_update;
  crypto_hash_sha512_final: Tcrypto_hash_sha512_final;
  crypto_onetimeauth_statebytes: Tcrypto_onetimeauth_statebytes;
  crypto_onetimeauth_bytes: Tcrypto_onetimeauth_bytes;
  crypto_onetimeauth_keybytes: Tcrypto_onetimeauth_keybytes;
  crypto_onetimeauth_primitive: Tcrypto_onetimeauth_primitive;
  crypto_onetimeauth: Tcrypto_onetimeauth;
  crypto_onetimeauth_verify: Tcrypto_onetimeauth_verify;
  crypto_onetimeauth_init: Tcrypto_onetimeauth_init;
  crypto_onetimeauth_update: Tcrypto_onetimeauth_update;
  crypto_onetimeauth_final: Tcrypto_onetimeauth_final;
  crypto_onetimeauth_poly1305_bytes: Tcrypto_onetimeauth_poly1305_bytes;
  crypto_onetimeauth_poly1305_keybytes: Tcrypto_onetimeauth_poly1305_keybytes;
  crypto_onetimeauth_poly1305_implementation_name: Tcrypto_onetimeauth_poly1305_implementation_name;
  crypto_onetimeauth_poly1305_set_implementation: Tcrypto_onetimeauth_poly1305_set_implementation;
  crypto_onetimeauth_pick_best_implementation: Tcrypto_onetimeauth_pick_best_implementation;
  crypto_onetimeauth_poly1305: Tcrypto_onetimeauth_poly1305;
  crypto_onetimeauth_poly1305_verify: Tcrypto_onetimeauth_poly1305_verify;
  crypto_onetimeauth_poly1305_init: Tcrypto_onetimeauth_poly1305_init;
  crypto_onetimeauth_poly1305_update: Tcrypto_onetimeauth_poly1305_update;
  crypto_onetimeauth_poly1305_final: Tcrypto_onetimeauth_poly1305_final;
  crypto_pwhash_scryptsalsa208sha256_saltbytes: Tcrypto_pwhash_scryptsalsa208sha256_saltbytes;
  crypto_pwhash_scryptsalsa208sha256_strbytes: Tcrypto_pwhash_scryptsalsa208sha256_strbytes;
  crypto_pwhash_scryptsalsa208sha256_strprefix: Tcrypto_pwhash_scryptsalsa208sha256_strprefix;
  crypto_pwhash_scryptsalsa208sha256_opslimit_interactive: Tcrypto_pwhash_scryptsalsa208sha256_opslimit_interactive;
  crypto_pwhash_scryptsalsa208sha256_memlimit_interactive: Tcrypto_pwhash_scryptsalsa208sha256_memlimit_interactive;
  crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive: Tcrypto_pwhash_scryptsalsa208sha256_opslimit_sensitive;
  crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive: Tcrypto_pwhash_scryptsalsa208sha256_memlimit_sensitive;
  crypto_pwhash_scryptsalsa208sha256: Tcrypto_pwhash_scryptsalsa208sha256;
  crypto_pwhash_scryptsalsa208sha256_str: Tcrypto_pwhash_scryptsalsa208sha256_str;
  crypto_pwhash_scryptsalsa208sha256_str_verify: Tcrypto_pwhash_scryptsalsa208sha256_str_verify;
  crypto_pwhash_scryptsalsa208sha256_ll: Tcrypto_pwhash_scryptsalsa208sha256_ll;
  crypto_scalarmult_bytes: Tcrypto_scalarmult_bytes;
  crypto_scalarmult_scalarbytes: Tcrypto_scalarmult_scalarbytes;
  crypto_scalarmult_primitive: Tcrypto_scalarmult_primitive;
  crypto_scalarmult_base: Tcrypto_scalarmult_base;
  crypto_scalarmult: Tcrypto_scalarmult;
  crypto_scalarmult_curve25519_bytes: Tcrypto_scalarmult_curve25519_bytes;
  crypto_scalarmult_curve25519_scalarbytes: Tcrypto_scalarmult_curve25519_scalarbytes;
  crypto_scalarmult_curve25519: Tcrypto_scalarmult_curve25519;
  crypto_scalarmult_curve25519_base: Tcrypto_scalarmult_curve25519_base;
  crypto_secretbox_keybytes: Tcrypto_secretbox_keybytes;
  crypto_secretbox_noncebytes: Tcrypto_secretbox_noncebytes;
  crypto_secretbox_macbytes: Tcrypto_secretbox_macbytes;
  crypto_secretbox_primitive: Tcrypto_secretbox_primitive;
  crypto_secretbox_easy: Tcrypto_secretbox_easy;
  crypto_secretbox_open_easy: Tcrypto_secretbox_open_easy;
  crypto_secretbox_detached: Tcrypto_secretbox_detached;
  crypto_secretbox_open_detached: Tcrypto_secretbox_open_detached;
  crypto_secretbox_zerobytes: Tcrypto_secretbox_zerobytes;
  crypto_secretbox_boxzerobytes: Tcrypto_secretbox_boxzerobytes;
  crypto_secretbox: Tcrypto_secretbox;
  crypto_secretbox_open: Tcrypto_secretbox_open;
  crypto_secretbox_xsalsa20poly1305_keybytes: Tcrypto_secretbox_xsalsa20poly1305_keybytes;
  crypto_secretbox_xsalsa20poly1305_noncebytes: Tcrypto_secretbox_xsalsa20poly1305_noncebytes;
  crypto_secretbox_xsalsa20poly1305_zerobytes: Tcrypto_secretbox_xsalsa20poly1305_zerobytes;
  crypto_secretbox_xsalsa20poly1305_boxzerobytes: Tcrypto_secretbox_xsalsa20poly1305_boxzerobytes;
  crypto_secretbox_xsalsa20poly1305_macbytes: Tcrypto_secretbox_xsalsa20poly1305_macbytes;
  crypto_secretbox_xsalsa20poly1305: Tcrypto_secretbox_xsalsa20poly1305;
  crypto_secretbox_xsalsa20poly1305_open: Tcrypto_secretbox_xsalsa20poly1305_open;
  crypto_shorthash_bytes: Tcrypto_shorthash_bytes;
  crypto_shorthash_keybytes: Tcrypto_shorthash_keybytes;
  crypto_shorthash_primitive: Tcrypto_shorthash_primitive;
  crypto_shorthash: Tcrypto_shorthash;
  crypto_shorthash_siphash24_bytes: Tcrypto_shorthash_siphash24_bytes;
  crypto_shorthash_siphash24_keybytes: Tcrypto_shorthash_siphash24_keybytes;
  crypto_shorthash_siphash24: Tcrypto_shorthash_siphash24;
  crypto_sign_bytes: Tcrypto_sign_bytes;
  crypto_sign_seedbytes: Tcrypto_sign_seedbytes;
  crypto_sign_publickeybytes: Tcrypto_sign_publickeybytes;
  crypto_sign_secretkeybytes: Tcrypto_sign_secretkeybytes;
  crypto_sign_primitive: Tcrypto_sign_primitive;
  crypto_sign_seed_keypair: Tcrypto_sign_seed_keypair;
  crypto_sign_keypair: Tcrypto_sign_keypair;
  crypto_sign: Tcrypto_sign;
  crypto_sign_open: Tcrypto_sign_open;
  crypto_sign_detached: Tcrypto_sign_detached;
  crypto_sign_verify_detached: Tcrypto_sign_verify_detached;
  crypto_sign_ed25519_bytes: Tcrypto_sign_ed25519_bytes;
  crypto_sign_ed25519_seedbytes: Tcrypto_sign_ed25519_seedbytes;
  crypto_sign_ed25519_publickeybytes: Tcrypto_sign_ed25519_publickeybytes;
  crypto_sign_ed25519_secretkeybytes: Tcrypto_sign_ed25519_secretkeybytes;
  crypto_sign_ed25519: Tcrypto_sign_ed25519;
  crypto_sign_ed25519_open: Tcrypto_sign_ed25519_open;
  crypto_sign_ed25519_detached: Tcrypto_sign_ed25519_detached;
  crypto_sign_ed25519_verify_detached: Tcrypto_sign_ed25519_verify_detached;
  crypto_sign_ed25519_keypair: Tcrypto_sign_ed25519_keypair;
  crypto_sign_ed25519_seed_keypair: Tcrypto_sign_ed25519_seed_keypair;
  crypto_sign_ed25519_pk_to_curve25519: Tcrypto_sign_ed25519_pk_to_curve25519;
  crypto_sign_ed25519_sk_to_curve25519: Tcrypto_sign_ed25519_sk_to_curve25519;
  crypto_sign_ed25519_sk_to_seed: Tcrypto_sign_ed25519_sk_to_seed;
  crypto_sign_ed25519_sk_to_pk: Tcrypto_sign_ed25519_sk_to_pk;
  crypto_sign_edwards25519sha512batch_bytes: Tcrypto_sign_edwards25519sha512batch_bytes;
  crypto_sign_edwards25519sha512batch_publickeybytes: Tcrypto_sign_edwards25519sha512batch_publickeybytes;
  crypto_sign_edwards25519sha512batch_secretkeybytes: Tcrypto_sign_edwards25519sha512batch_secretkeybytes;
  crypto_sign_edwards25519sha512batch: Tcrypto_sign_edwards25519sha512batch;
  crypto_sign_edwards25519sha512batch_open: Tcrypto_sign_edwards25519sha512batch_open;
  crypto_sign_edwards25519sha512batch_keypair: Tcrypto_sign_edwards25519sha512batch_keypair;
  crypto_stream_keybytes: Tcrypto_stream_keybytes;
  crypto_stream_noncebytes: Tcrypto_stream_noncebytes;
  crypto_stream_primitive: Tcrypto_stream_primitive;
  crypto_stream: Tcrypto_stream;
  crypto_stream_xor: Tcrypto_stream_xor;
  crypto_stream_aes128ctr_keybytes: Tcrypto_stream_aes128ctr_keybytes;
  crypto_stream_aes128ctr_noncebytes: Tcrypto_stream_aes128ctr_noncebytes;
  crypto_stream_aes128ctr_beforenmbytes: Tcrypto_stream_aes128ctr_beforenmbytes;
  crypto_stream_aes128ctr: Tcrypto_stream_aes128ctr;
  crypto_stream_aes128ctr_xor: Tcrypto_stream_aes128ctr_xor;
  crypto_stream_aes128ctr_beforenm: Tcrypto_stream_aes128ctr_beforenm;
  crypto_stream_aes128ctr_afternm: Tcrypto_stream_aes128ctr_afternm;
  crypto_stream_aes128ctr_xor_afternm: Tcrypto_stream_aes128ctr_xor_afternm;
  crypto_stream_chacha20_keybytes: Tcrypto_stream_chacha20_keybytes;
  crypto_stream_chacha20_noncebytes: Tcrypto_stream_chacha20_noncebytes;
  crypto_stream_chacha20: Tcrypto_stream_chacha20;
  crypto_stream_chacha20_xor: Tcrypto_stream_chacha20_xor;
  crypto_stream_chacha20_xor_ic: Tcrypto_stream_chacha20_xor_ic;
  crypto_stream_salsa20_keybytes: Tcrypto_stream_salsa20_keybytes;
  crypto_stream_salsa20_noncebytes: Tcrypto_stream_salsa20_noncebytes;
  crypto_stream_salsa20: Tcrypto_stream_salsa20;
  crypto_stream_salsa20_xor: Tcrypto_stream_salsa20_xor;
  crypto_stream_salsa20_xor_ic: Tcrypto_stream_salsa20_xor_ic;
  crypto_stream_salsa2012_keybytes: Tcrypto_stream_salsa2012_keybytes;
  crypto_stream_salsa2012_noncebytes: Tcrypto_stream_salsa2012_noncebytes;
  crypto_stream_salsa2012: Tcrypto_stream_salsa2012;
  crypto_stream_salsa2012_xor: Tcrypto_stream_salsa2012_xor;
  crypto_stream_salsa208_keybytes: Tcrypto_stream_salsa208_keybytes;
  crypto_stream_salsa208_noncebytes: Tcrypto_stream_salsa208_noncebytes;
  crypto_stream_salsa208: Tcrypto_stream_salsa208;
  crypto_stream_salsa208_xor: Tcrypto_stream_salsa208_xor;
  crypto_stream_xsalsa20_keybytes: Tcrypto_stream_xsalsa20_keybytes;
  crypto_stream_xsalsa20_noncebytes: Tcrypto_stream_xsalsa20_noncebytes;
  crypto_stream_xsalsa20: Tcrypto_stream_xsalsa20;
  crypto_stream_xsalsa20_xor: Tcrypto_stream_xsalsa20_xor;
  crypto_stream_xsalsa20_xor_ic: Tcrypto_stream_xsalsa20_xor_ic;
  crypto_verify_16_bytes: Tcrypto_verify_16_bytes;
  crypto_verify_16: Tcrypto_verify_16;
  crypto_verify_32_bytes: Tcrypto_verify_32_bytes;
  crypto_verify_32: Tcrypto_verify_32;
  crypto_verify_64_bytes: Tcrypto_verify_64_bytes;
  crypto_verify_64: Tcrypto_verify_64;
  randombytes_buf: Trandombytes_buf;
  randombytes_random: Trandombytes_random;
  randombytes_uniform: Trandombytes_uniform;
  randombytes_stir: Trandombytes_stir;
  randombytes_close: Trandombytes_close;
  randombytes_set_implementation: Trandombytes_set_implementation;
  randombytes_implementation_name: Trandombytes_implementation_name;
  randombytes: Trandombytes;
  randombytes_salsa20_implementation_name: Trandombytes_salsa20_implementation_name;
  randombytes_salsa20_random: Trandombytes_salsa20_random;
  randombytes_salsa20_random_stir: Trandombytes_salsa20_random_stir;
  randombytes_salsa20_random_uniform: Trandombytes_salsa20_random_uniform;
  randombytes_salsa20_random_buf: Trandombytes_salsa20_random_buf;
  randombytes_salsa20_random_close: Trandombytes_salsa20_random_close;
  randombytes_sysrandom_implementation_name: Trandombytes_sysrandom_implementation_name;
  randombytes_sysrandom: Trandombytes_sysrandom;
  randombytes_sysrandom_stir: Trandombytes_sysrandom_stir;
  randombytes_sysrandom_uniform: Trandombytes_sysrandom_uniform;
  randombytes_sysrandom_buf: Trandombytes_sysrandom_buf;
  randombytes_sysrandom_close: Trandombytes_sysrandom_close;
  sodium_runtime_get_cpu_features: Tsodium_runtime_get_cpu_features;
  sodium_runtime_has_neon: Tsodium_runtime_has_neon;
  sodium_runtime_has_sse2: Tsodium_runtime_has_sse2;
  sodium_runtime_has_sse3: Tsodium_runtime_has_sse3;
  sodium_memzero: Tsodium_memzero;
  sodium_memcmp: Tsodium_memcmp;
  sodium_bin2hex: Tsodium_bin2hex;
  sodium_hex2bin: Tsodium_hex2bin;
  sodium_mlock: Tsodium_mlock;
  sodium_munlock: Tsodium_munlock;
  sodium_malloc: Tsodium_malloc;
  sodium_free: Tsodium_free;
  sodium_allocarray: Tsodium_allocarray;
  sodium_mprotect_noaccess: Tsodium_mprotect_noaccess;
  sodium_mprotect_readonly: Tsodium_mprotect_readonly;
  sodium_mprotect_readwrite: Tsodium_mprotect_readwrite;
  _sodium_alloc_init: T_sodium_alloc_init;
  sodium_version_string: Tsodium_version_string;
  sodium_library_version_major: Tsodium_library_version_major;
  sodium_library_version_minor: Tsodium_library_version_minor;

  //libsodium 1.0.4
  sodium_increment: Tsodium_increment;


var
  sodium_dllLoaded: Boolean = False;  { is DLL (dynamically) loaded already? }
  sodium_dllFileName: AnsiString = 'libsodium.dll';


implementation


var
  SaveExit: pointer;
  DLLHandle: THandle;
{$IFNDEF MSDOS}
  ErrorMode: Integer;
{$ENDIF}

  procedure NewExit; far;
  begin
    ExitProc := SaveExit;
    FreeLibrary(DLLHandle)
  end {NewExit};

procedure LoadDLL;
begin
  if sodium_dllLoaded then Exit;
{$IFNDEF MSDOS}
  ErrorMode := SetErrorMode($8000{SEM_NoOpenFileErrorBox});
{$ENDIF}
{$IFDEF WIN64}
  if FileExists('libsodium64.dll') then sodium_dllFileName := 'libsodium64.dll';
{$ENDIF}
{$IF CompilerVersion >= 20.0} { Delphi 2009 unicode }
  DLLHandle := LoadLibrary(PWideChar(WideString(sodium_dllFileName)));
{$ELSE}
  DLLHandle := LoadLibrary(PAnsiChar(sodium_dllFileName));
{$IFEND}
  if DLLHandle >= 32 then
  begin
    sodium_dllLoaded := True;
    SaveExit := ExitProc;
    ExitProc := @NewExit;
    @sodium_init := GetProcAddress(DLLHandle,'sodium_init');
  {$IFDEF WIN32}
    Assert(@sodium_init <> nil);
  {$ENDIF}
    @crypto_aead_chacha20poly1305_keybytes := GetProcAddress(DLLHandle,'crypto_aead_chacha20poly1305_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_aead_chacha20poly1305_keybytes <> nil);
  {$ENDIF}
    @crypto_aead_chacha20poly1305_nsecbytes := GetProcAddress(DLLHandle,'crypto_aead_chacha20poly1305_nsecbytes');
  {$IFDEF WIN32}
    Assert(@crypto_aead_chacha20poly1305_nsecbytes <> nil);
  {$ENDIF}
    @crypto_aead_chacha20poly1305_npubbytes := GetProcAddress(DLLHandle,'crypto_aead_chacha20poly1305_npubbytes');
  {$IFDEF WIN32}
    Assert(@crypto_aead_chacha20poly1305_npubbytes <> nil);
  {$ENDIF}
    @crypto_aead_chacha20poly1305_abytes := GetProcAddress(DLLHandle,'crypto_aead_chacha20poly1305_abytes');
  {$IFDEF WIN32}
    Assert(@crypto_aead_chacha20poly1305_abytes <> nil);
  {$ENDIF}
    @crypto_aead_chacha20poly1305_encrypt := GetProcAddress(DLLHandle,'crypto_aead_chacha20poly1305_encrypt');
  {$IFDEF WIN32}
    Assert(@crypto_aead_chacha20poly1305_encrypt <> nil);
  {$ENDIF}
    @crypto_aead_chacha20poly1305_decrypt := GetProcAddress(DLLHandle,'crypto_aead_chacha20poly1305_decrypt');
  {$IFDEF WIN32}
    Assert(@crypto_aead_chacha20poly1305_decrypt <> nil);
  {$ENDIF}
    @crypto_auth_bytes := GetProcAddress(DLLHandle,'crypto_auth_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_auth_bytes <> nil);
  {$ENDIF}
    @crypto_auth_keybytes := GetProcAddress(DLLHandle,'crypto_auth_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_auth_keybytes <> nil);
  {$ENDIF}
    @crypto_auth_primitive := GetProcAddress(DLLHandle,'crypto_auth_primitive');
  {$IFDEF WIN32}
    Assert(@crypto_auth_primitive <> nil);
  {$ENDIF}
    @crypto_auth := GetProcAddress(DLLHandle,'crypto_auth');
  {$IFDEF WIN32}
    Assert(@crypto_auth <> nil);
  {$ENDIF}
    @crypto_auth_verify := GetProcAddress(DLLHandle,'crypto_auth_verify');
  {$IFDEF WIN32}
    Assert(@crypto_auth_verify <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha256_bytes := GetProcAddress(DLLHandle,'crypto_auth_hmacsha256_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha256_bytes <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha256_keybytes := GetProcAddress(DLLHandle,'crypto_auth_hmacsha256_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha256_keybytes <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha256 := GetProcAddress(DLLHandle,'crypto_auth_hmacsha256');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha256 <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha256_verify := GetProcAddress(DLLHandle,'crypto_auth_hmacsha256_verify');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha256_verify <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha256_statebytes := GetProcAddress(DLLHandle,'crypto_auth_hmacsha256_statebytes');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha256_statebytes <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha256_init := GetProcAddress(DLLHandle,'crypto_auth_hmacsha256_init');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha256_init <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha256_update := GetProcAddress(DLLHandle,'crypto_auth_hmacsha256_update');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha256_update <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha256_final := GetProcAddress(DLLHandle,'crypto_auth_hmacsha256_final');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha256_final <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512_bytes := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512_bytes <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512_keybytes := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512_keybytes <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512 := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512 <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512_verify := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512_verify');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512_verify <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512_statebytes := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512_statebytes');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512_statebytes <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512_init := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512_init');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512_init <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512_update := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512_update');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512_update <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512_final := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512_final');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512_final <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512256_bytes := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512256_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512256_bytes <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512256_keybytes := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512256_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512256_keybytes <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512256 := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512256');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512256 <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512256_verify := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512256_verify');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512256_verify <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512256_statebytes := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512256_statebytes');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512256_statebytes <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512256_init := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512256_init');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512256_init <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512256_update := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512256_update');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512256_update <> nil);
  {$ENDIF}
    @crypto_auth_hmacsha512256_final := GetProcAddress(DLLHandle,'crypto_auth_hmacsha512256_final');
  {$IFDEF WIN32}
    Assert(@crypto_auth_hmacsha512256_final <> nil);
  {$ENDIF}
    @crypto_box_seedbytes := GetProcAddress(DLLHandle,'crypto_box_seedbytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_seedbytes <> nil);
  {$ENDIF}
    @crypto_box_publickeybytes := GetProcAddress(DLLHandle,'crypto_box_publickeybytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_publickeybytes <> nil);
  {$ENDIF}
    @crypto_box_secretkeybytes := GetProcAddress(DLLHandle,'crypto_box_secretkeybytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_secretkeybytes <> nil);
  {$ENDIF}
    @crypto_box_noncebytes := GetProcAddress(DLLHandle,'crypto_box_noncebytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_noncebytes <> nil);
  {$ENDIF}
    @crypto_box_macbytes := GetProcAddress(DLLHandle,'crypto_box_macbytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_macbytes <> nil);
  {$ENDIF}
    @crypto_box_primitive := GetProcAddress(DLLHandle,'crypto_box_primitive');
  {$IFDEF WIN32}
    Assert(@crypto_box_primitive <> nil);
  {$ENDIF}
    @crypto_box_seed_keypair := GetProcAddress(DLLHandle,'crypto_box_seed_keypair');
  {$IFDEF WIN32}
    Assert(@crypto_box_seed_keypair <> nil);
  {$ENDIF}
    @crypto_box_keypair := GetProcAddress(DLLHandle,'crypto_box_keypair');
  {$IFDEF WIN32}
    Assert(@crypto_box_keypair <> nil);
  {$ENDIF}
    @crypto_box_easy := GetProcAddress(DLLHandle,'crypto_box_easy');
  {$IFDEF WIN32}
    Assert(@crypto_box_easy <> nil);
  {$ENDIF}
    @crypto_box_open_easy := GetProcAddress(DLLHandle,'crypto_box_open_easy');
  {$IFDEF WIN32}
    Assert(@crypto_box_open_easy <> nil);
  {$ENDIF}
    @crypto_box_detached := GetProcAddress(DLLHandle,'crypto_box_detached');
  {$IFDEF WIN32}
    Assert(@crypto_box_detached <> nil);
  {$ENDIF}
    @crypto_box_open_detached := GetProcAddress(DLLHandle,'crypto_box_open_detached');
  {$IFDEF WIN32}
    Assert(@crypto_box_open_detached <> nil);
  {$ENDIF}
    @crypto_box_beforenmbytes := GetProcAddress(DLLHandle,'crypto_box_beforenmbytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_beforenmbytes <> nil);
  {$ENDIF}
    @crypto_box_beforenm := GetProcAddress(DLLHandle,'crypto_box_beforenm');
  {$IFDEF WIN32}
    Assert(@crypto_box_beforenm <> nil);
  {$ENDIF}
    @crypto_box_easy_afternm := GetProcAddress(DLLHandle,'crypto_box_easy_afternm');
  {$IFDEF WIN32}
    Assert(@crypto_box_easy_afternm <> nil);
  {$ENDIF}
    @crypto_box_open_easy_afternm := GetProcAddress(DLLHandle,'crypto_box_open_easy_afternm');
  {$IFDEF WIN32}
    Assert(@crypto_box_open_easy_afternm <> nil);
  {$ENDIF}
    @crypto_box_detached_afternm := GetProcAddress(DLLHandle,'crypto_box_detached_afternm');
  {$IFDEF WIN32}
    Assert(@crypto_box_detached_afternm <> nil);
  {$ENDIF}
    @crypto_box_open_detached_afternm := GetProcAddress(DLLHandle,'crypto_box_open_detached_afternm');
  {$IFDEF WIN32}
    Assert(@crypto_box_open_detached_afternm <> nil);
  {$ENDIF}
    @crypto_box_sealbytes := GetProcAddress(DLLHandle,'crypto_box_sealbytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_sealbytes <> nil);
  {$ENDIF}
    @crypto_box_seal := GetProcAddress(DLLHandle,'crypto_box_seal');
  {$IFDEF WIN32}
    Assert(@crypto_box_seal <> nil);
  {$ENDIF}
    @crypto_box_seal_open := GetProcAddress(DLLHandle,'crypto_box_seal_open');
  {$IFDEF WIN32}
    Assert(@crypto_box_seal_open <> nil);
  {$ENDIF}
    @crypto_box_zerobytes := GetProcAddress(DLLHandle,'crypto_box_zerobytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_zerobytes <> nil);
  {$ENDIF}
    @crypto_box_boxzerobytes := GetProcAddress(DLLHandle,'crypto_box_boxzerobytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_boxzerobytes <> nil);
  {$ENDIF}
    @crypto_box := GetProcAddress(DLLHandle,'crypto_box');
  {$IFDEF WIN32}
    Assert(@crypto_box <> nil);
  {$ENDIF}
    @crypto_box_open := GetProcAddress(DLLHandle,'crypto_box_open');
  {$IFDEF WIN32}
    Assert(@crypto_box_open <> nil);
  {$ENDIF}
    @crypto_box_afternm := GetProcAddress(DLLHandle,'crypto_box_afternm');
  {$IFDEF WIN32}
    Assert(@crypto_box_afternm <> nil);
  {$ENDIF}
    @crypto_box_open_afternm := GetProcAddress(DLLHandle,'crypto_box_open_afternm');
  {$IFDEF WIN32}
    Assert(@crypto_box_open_afternm <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305_seedbytes := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305_seedbytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305_seedbytes <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305_publickeybytes := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305_publickeybytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305_publickeybytes <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305_secretkeybytes := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305_secretkeybytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305_secretkeybytes <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305_beforenmbytes := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305_beforenmbytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305_beforenmbytes <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305_noncebytes := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305_noncebytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305_noncebytes <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305_zerobytes := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305_zerobytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305_zerobytes <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305_boxzerobytes := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305_boxzerobytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305_boxzerobytes <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305_macbytes := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305_macbytes');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305_macbytes <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305 := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305 <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305_open := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305_open');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305_open <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305_seed_keypair := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305_seed_keypair');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305_seed_keypair <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305_keypair := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305_keypair');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305_keypair <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305_beforenm := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305_beforenm');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305_beforenm <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305_afternm := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305_afternm');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305_afternm <> nil);
  {$ENDIF}
    @crypto_box_curve25519xsalsa20poly1305_open_afternm := GetProcAddress(DLLHandle,'crypto_box_curve25519xsalsa20poly1305_open_afternm');
  {$IFDEF WIN32}
    Assert(@crypto_box_curve25519xsalsa20poly1305_open_afternm <> nil);
  {$ENDIF}
    @crypto_core_hsalsa20_outputbytes := GetProcAddress(DLLHandle,'crypto_core_hsalsa20_outputbytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_hsalsa20_outputbytes <> nil);
  {$ENDIF}
    @crypto_core_hsalsa20_inputbytes := GetProcAddress(DLLHandle,'crypto_core_hsalsa20_inputbytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_hsalsa20_inputbytes <> nil);
  {$ENDIF}
    @crypto_core_hsalsa20_keybytes := GetProcAddress(DLLHandle,'crypto_core_hsalsa20_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_hsalsa20_keybytes <> nil);
  {$ENDIF}
    @crypto_core_hsalsa20_constbytes := GetProcAddress(DLLHandle,'crypto_core_hsalsa20_constbytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_hsalsa20_constbytes <> nil);
  {$ENDIF}
    @crypto_core_hsalsa20 := GetProcAddress(DLLHandle,'crypto_core_hsalsa20');
  {$IFDEF WIN32}
    Assert(@crypto_core_hsalsa20 <> nil);
  {$ENDIF}
    @crypto_core_salsa20_outputbytes := GetProcAddress(DLLHandle,'crypto_core_salsa20_outputbytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa20_outputbytes <> nil);
  {$ENDIF}
    @crypto_core_salsa20_inputbytes := GetProcAddress(DLLHandle,'crypto_core_salsa20_inputbytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa20_inputbytes <> nil);
  {$ENDIF}
    @crypto_core_salsa20_keybytes := GetProcAddress(DLLHandle,'crypto_core_salsa20_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa20_keybytes <> nil);
  {$ENDIF}
    @crypto_core_salsa20_constbytes := GetProcAddress(DLLHandle,'crypto_core_salsa20_constbytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa20_constbytes <> nil);
  {$ENDIF}
    @crypto_core_salsa20 := GetProcAddress(DLLHandle,'crypto_core_salsa20');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa20 <> nil);
  {$ENDIF}
    @crypto_core_salsa2012_outputbytes := GetProcAddress(DLLHandle,'crypto_core_salsa2012_outputbytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa2012_outputbytes <> nil);
  {$ENDIF}
    @crypto_core_salsa2012_inputbytes := GetProcAddress(DLLHandle,'crypto_core_salsa2012_inputbytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa2012_inputbytes <> nil);
  {$ENDIF}
    @crypto_core_salsa2012_keybytes := GetProcAddress(DLLHandle,'crypto_core_salsa2012_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa2012_keybytes <> nil);
  {$ENDIF}
    @crypto_core_salsa2012_constbytes := GetProcAddress(DLLHandle,'crypto_core_salsa2012_constbytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa2012_constbytes <> nil);
  {$ENDIF}
    @crypto_core_salsa2012 := GetProcAddress(DLLHandle,'crypto_core_salsa2012');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa2012 <> nil);
  {$ENDIF}
    @crypto_core_salsa208_outputbytes := GetProcAddress(DLLHandle,'crypto_core_salsa208_outputbytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa208_outputbytes <> nil);
  {$ENDIF}
    @crypto_core_salsa208_inputbytes := GetProcAddress(DLLHandle,'crypto_core_salsa208_inputbytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa208_inputbytes <> nil);
  {$ENDIF}
    @crypto_core_salsa208_keybytes := GetProcAddress(DLLHandle,'crypto_core_salsa208_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa208_keybytes <> nil);
  {$ENDIF}
    @crypto_core_salsa208_constbytes := GetProcAddress(DLLHandle,'crypto_core_salsa208_constbytes');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa208_constbytes <> nil);
  {$ENDIF}
    @crypto_core_salsa208 := GetProcAddress(DLLHandle,'crypto_core_salsa208');
  {$IFDEF WIN32}
    Assert(@crypto_core_salsa208 <> nil);
  {$ENDIF}
    @crypto_generichash_bytes_min := GetProcAddress(DLLHandle,'crypto_generichash_bytes_min');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_bytes_min <> nil);
  {$ENDIF}
    @crypto_generichash_bytes_max := GetProcAddress(DLLHandle,'crypto_generichash_bytes_max');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_bytes_max <> nil);
  {$ENDIF}
    @crypto_generichash_bytes := GetProcAddress(DLLHandle,'crypto_generichash_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_bytes <> nil);
  {$ENDIF}
    @crypto_generichash_keybytes_min := GetProcAddress(DLLHandle,'crypto_generichash_keybytes_min');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_keybytes_min <> nil);
  {$ENDIF}
    @crypto_generichash_keybytes_max := GetProcAddress(DLLHandle,'crypto_generichash_keybytes_max');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_keybytes_max <> nil);
  {$ENDIF}
    @crypto_generichash_keybytes := GetProcAddress(DLLHandle,'crypto_generichash_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_keybytes <> nil);
  {$ENDIF}
    @crypto_generichash_primitive := GetProcAddress(DLLHandle,'crypto_generichash_primitive');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_primitive <> nil);
  {$ENDIF}
    @crypto_generichash_statebytes := GetProcAddress(DLLHandle,'crypto_generichash_statebytes');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_statebytes <> nil);
  {$ENDIF}
    @crypto_generichash := GetProcAddress(DLLHandle,'crypto_generichash');
  {$IFDEF WIN32}
    Assert(@crypto_generichash <> nil);
  {$ENDIF}
    @crypto_generichash_init := GetProcAddress(DLLHandle,'crypto_generichash_init');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_init <> nil);
  {$ENDIF}
    @crypto_generichash_update := GetProcAddress(DLLHandle,'crypto_generichash_update');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_update <> nil);
  {$ENDIF}
    @crypto_generichash_final := GetProcAddress(DLLHandle,'crypto_generichash_final');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_final <> nil);
  {$ENDIF}
    @crypto_generichash_blake2b_bytes_min := GetProcAddress(DLLHandle,'crypto_generichash_blake2b_bytes_min');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_blake2b_bytes_min <> nil);
  {$ENDIF}
    @crypto_generichash_blake2b_bytes_max := GetProcAddress(DLLHandle,'crypto_generichash_blake2b_bytes_max');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_blake2b_bytes_max <> nil);
  {$ENDIF}
    @crypto_generichash_blake2b_bytes := GetProcAddress(DLLHandle,'crypto_generichash_blake2b_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_blake2b_bytes <> nil);
  {$ENDIF}
    @crypto_generichash_blake2b_keybytes_min := GetProcAddress(DLLHandle,'crypto_generichash_blake2b_keybytes_min');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_blake2b_keybytes_min <> nil);
  {$ENDIF}
    @crypto_generichash_blake2b_keybytes_max := GetProcAddress(DLLHandle,'crypto_generichash_blake2b_keybytes_max');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_blake2b_keybytes_max <> nil);
  {$ENDIF}
    @crypto_generichash_blake2b_keybytes := GetProcAddress(DLLHandle,'crypto_generichash_blake2b_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_blake2b_keybytes <> nil);
  {$ENDIF}
    @crypto_generichash_blake2b_saltbytes := GetProcAddress(DLLHandle,'crypto_generichash_blake2b_saltbytes');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_blake2b_saltbytes <> nil);
  {$ENDIF}
    @crypto_generichash_blake2b_personalbytes := GetProcAddress(DLLHandle,'crypto_generichash_blake2b_personalbytes');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_blake2b_personalbytes <> nil);
  {$ENDIF}
    @crypto_generichash_blake2b := GetProcAddress(DLLHandle,'crypto_generichash_blake2b');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_blake2b <> nil);
  {$ENDIF}
    @crypto_generichash_blake2b_salt_personal := GetProcAddress(DLLHandle,'crypto_generichash_blake2b_salt_personal');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_blake2b_salt_personal <> nil);
  {$ENDIF}
    @crypto_generichash_blake2b_init := GetProcAddress(DLLHandle,'crypto_generichash_blake2b_init');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_blake2b_init <> nil);
  {$ENDIF}
    @crypto_generichash_blake2b_init_salt_personal := GetProcAddress(DLLHandle,'crypto_generichash_blake2b_init_salt_personal');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_blake2b_init_salt_personal <> nil);
  {$ENDIF}
    @crypto_generichash_blake2b_update := GetProcAddress(DLLHandle,'crypto_generichash_blake2b_update');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_blake2b_update <> nil);
  {$ENDIF}
    @crypto_generichash_blake2b_final := GetProcAddress(DLLHandle,'crypto_generichash_blake2b_final');
  {$IFDEF WIN32}
    Assert(@crypto_generichash_blake2b_final <> nil);
  {$ENDIF}
    @crypto_hash_bytes := GetProcAddress(DLLHandle,'crypto_hash_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_hash_bytes <> nil);
  {$ENDIF}
    @crypto_hash := GetProcAddress(DLLHandle,'crypto_hash');
  {$IFDEF WIN32}
    Assert(@crypto_hash <> nil);
  {$ENDIF}
    @crypto_hash_primitive := GetProcAddress(DLLHandle,'crypto_hash_primitive');
  {$IFDEF WIN32}
    Assert(@crypto_hash_primitive <> nil);
  {$ENDIF}
    @crypto_hash_sha256_statebytes := GetProcAddress(DLLHandle,'crypto_hash_sha256_statebytes');
  {$IFDEF WIN32}
    Assert(@crypto_hash_sha256_statebytes <> nil);
  {$ENDIF}
    @crypto_hash_sha256_bytes := GetProcAddress(DLLHandle,'crypto_hash_sha256_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_hash_sha256_bytes <> nil);
  {$ENDIF}
    @crypto_hash_sha256 := GetProcAddress(DLLHandle,'crypto_hash_sha256');
  {$IFDEF WIN32}
    Assert(@crypto_hash_sha256 <> nil);
  {$ENDIF}
    @crypto_hash_sha256_init := GetProcAddress(DLLHandle,'crypto_hash_sha256_init');
  {$IFDEF WIN32}
    Assert(@crypto_hash_sha256_init <> nil);
  {$ENDIF}
    @crypto_hash_sha256_update := GetProcAddress(DLLHandle,'crypto_hash_sha256_update');
  {$IFDEF WIN32}
    Assert(@crypto_hash_sha256_update <> nil);
  {$ENDIF}
    @crypto_hash_sha256_final := GetProcAddress(DLLHandle,'crypto_hash_sha256_final');
  {$IFDEF WIN32}
    Assert(@crypto_hash_sha256_final <> nil);
  {$ENDIF}
    @crypto_hash_sha512_statebytes := GetProcAddress(DLLHandle,'crypto_hash_sha512_statebytes');
  {$IFDEF WIN32}
    Assert(@crypto_hash_sha512_statebytes <> nil);
  {$ENDIF}
    @crypto_hash_sha512_bytes := GetProcAddress(DLLHandle,'crypto_hash_sha512_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_hash_sha512_bytes <> nil);
  {$ENDIF}
    @crypto_hash_sha512 := GetProcAddress(DLLHandle,'crypto_hash_sha512');
  {$IFDEF WIN32}
    Assert(@crypto_hash_sha512 <> nil);
  {$ENDIF}
    @crypto_hash_sha512_init := GetProcAddress(DLLHandle,'crypto_hash_sha512_init');
  {$IFDEF WIN32}
    Assert(@crypto_hash_sha512_init <> nil);
  {$ENDIF}
    @crypto_hash_sha512_update := GetProcAddress(DLLHandle,'crypto_hash_sha512_update');
  {$IFDEF WIN32}
    Assert(@crypto_hash_sha512_update <> nil);
  {$ENDIF}
    @crypto_hash_sha512_final := GetProcAddress(DLLHandle,'crypto_hash_sha512_final');
  {$IFDEF WIN32}
    Assert(@crypto_hash_sha512_final <> nil);
  {$ENDIF}
    @crypto_onetimeauth_statebytes := GetProcAddress(DLLHandle,'crypto_onetimeauth_statebytes');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_statebytes <> nil);
  {$ENDIF}
    @crypto_onetimeauth_bytes := GetProcAddress(DLLHandle,'crypto_onetimeauth_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_bytes <> nil);
  {$ENDIF}
    @crypto_onetimeauth_keybytes := GetProcAddress(DLLHandle,'crypto_onetimeauth_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_keybytes <> nil);
  {$ENDIF}
    @crypto_onetimeauth_primitive := GetProcAddress(DLLHandle,'crypto_onetimeauth_primitive');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_primitive <> nil);
  {$ENDIF}
    @crypto_onetimeauth := GetProcAddress(DLLHandle,'crypto_onetimeauth');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth <> nil);
  {$ENDIF}
    @crypto_onetimeauth_verify := GetProcAddress(DLLHandle,'crypto_onetimeauth_verify');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_verify <> nil);
  {$ENDIF}
    @crypto_onetimeauth_init := GetProcAddress(DLLHandle,'crypto_onetimeauth_init');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_init <> nil);
  {$ENDIF}
    @crypto_onetimeauth_update := GetProcAddress(DLLHandle,'crypto_onetimeauth_update');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_update <> nil);
  {$ENDIF}
    @crypto_onetimeauth_final := GetProcAddress(DLLHandle,'crypto_onetimeauth_final');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_final <> nil);
  {$ENDIF}
    @crypto_onetimeauth_poly1305_bytes := GetProcAddress(DLLHandle,'crypto_onetimeauth_poly1305_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_poly1305_bytes <> nil);
  {$ENDIF}
    @crypto_onetimeauth_poly1305_keybytes := GetProcAddress(DLLHandle,'crypto_onetimeauth_poly1305_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_poly1305_keybytes <> nil);
  {$ENDIF}
    @crypto_onetimeauth_poly1305_implementation_name := GetProcAddress(DLLHandle,'crypto_onetimeauth_poly1305_implementation_name');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_poly1305_implementation_name <> nil);
  {$ENDIF}
    @crypto_onetimeauth_poly1305_set_implementation := GetProcAddress(DLLHandle,'crypto_onetimeauth_poly1305_set_implementation');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_poly1305_set_implementation <> nil);
  {$ENDIF}
//    @crypto_onetimeauth_pick_best_implementation := GetProcAddress(DLLHandle,'crypto_onetimeauth_pick_best_implementation');
//  {$IFDEF WIN32}
//    Assert(@crypto_onetimeauth_pick_best_implementation <> nil);
//  {$ENDIF}
    @crypto_onetimeauth_poly1305 := GetProcAddress(DLLHandle,'crypto_onetimeauth_poly1305');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_poly1305 <> nil);
  {$ENDIF}
    @crypto_onetimeauth_poly1305_verify := GetProcAddress(DLLHandle,'crypto_onetimeauth_poly1305_verify');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_poly1305_verify <> nil);
  {$ENDIF}
    @crypto_onetimeauth_poly1305_init := GetProcAddress(DLLHandle,'crypto_onetimeauth_poly1305_init');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_poly1305_init <> nil);
  {$ENDIF}
    @crypto_onetimeauth_poly1305_update := GetProcAddress(DLLHandle,'crypto_onetimeauth_poly1305_update');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_poly1305_update <> nil);
  {$ENDIF}
    @crypto_onetimeauth_poly1305_final := GetProcAddress(DLLHandle,'crypto_onetimeauth_poly1305_final');
  {$IFDEF WIN32}
    Assert(@crypto_onetimeauth_poly1305_final <> nil);
  {$ENDIF}
    @crypto_pwhash_scryptsalsa208sha256_saltbytes := GetProcAddress(DLLHandle,'crypto_pwhash_scryptsalsa208sha256_saltbytes');
  {$IFDEF WIN32}
    Assert(@crypto_pwhash_scryptsalsa208sha256_saltbytes <> nil);
  {$ENDIF}
    @crypto_pwhash_scryptsalsa208sha256_strbytes := GetProcAddress(DLLHandle,'crypto_pwhash_scryptsalsa208sha256_strbytes');
  {$IFDEF WIN32}
    Assert(@crypto_pwhash_scryptsalsa208sha256_strbytes <> nil);
  {$ENDIF}
    @crypto_pwhash_scryptsalsa208sha256_strprefix := GetProcAddress(DLLHandle,'crypto_pwhash_scryptsalsa208sha256_strprefix');
  {$IFDEF WIN32}
    Assert(@crypto_pwhash_scryptsalsa208sha256_strprefix <> nil);
  {$ENDIF}
    @crypto_pwhash_scryptsalsa208sha256_opslimit_interactive := GetProcAddress(DLLHandle,'crypto_pwhash_scryptsalsa208sha256_opslimit_interactive');
  {$IFDEF WIN32}
    Assert(@crypto_pwhash_scryptsalsa208sha256_opslimit_interactive <> nil);
  {$ENDIF}
    @crypto_pwhash_scryptsalsa208sha256_memlimit_interactive := GetProcAddress(DLLHandle,'crypto_pwhash_scryptsalsa208sha256_memlimit_interactive');
  {$IFDEF WIN32}
    Assert(@crypto_pwhash_scryptsalsa208sha256_memlimit_interactive <> nil);
  {$ENDIF}
    @crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive := GetProcAddress(DLLHandle,'crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive');
  {$IFDEF WIN32}
    Assert(@crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive <> nil);
  {$ENDIF}
    @crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive := GetProcAddress(DLLHandle,'crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive');
  {$IFDEF WIN32}
    Assert(@crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive <> nil);
  {$ENDIF}
    @crypto_pwhash_scryptsalsa208sha256 := GetProcAddress(DLLHandle,'crypto_pwhash_scryptsalsa208sha256');
  {$IFDEF WIN32}
    Assert(@crypto_pwhash_scryptsalsa208sha256 <> nil);
  {$ENDIF}
    @crypto_pwhash_scryptsalsa208sha256_str := GetProcAddress(DLLHandle,'crypto_pwhash_scryptsalsa208sha256_str');
  {$IFDEF WIN32}
    Assert(@crypto_pwhash_scryptsalsa208sha256_str <> nil);
  {$ENDIF}
    @crypto_pwhash_scryptsalsa208sha256_str_verify := GetProcAddress(DLLHandle,'crypto_pwhash_scryptsalsa208sha256_str_verify');
  {$IFDEF WIN32}
    Assert(@crypto_pwhash_scryptsalsa208sha256_str_verify <> nil);
  {$ENDIF}
    @crypto_pwhash_scryptsalsa208sha256_ll := GetProcAddress(DLLHandle,'crypto_pwhash_scryptsalsa208sha256_ll');
  {$IFDEF WIN32}
    Assert(@crypto_pwhash_scryptsalsa208sha256_ll <> nil);
  {$ENDIF}
    @crypto_scalarmult_bytes := GetProcAddress(DLLHandle,'crypto_scalarmult_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_scalarmult_bytes <> nil);
  {$ENDIF}
    @crypto_scalarmult_scalarbytes := GetProcAddress(DLLHandle,'crypto_scalarmult_scalarbytes');
  {$IFDEF WIN32}
    Assert(@crypto_scalarmult_scalarbytes <> nil);
  {$ENDIF}
    @crypto_scalarmult_primitive := GetProcAddress(DLLHandle,'crypto_scalarmult_primitive');
  {$IFDEF WIN32}
    Assert(@crypto_scalarmult_primitive <> nil);
  {$ENDIF}
    @crypto_scalarmult_base := GetProcAddress(DLLHandle,'crypto_scalarmult_base');
  {$IFDEF WIN32}
    Assert(@crypto_scalarmult_base <> nil);
  {$ENDIF}
    @crypto_scalarmult := GetProcAddress(DLLHandle,'crypto_scalarmult');
  {$IFDEF WIN32}
    Assert(@crypto_scalarmult <> nil);
  {$ENDIF}
    @crypto_scalarmult_curve25519_bytes := GetProcAddress(DLLHandle,'crypto_scalarmult_curve25519_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_scalarmult_curve25519_bytes <> nil);
  {$ENDIF}
    @crypto_scalarmult_curve25519_scalarbytes := GetProcAddress(DLLHandle,'crypto_scalarmult_curve25519_scalarbytes');
  {$IFDEF WIN32}
    Assert(@crypto_scalarmult_curve25519_scalarbytes <> nil);
  {$ENDIF}
    @crypto_scalarmult_curve25519 := GetProcAddress(DLLHandle,'crypto_scalarmult_curve25519');
  {$IFDEF WIN32}
    Assert(@crypto_scalarmult_curve25519 <> nil);
  {$ENDIF}
    @crypto_scalarmult_curve25519_base := GetProcAddress(DLLHandle,'crypto_scalarmult_curve25519_base');
  {$IFDEF WIN32}
    Assert(@crypto_scalarmult_curve25519_base <> nil);
  {$ENDIF}
    @crypto_secretbox_keybytes := GetProcAddress(DLLHandle,'crypto_secretbox_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_keybytes <> nil);
  {$ENDIF}
    @crypto_secretbox_noncebytes := GetProcAddress(DLLHandle,'crypto_secretbox_noncebytes');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_noncebytes <> nil);
  {$ENDIF}
    @crypto_secretbox_macbytes := GetProcAddress(DLLHandle,'crypto_secretbox_macbytes');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_macbytes <> nil);
  {$ENDIF}
    @crypto_secretbox_primitive := GetProcAddress(DLLHandle,'crypto_secretbox_primitive');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_primitive <> nil);
  {$ENDIF}
    @crypto_secretbox_easy := GetProcAddress(DLLHandle,'crypto_secretbox_easy');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_easy <> nil);
  {$ENDIF}
    @crypto_secretbox_open_easy := GetProcAddress(DLLHandle,'crypto_secretbox_open_easy');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_open_easy <> nil);
  {$ENDIF}
    @crypto_secretbox_detached := GetProcAddress(DLLHandle,'crypto_secretbox_detached');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_detached <> nil);
  {$ENDIF}
    @crypto_secretbox_open_detached := GetProcAddress(DLLHandle,'crypto_secretbox_open_detached');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_open_detached <> nil);
  {$ENDIF}
    @crypto_secretbox_zerobytes := GetProcAddress(DLLHandle,'crypto_secretbox_zerobytes');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_zerobytes <> nil);
  {$ENDIF}
    @crypto_secretbox_boxzerobytes := GetProcAddress(DLLHandle,'crypto_secretbox_boxzerobytes');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_boxzerobytes <> nil);
  {$ENDIF}
    @crypto_secretbox := GetProcAddress(DLLHandle,'crypto_secretbox');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox <> nil);
  {$ENDIF}
    @crypto_secretbox_open := GetProcAddress(DLLHandle,'crypto_secretbox_open');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_open <> nil);
  {$ENDIF}
    @crypto_secretbox_xsalsa20poly1305_keybytes := GetProcAddress(DLLHandle,'crypto_secretbox_xsalsa20poly1305_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_xsalsa20poly1305_keybytes <> nil);
  {$ENDIF}
    @crypto_secretbox_xsalsa20poly1305_noncebytes := GetProcAddress(DLLHandle,'crypto_secretbox_xsalsa20poly1305_noncebytes');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_xsalsa20poly1305_noncebytes <> nil);
  {$ENDIF}
    @crypto_secretbox_xsalsa20poly1305_zerobytes := GetProcAddress(DLLHandle,'crypto_secretbox_xsalsa20poly1305_zerobytes');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_xsalsa20poly1305_zerobytes <> nil);
  {$ENDIF}
    @crypto_secretbox_xsalsa20poly1305_boxzerobytes := GetProcAddress(DLLHandle,'crypto_secretbox_xsalsa20poly1305_boxzerobytes');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_xsalsa20poly1305_boxzerobytes <> nil);
  {$ENDIF}
    @crypto_secretbox_xsalsa20poly1305_macbytes := GetProcAddress(DLLHandle,'crypto_secretbox_xsalsa20poly1305_macbytes');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_xsalsa20poly1305_macbytes <> nil);
  {$ENDIF}
    @crypto_secretbox_xsalsa20poly1305 := GetProcAddress(DLLHandle,'crypto_secretbox_xsalsa20poly1305');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_xsalsa20poly1305 <> nil);
  {$ENDIF}
    @crypto_secretbox_xsalsa20poly1305_open := GetProcAddress(DLLHandle,'crypto_secretbox_xsalsa20poly1305_open');
  {$IFDEF WIN32}
    Assert(@crypto_secretbox_xsalsa20poly1305_open <> nil);
  {$ENDIF}
    @crypto_shorthash_bytes := GetProcAddress(DLLHandle,'crypto_shorthash_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_shorthash_bytes <> nil);
  {$ENDIF}
    @crypto_shorthash_keybytes := GetProcAddress(DLLHandle,'crypto_shorthash_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_shorthash_keybytes <> nil);
  {$ENDIF}
    @crypto_shorthash_primitive := GetProcAddress(DLLHandle,'crypto_shorthash_primitive');
  {$IFDEF WIN32}
    Assert(@crypto_shorthash_primitive <> nil);
  {$ENDIF}
    @crypto_shorthash := GetProcAddress(DLLHandle,'crypto_shorthash');
  {$IFDEF WIN32}
    Assert(@crypto_shorthash <> nil);
  {$ENDIF}
    @crypto_shorthash_siphash24_bytes := GetProcAddress(DLLHandle,'crypto_shorthash_siphash24_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_shorthash_siphash24_bytes <> nil);
  {$ENDIF}
    @crypto_shorthash_siphash24_keybytes := GetProcAddress(DLLHandle,'crypto_shorthash_siphash24_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_shorthash_siphash24_keybytes <> nil);
  {$ENDIF}
    @crypto_shorthash_siphash24 := GetProcAddress(DLLHandle,'crypto_shorthash_siphash24');
  {$IFDEF WIN32}
    Assert(@crypto_shorthash_siphash24 <> nil);
  {$ENDIF}
    @crypto_sign_bytes := GetProcAddress(DLLHandle,'crypto_sign_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_sign_bytes <> nil);
  {$ENDIF}
    @crypto_sign_seedbytes := GetProcAddress(DLLHandle,'crypto_sign_seedbytes');
  {$IFDEF WIN32}
    Assert(@crypto_sign_seedbytes <> nil);
  {$ENDIF}
    @crypto_sign_publickeybytes := GetProcAddress(DLLHandle,'crypto_sign_publickeybytes');
  {$IFDEF WIN32}
    Assert(@crypto_sign_publickeybytes <> nil);
  {$ENDIF}
    @crypto_sign_secretkeybytes := GetProcAddress(DLLHandle,'crypto_sign_secretkeybytes');
  {$IFDEF WIN32}
    Assert(@crypto_sign_secretkeybytes <> nil);
  {$ENDIF}
    @crypto_sign_primitive := GetProcAddress(DLLHandle,'crypto_sign_primitive');
  {$IFDEF WIN32}
    Assert(@crypto_sign_primitive <> nil);
  {$ENDIF}
    @crypto_sign_seed_keypair := GetProcAddress(DLLHandle,'crypto_sign_seed_keypair');
  {$IFDEF WIN32}
    Assert(@crypto_sign_seed_keypair <> nil);
  {$ENDIF}
    @crypto_sign_keypair := GetProcAddress(DLLHandle,'crypto_sign_keypair');
  {$IFDEF WIN32}
    Assert(@crypto_sign_keypair <> nil);
  {$ENDIF}
    @crypto_sign := GetProcAddress(DLLHandle,'crypto_sign');
  {$IFDEF WIN32}
    Assert(@crypto_sign <> nil);
  {$ENDIF}
    @crypto_sign_open := GetProcAddress(DLLHandle,'crypto_sign_open');
  {$IFDEF WIN32}
    Assert(@crypto_sign_open <> nil);
  {$ENDIF}
    @crypto_sign_detached := GetProcAddress(DLLHandle,'crypto_sign_detached');
  {$IFDEF WIN32}
    Assert(@crypto_sign_detached <> nil);
  {$ENDIF}
    @crypto_sign_verify_detached := GetProcAddress(DLLHandle,'crypto_sign_verify_detached');
  {$IFDEF WIN32}
    Assert(@crypto_sign_verify_detached <> nil);
  {$ENDIF}
    @crypto_sign_ed25519_bytes := GetProcAddress(DLLHandle,'crypto_sign_ed25519_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_sign_ed25519_bytes <> nil);
  {$ENDIF}
    @crypto_sign_ed25519_seedbytes := GetProcAddress(DLLHandle,'crypto_sign_ed25519_seedbytes');
  {$IFDEF WIN32}
    Assert(@crypto_sign_ed25519_seedbytes <> nil);
  {$ENDIF}
    @crypto_sign_ed25519_publickeybytes := GetProcAddress(DLLHandle,'crypto_sign_ed25519_publickeybytes');
  {$IFDEF WIN32}
    Assert(@crypto_sign_ed25519_publickeybytes <> nil);
  {$ENDIF}
    @crypto_sign_ed25519_secretkeybytes := GetProcAddress(DLLHandle,'crypto_sign_ed25519_secretkeybytes');
  {$IFDEF WIN32}
    Assert(@crypto_sign_ed25519_secretkeybytes <> nil);
  {$ENDIF}
    @crypto_sign_ed25519 := GetProcAddress(DLLHandle,'crypto_sign_ed25519');
  {$IFDEF WIN32}
    Assert(@crypto_sign_ed25519 <> nil);
  {$ENDIF}
    @crypto_sign_ed25519_open := GetProcAddress(DLLHandle,'crypto_sign_ed25519_open');
  {$IFDEF WIN32}
    Assert(@crypto_sign_ed25519_open <> nil);
  {$ENDIF}
    @crypto_sign_ed25519_detached := GetProcAddress(DLLHandle,'crypto_sign_ed25519_detached');
  {$IFDEF WIN32}
    Assert(@crypto_sign_ed25519_detached <> nil);
  {$ENDIF}
    @crypto_sign_ed25519_verify_detached := GetProcAddress(DLLHandle,'crypto_sign_ed25519_verify_detached');
  {$IFDEF WIN32}
    Assert(@crypto_sign_ed25519_verify_detached <> nil);
  {$ENDIF}
    @crypto_sign_ed25519_keypair := GetProcAddress(DLLHandle,'crypto_sign_ed25519_keypair');
  {$IFDEF WIN32}
    Assert(@crypto_sign_ed25519_keypair <> nil);
  {$ENDIF}
    @crypto_sign_ed25519_seed_keypair := GetProcAddress(DLLHandle,'crypto_sign_ed25519_seed_keypair');
  {$IFDEF WIN32}
    Assert(@crypto_sign_ed25519_seed_keypair <> nil);
  {$ENDIF}
    @crypto_sign_ed25519_pk_to_curve25519 := GetProcAddress(DLLHandle,'crypto_sign_ed25519_pk_to_curve25519');
  {$IFDEF WIN32}
    Assert(@crypto_sign_ed25519_pk_to_curve25519 <> nil);
  {$ENDIF}
    @crypto_sign_ed25519_sk_to_curve25519 := GetProcAddress(DLLHandle,'crypto_sign_ed25519_sk_to_curve25519');
  {$IFDEF WIN32}
    Assert(@crypto_sign_ed25519_sk_to_curve25519 <> nil);
  {$ENDIF}
    @crypto_sign_ed25519_sk_to_seed := GetProcAddress(DLLHandle,'crypto_sign_ed25519_sk_to_seed');
  {$IFDEF WIN32}
    Assert(@crypto_sign_ed25519_sk_to_seed <> nil);
  {$ENDIF}
    @crypto_sign_ed25519_sk_to_pk := GetProcAddress(DLLHandle,'crypto_sign_ed25519_sk_to_pk');
  {$IFDEF WIN32}
    Assert(@crypto_sign_ed25519_sk_to_pk <> nil);
  {$ENDIF}
    @crypto_sign_edwards25519sha512batch_bytes := GetProcAddress(DLLHandle,'crypto_sign_edwards25519sha512batch_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_sign_edwards25519sha512batch_bytes <> nil);
  {$ENDIF}
    @crypto_sign_edwards25519sha512batch_publickeybytes := GetProcAddress(DLLHandle,'crypto_sign_edwards25519sha512batch_publickeybytes');
  {$IFDEF WIN32}
    Assert(@crypto_sign_edwards25519sha512batch_publickeybytes <> nil);
  {$ENDIF}
    @crypto_sign_edwards25519sha512batch_secretkeybytes := GetProcAddress(DLLHandle,'crypto_sign_edwards25519sha512batch_secretkeybytes');
  {$IFDEF WIN32}
    Assert(@crypto_sign_edwards25519sha512batch_secretkeybytes <> nil);
  {$ENDIF}
    @crypto_sign_edwards25519sha512batch := GetProcAddress(DLLHandle,'crypto_sign_edwards25519sha512batch');
  {$IFDEF WIN32}
    Assert(@crypto_sign_edwards25519sha512batch <> nil);
  {$ENDIF}
    @crypto_sign_edwards25519sha512batch_open := GetProcAddress(DLLHandle,'crypto_sign_edwards25519sha512batch_open');
  {$IFDEF WIN32}
    Assert(@crypto_sign_edwards25519sha512batch_open <> nil);
  {$ENDIF}
    @crypto_sign_edwards25519sha512batch_keypair := GetProcAddress(DLLHandle,'crypto_sign_edwards25519sha512batch_keypair');
  {$IFDEF WIN32}
    Assert(@crypto_sign_edwards25519sha512batch_keypair <> nil);
  {$ENDIF}
    @crypto_stream_keybytes := GetProcAddress(DLLHandle,'crypto_stream_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_keybytes <> nil);
  {$ENDIF}
    @crypto_stream_noncebytes := GetProcAddress(DLLHandle,'crypto_stream_noncebytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_noncebytes <> nil);
  {$ENDIF}
    @crypto_stream_primitive := GetProcAddress(DLLHandle,'crypto_stream_primitive');
  {$IFDEF WIN32}
    Assert(@crypto_stream_primitive <> nil);
  {$ENDIF}
    @crypto_stream := GetProcAddress(DLLHandle,'crypto_stream');
  {$IFDEF WIN32}
    Assert(@crypto_stream <> nil);
  {$ENDIF}
    @crypto_stream_xor := GetProcAddress(DLLHandle,'crypto_stream_xor');
  {$IFDEF WIN32}
    Assert(@crypto_stream_xor <> nil);
  {$ENDIF}
    @crypto_stream_aes128ctr_keybytes := GetProcAddress(DLLHandle,'crypto_stream_aes128ctr_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_aes128ctr_keybytes <> nil);
  {$ENDIF}
    @crypto_stream_aes128ctr_noncebytes := GetProcAddress(DLLHandle,'crypto_stream_aes128ctr_noncebytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_aes128ctr_noncebytes <> nil);
  {$ENDIF}
    @crypto_stream_aes128ctr_beforenmbytes := GetProcAddress(DLLHandle,'crypto_stream_aes128ctr_beforenmbytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_aes128ctr_beforenmbytes <> nil);
  {$ENDIF}
    @crypto_stream_aes128ctr := GetProcAddress(DLLHandle,'crypto_stream_aes128ctr');
  {$IFDEF WIN32}
    Assert(@crypto_stream_aes128ctr <> nil);
  {$ENDIF}
    @crypto_stream_aes128ctr_xor := GetProcAddress(DLLHandle,'crypto_stream_aes128ctr_xor');
  {$IFDEF WIN32}
    Assert(@crypto_stream_aes128ctr_xor <> nil);
  {$ENDIF}
    @crypto_stream_aes128ctr_beforenm := GetProcAddress(DLLHandle,'crypto_stream_aes128ctr_beforenm');
  {$IFDEF WIN32}
    Assert(@crypto_stream_aes128ctr_beforenm <> nil);
  {$ENDIF}
    @crypto_stream_aes128ctr_afternm := GetProcAddress(DLLHandle,'crypto_stream_aes128ctr_afternm');
  {$IFDEF WIN32}
    Assert(@crypto_stream_aes128ctr_afternm <> nil);
  {$ENDIF}
    @crypto_stream_aes128ctr_xor_afternm := GetProcAddress(DLLHandle,'crypto_stream_aes128ctr_xor_afternm');
  {$IFDEF WIN32}
    Assert(@crypto_stream_aes128ctr_xor_afternm <> nil);
  {$ENDIF}
    @crypto_stream_chacha20_keybytes := GetProcAddress(DLLHandle,'crypto_stream_chacha20_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_chacha20_keybytes <> nil);
  {$ENDIF}
    @crypto_stream_chacha20_noncebytes := GetProcAddress(DLLHandle,'crypto_stream_chacha20_noncebytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_chacha20_noncebytes <> nil);
  {$ENDIF}
    @crypto_stream_chacha20 := GetProcAddress(DLLHandle,'crypto_stream_chacha20');
  {$IFDEF WIN32}
    Assert(@crypto_stream_chacha20 <> nil);
  {$ENDIF}
    @crypto_stream_chacha20_xor := GetProcAddress(DLLHandle,'crypto_stream_chacha20_xor');
  {$IFDEF WIN32}
    Assert(@crypto_stream_chacha20_xor <> nil);
  {$ENDIF}
    @crypto_stream_chacha20_xor_ic := GetProcAddress(DLLHandle,'crypto_stream_chacha20_xor_ic');
  {$IFDEF WIN32}
    Assert(@crypto_stream_chacha20_xor_ic <> nil);
  {$ENDIF}
    @crypto_stream_salsa20_keybytes := GetProcAddress(DLLHandle,'crypto_stream_salsa20_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_salsa20_keybytes <> nil);
  {$ENDIF}
    @crypto_stream_salsa20_noncebytes := GetProcAddress(DLLHandle,'crypto_stream_salsa20_noncebytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_salsa20_noncebytes <> nil);
  {$ENDIF}
    @crypto_stream_salsa20 := GetProcAddress(DLLHandle,'crypto_stream_salsa20');
  {$IFDEF WIN32}
    Assert(@crypto_stream_salsa20 <> nil);
  {$ENDIF}
    @crypto_stream_salsa20_xor := GetProcAddress(DLLHandle,'crypto_stream_salsa20_xor');
  {$IFDEF WIN32}
    Assert(@crypto_stream_salsa20_xor <> nil);
  {$ENDIF}
    @crypto_stream_salsa20_xor_ic := GetProcAddress(DLLHandle,'crypto_stream_salsa20_xor_ic');
  {$IFDEF WIN32}
    Assert(@crypto_stream_salsa20_xor_ic <> nil);
  {$ENDIF}
    @crypto_stream_salsa2012_keybytes := GetProcAddress(DLLHandle,'crypto_stream_salsa2012_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_salsa2012_keybytes <> nil);
  {$ENDIF}
    @crypto_stream_salsa2012_noncebytes := GetProcAddress(DLLHandle,'crypto_stream_salsa2012_noncebytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_salsa2012_noncebytes <> nil);
  {$ENDIF}
    @crypto_stream_salsa2012 := GetProcAddress(DLLHandle,'crypto_stream_salsa2012');
  {$IFDEF WIN32}
    Assert(@crypto_stream_salsa2012 <> nil);
  {$ENDIF}
    @crypto_stream_salsa2012_xor := GetProcAddress(DLLHandle,'crypto_stream_salsa2012_xor');
  {$IFDEF WIN32}
    Assert(@crypto_stream_salsa2012_xor <> nil);
  {$ENDIF}
    @crypto_stream_salsa208_keybytes := GetProcAddress(DLLHandle,'crypto_stream_salsa208_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_salsa208_keybytes <> nil);
  {$ENDIF}
    @crypto_stream_salsa208_noncebytes := GetProcAddress(DLLHandle,'crypto_stream_salsa208_noncebytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_salsa208_noncebytes <> nil);
  {$ENDIF}
    @crypto_stream_salsa208 := GetProcAddress(DLLHandle,'crypto_stream_salsa208');
  {$IFDEF WIN32}
    Assert(@crypto_stream_salsa208 <> nil);
  {$ENDIF}
    @crypto_stream_salsa208_xor := GetProcAddress(DLLHandle,'crypto_stream_salsa208_xor');
  {$IFDEF WIN32}
    Assert(@crypto_stream_salsa208_xor <> nil);
  {$ENDIF}
    @crypto_stream_xsalsa20_keybytes := GetProcAddress(DLLHandle,'crypto_stream_xsalsa20_keybytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_xsalsa20_keybytes <> nil);
  {$ENDIF}
    @crypto_stream_xsalsa20_noncebytes := GetProcAddress(DLLHandle,'crypto_stream_xsalsa20_noncebytes');
  {$IFDEF WIN32}
    Assert(@crypto_stream_xsalsa20_noncebytes <> nil);
  {$ENDIF}
    @crypto_stream_xsalsa20 := GetProcAddress(DLLHandle,'crypto_stream_xsalsa20');
  {$IFDEF WIN32}
    Assert(@crypto_stream_xsalsa20 <> nil);
  {$ENDIF}
    @crypto_stream_xsalsa20_xor := GetProcAddress(DLLHandle,'crypto_stream_xsalsa20_xor');
  {$IFDEF WIN32}
    Assert(@crypto_stream_xsalsa20_xor <> nil);
  {$ENDIF}
    @crypto_stream_xsalsa20_xor_ic := GetProcAddress(DLLHandle,'crypto_stream_xsalsa20_xor_ic');
  {$IFDEF WIN32}
    Assert(@crypto_stream_xsalsa20_xor_ic <> nil);
  {$ENDIF}
    @crypto_verify_16_bytes := GetProcAddress(DLLHandle,'crypto_verify_16_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_verify_16_bytes <> nil);
  {$ENDIF}
    @crypto_verify_16 := GetProcAddress(DLLHandle,'crypto_verify_16');
  {$IFDEF WIN32}
    Assert(@crypto_verify_16 <> nil);
  {$ENDIF}
    @crypto_verify_32_bytes := GetProcAddress(DLLHandle,'crypto_verify_32_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_verify_32_bytes <> nil);
  {$ENDIF}
    @crypto_verify_32 := GetProcAddress(DLLHandle,'crypto_verify_32');
  {$IFDEF WIN32}
    Assert(@crypto_verify_32 <> nil);
  {$ENDIF}
    @crypto_verify_64_bytes := GetProcAddress(DLLHandle,'crypto_verify_64_bytes');
  {$IFDEF WIN32}
    Assert(@crypto_verify_64_bytes <> nil);
  {$ENDIF}
    @crypto_verify_64 := GetProcAddress(DLLHandle,'crypto_verify_64');
  {$IFDEF WIN32}
    Assert(@crypto_verify_64 <> nil);
  {$ENDIF}
    @randombytes_buf := GetProcAddress(DLLHandle,'randombytes_buf');
  {$IFDEF WIN32}
    Assert(@randombytes_buf <> nil);
  {$ENDIF}
    @randombytes_random := GetProcAddress(DLLHandle,'randombytes_random');
  {$IFDEF WIN32}
    Assert(@randombytes_random <> nil);
  {$ENDIF}
    @randombytes_uniform := GetProcAddress(DLLHandle,'randombytes_uniform');
  {$IFDEF WIN32}
    Assert(@randombytes_uniform <> nil);
  {$ENDIF}
    @randombytes_stir := GetProcAddress(DLLHandle,'randombytes_stir');
  {$IFDEF WIN32}
    Assert(@randombytes_stir <> nil);
  {$ENDIF}
    @randombytes_close := GetProcAddress(DLLHandle,'randombytes_close');
  {$IFDEF WIN32}
    Assert(@randombytes_close <> nil);
  {$ENDIF}
    @randombytes_set_implementation := GetProcAddress(DLLHandle,'randombytes_set_implementation');
  {$IFDEF WIN32}
    Assert(@randombytes_set_implementation <> nil);
  {$ENDIF}
    @randombytes_implementation_name := GetProcAddress(DLLHandle,'randombytes_implementation_name');
  {$IFDEF WIN32}
    Assert(@randombytes_implementation_name <> nil);
  {$ENDIF}
    @randombytes := GetProcAddress(DLLHandle,'randombytes');
  {$IFDEF WIN32}
    Assert(@randombytes <> nil);
  {$ENDIF}
  @randombytes_salsa20_implementation_name := GetProcAddress(DLLHandle,'randombytes_salsa20_implementation_name');
{$IFDEF WIN32}
  Assert(@randombytes_salsa20_implementation_name <> nil);
{$ENDIF}
  @randombytes_salsa20_random := GetProcAddress(DLLHandle,'randombytes_salsa20_random');
{$IFDEF WIN32}
  Assert(@randombytes_salsa20_random <> nil);
{$ENDIF}
  @randombytes_salsa20_random_stir := GetProcAddress(DLLHandle,'randombytes_salsa20_random_stir');
{$IFDEF WIN32}
  Assert(@randombytes_salsa20_random_stir <> nil);
{$ENDIF}
//  @randombytes_salsa20_random_uniform := GetProcAddress(DLLHandle,'randombytes_salsa20_random_uniform');
//{$IFDEF WIN32}
//  Assert(@randombytes_salsa20_random_uniform <> nil);
//{$ENDIF}
  @randombytes_salsa20_random_buf := GetProcAddress(DLLHandle,'randombytes_salsa20_random_buf');
{$IFDEF WIN32}
  Assert(@randombytes_salsa20_random_buf <> nil);
{$ENDIF}
  @randombytes_salsa20_random_close := GetProcAddress(DLLHandle,'randombytes_salsa20_random_close');
{$IFDEF WIN32}
  Assert(@randombytes_salsa20_random_close <> nil);
{$ENDIF}
  @randombytes_sysrandom_implementation_name := GetProcAddress(DLLHandle,'randombytes_sysrandom_implementation_name');
{$IFDEF WIN32}
  Assert(@randombytes_sysrandom_implementation_name <> nil);
{$ENDIF}
  @randombytes_sysrandom := GetProcAddress(DLLHandle,'randombytes_sysrandom');
{$IFDEF WIN32}
  Assert(@randombytes_sysrandom <> nil);
{$ENDIF}
  @randombytes_sysrandom_stir := GetProcAddress(DLLHandle,'randombytes_sysrandom_stir');
{$IFDEF WIN32}
  Assert(@randombytes_sysrandom_stir <> nil);
{$ENDIF}
//  @randombytes_sysrandom_uniform := GetProcAddress(DLLHandle,'randombytes_sysrandom_uniform');
//{$IFDEF WIN32}
//  Assert(@randombytes_sysrandom_uniform <> nil);
//{$ENDIF}
  @randombytes_sysrandom_buf := GetProcAddress(DLLHandle,'randombytes_sysrandom_buf');
{$IFDEF WIN32}
  Assert(@randombytes_sysrandom_buf <> nil);
{$ENDIF}
  @randombytes_sysrandom_close := GetProcAddress(DLLHandle,'randombytes_sysrandom_close');
{$IFDEF WIN32}
  Assert(@randombytes_sysrandom_close <> nil);
{$ENDIF}
  @sodium_runtime_get_cpu_features := GetProcAddress(DLLHandle,'sodium_runtime_get_cpu_features');
{$IFDEF WIN32}
  Assert(@sodium_runtime_get_cpu_features <> nil);
{$ENDIF}
  @sodium_runtime_has_neon := GetProcAddress(DLLHandle,'sodium_runtime_has_neon');
{$IFDEF WIN32}
  Assert(@sodium_runtime_has_neon <> nil);
{$ENDIF}
  @sodium_runtime_has_sse2 := GetProcAddress(DLLHandle,'sodium_runtime_has_sse2');
{$IFDEF WIN32}
  Assert(@sodium_runtime_has_sse2 <> nil);
{$ENDIF}
  @sodium_runtime_has_sse3 := GetProcAddress(DLLHandle,'sodium_runtime_has_sse3');
{$IFDEF WIN32}
  Assert(@sodium_runtime_has_sse3 <> nil);
{$ENDIF}
  @sodium_memzero := GetProcAddress(DLLHandle,'sodium_memzero');
{$IFDEF WIN32}
  Assert(@sodium_memzero <> nil);
{$ENDIF}
  @sodium_memcmp := GetProcAddress(DLLHandle,'sodium_memcmp');
{$IFDEF WIN32}
  Assert(@sodium_memcmp <> nil);
{$ENDIF}
  @sodium_bin2hex := GetProcAddress(DLLHandle,'sodium_bin2hex');
{$IFDEF WIN32}
  Assert(@sodium_bin2hex <> nil);
{$ENDIF}
  @sodium_hex2bin := GetProcAddress(DLLHandle,'sodium_hex2bin');
{$IFDEF WIN32}
  Assert(@sodium_hex2bin <> nil);
{$ENDIF}
  @sodium_mlock := GetProcAddress(DLLHandle,'sodium_mlock');
{$IFDEF WIN32}
  Assert(@sodium_mlock <> nil);
{$ENDIF}
  @sodium_munlock := GetProcAddress(DLLHandle,'sodium_munlock');
{$IFDEF WIN32}
  Assert(@sodium_munlock <> nil);
{$ENDIF}
  @sodium_malloc := GetProcAddress(DLLHandle,'sodium_malloc');
{$IFDEF WIN32}
  Assert(@sodium_malloc <> nil);
{$ENDIF}
  @sodium_allocarray := GetProcAddress(DLLHandle,'sodium_allocarray');
{$IFDEF WIN32}
  Assert(@sodium_allocarray <> nil);
{$ENDIF}
  @sodium_free := GetProcAddress(DLLHandle,'sodium_free');
{$IFDEF WIN32}
  Assert(@sodium_free <> nil);
{$ENDIF}
  @sodium_mprotect_noaccess := GetProcAddress(DLLHandle,'sodium_mprotect_noaccess');
{$IFDEF WIN32}
  Assert(@sodium_mprotect_noaccess <> nil);
{$ENDIF}
  @sodium_mprotect_readonly := GetProcAddress(DLLHandle,'sodium_mprotect_readonly');
{$IFDEF WIN32}
  Assert(@sodium_mprotect_readonly <> nil);
{$ENDIF}
  @sodium_mprotect_readwrite := GetProcAddress(DLLHandle,'sodium_mprotect_readwrite');
{$IFDEF WIN32}
  Assert(@sodium_mprotect_readwrite <> nil);
{$ENDIF}
//  @_sodium_alloc_init := GetProcAddress(DLLHandle,'_sodium_alloc_init');
//{$IFDEF WIN32}
//  Assert(@_sodium_alloc_init <> nil);
//{$ENDIF}
  @sodium_version_string := GetProcAddress(DLLHandle,'sodium_version_string');
{$IFDEF WIN32}
  Assert(@sodium_version_string <> nil);
{$ENDIF}
  @sodium_library_version_major := GetProcAddress(DLLHandle,'sodium_library_version_major');
{$IFDEF WIN32}
  Assert(@sodium_library_version_major <> nil);
{$ENDIF}
  @sodium_library_version_minor := GetProcAddress(DLLHandle,'sodium_library_version_minor');
{$IFDEF WIN32}
  Assert(@sodium_library_version_minor <> nil);
{$ENDIF}
  @sodium_increment := GetProcAddress(DLLHandle,'sodium_increment');  // libsodium 1.0.4
  end
  else
  begin
    sodium_dllLoaded := False;
    { Error: LIBSODIUM.DLL could not be loaded !! }
  end;
{$IFNDEF MSDOS}
  SetErrorMode(ErrorMode)
{$ENDIF}
end {LoadDLL};

begin
  LoadDLL;
end.

