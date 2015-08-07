program lsDemo;
{$apptype console}

//
// by Alexander Paul Morris, 2015-08-06
//
// demos for Delphi wrapper to libsodium.dll
//

uses SysUtils, Classes, WinTypes, LibSodium;


//http://doc.libsodium.org/advanced/sha-2_hash_function.html
//http://doc.libsodium.org/advanced/hmac-sha2.html
procedure LibSodiumHmacSha2AuthDemo;
var testMessage,hexHash: AnsiString;
    sha2Hash: array [0..ls_crypto_hash_sha256_BYTES-1] of byte;
    hmacHash: array [0..ls_crypto_auth_hmacsha256_BYTES-1] of byte;
    key: array [0..ls_crypto_auth_hmacsha256_KEYBYTES-1] of byte;
begin
  testMessage := 'my test message';

  crypto_hash_sha256(@sha2Hash, @testMessage[1], length(testMessage));
  SetLength(hexHash,ls_crypto_hash_sha256_BYTES*2+1);
  sodium_bin2hex(@hexHash[1],length(hexHash),@sha2Hash,ls_crypto_hash_sha256_BYTES);
  writeln('Sha2 Hash = ',hexHash);

  randombytes_buf(@key, sizeof(key));
  crypto_auth_hmacsha512(@hmacHash, @testMessage[1], length(testMessage), @key);
  SetLength(hexHash,ls_crypto_auth_hmacsha256_BYTES*2+1);
  sodium_bin2hex(@hexHash[1],length(hexHash),@hmacHash,ls_crypto_auth_hmacsha256_BYTES);
  writeln('HmacSha256 Hash = ',hexHash);

end;


//http://doc.libsodium.org/password_hashing/index.html
procedure LibSodiumSalsa208sha256PasswordHashingDemo;
var password,hexHash: AnsiString;
    key: array [0..ls_crypto_box_SEEDBYTES-1] of byte;
    salt: array [0..ls_crypto_pwhash_scryptsalsa208sha256_SALTBYTES-1] of byte;
    hashed_password: array [0..ls_crypto_pwhash_scryptsalsa208sha256_STRBYTES-1] of byte;
begin
  // key derivation
  randombytes_buf(@salt, sizeof(salt));
  password := 'myPassword';
  if (crypto_pwhash_scryptsalsa208sha256(@key, sizeof(key), @password[1], length(password), @salt,
                                         ls_crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
                                         ls_crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) <> 0) then begin
    Writeln('Salsa208sha256: Something went wrong... [Out of Memory?]');
   end else begin
    SetLength(hexHash,ls_crypto_box_SEEDBYTES*2+1);
    sodium_bin2hex(@hexHash[1],length(hexHash),@key,ls_crypto_box_SEEDBYTES);
    Writeln('Salsa208sha256 Password Key = ',hexHash);
    end;

  // password storage - for very sensitive passwords, you can use _SENSITIVE instead of _INTERACTIVE,
  //   but be warned, deriving a key will take about 2 seconds on a 2.8 Ghz Core i7 CPU and requires
  //   up to 1 gigabyte of dedicated RAM.
  password := 'myPassword';
  if (crypto_pwhash_scryptsalsa208sha256_str(@hashed_password, @password[1], length(password),
                                             crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
                                             crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) <> 0) then begin
    Writeln('Salsa208sha256: Something went wrong... [Out of Memory?]');
   end;
  if (crypto_pwhash_scryptsalsa208sha256_str_verify(@hashed_password, @password[1], length(password)) <> 0) then
    Writeln('Salsa208sha256: Password and Hash MISMATCH! ['+password+']') else
      Writeln('Salsa208sha256: Password and Hash Match! ['+password+']');
  password := 'MyPassword';
  if (crypto_pwhash_scryptsalsa208sha256_str_verify(@hashed_password, @password[1], length(password)) <> 0) then
    Writeln('Salsa208sha256: Password and Hash MISMATCH! ['+password+']') else
      Writeln('Salsa208sha256: Password and Hash Match! ['+password+']');

end;


//https://blake2.net/ - BLAKE2 — fast secure hashing
//  improved version of the SHA-3 finalist BLAKE. Like SHA-3, BLAKE2 offers the highest security,
//  yet is fast as MD5 on 64-bit platforms and requires at least 33% less RAM than SHA-2 or SHA-3
//  on low-end systems. The core algorithm of BLAKE2 is derived from ChaCha, a stream cipher designed
//  by Daniel J. Bernstein that has been proposed as a standard cipher for TLS.
//http://doc.libsodium.org/hashing/generic_hashing.html
procedure LibSodiumBlake2HashDemo;
var testMessage,hexHash: AnsiString;
    hash: array [0..ls_crypto_generichash_BYTES-1] of byte;
    key: array [0..ls_crypto_generichash_KEYBYTES-1] of byte;
    state: crypto_generichash_state;
begin
  randombytes_buf(@key,ls_crypto_aead_chacha20poly1305_KEYBYTES);
  testMessage := 'my very important message';
  crypto_generichash(@hash, sizeof(hash), @testMessage[1], Length(testMessage), @key, length(key));

  SetLength(hexHash,ls_crypto_generichash_BYTES*2+1);
  sodium_bin2hex(@hexHash[1],length(hexHash),@hash,ls_crypto_generichash_BYTES);
  writeln('Blake2 Hash = ',hexHash);

  crypto_generichash_init(state, @key, sizeof(key), sizeof(hash));
  testMessage := 'my very ';
  crypto_generichash_update(state, @testMessage[1], Length(testMessage));
  testMessage := 'important message';
  crypto_generichash_update(state, @testMessage[1], Length(testMessage));
  crypto_generichash_final(state, @hash, sizeof(hash));

  SetLength(hexHash,ls_crypto_generichash_BYTES*2+1);
  sodium_bin2hex(@hexHash[1],length(hexHash),@hash,ls_crypto_generichash_BYTES);
  writeln('Multi-part Blake2 Hash = ',hexHash);

end;


//NOTE: cryptBuf and testMessage can overlap, making in-place encryption possible (no need for 2 buffers).
//      However do not forget that crypto_secretbox_MACBYTES extra bytes are required
//      to prepend the tag.
//http://doc.libsodium.org/secret-key_cryptography/aead.html
procedure LibSodiumAeadChacha20poly1305Demo;
var testMessage,cryptBuf,additionalData: AnsiString;
    nonce: array [0..ls_crypto_aead_chacha20poly1305_NPUBBYTES-1] of byte;
    key: array [0..ls_crypto_aead_chacha20poly1305_KEYBYTES-1] of byte;
    cryptLen,decryptLen: UINT64;
begin
  randombytes_buf(@nonce,ls_crypto_aead_chacha20poly1305_NPUBBYTES);
  randombytes_buf(@key,ls_crypto_aead_chacha20poly1305_KEYBYTES);
  testMessage := 'my secret message';
  additionalData := 'lsAead';

  SetLength(cryptBuf,length(testMessage)+ls_crypto_aead_chacha20poly1305_ABYTES);

  crypto_aead_chacha20poly1305_encrypt(@cryptBuf[1], cryptLen, @testMessage[1], length(testMessage),
                                       @additionalData, length(additionalData), nil, @nonce, @key);

  FillChar(testMessage[1],length(testMessage),0);
  SetLength(testMessage,cryptLen-ls_crypto_aead_chacha20poly1305_ABYTES);

  //missing additionalData
  if (crypto_aead_chacha20poly1305_decrypt(@testMessage[1], decryptLen, nil, @cryptBuf[1], length(cryptBuf),
                                           nil, 0, @nonce, @key) = 0) then begin
    writeln('chacha20poly1305 decrypted message = "',testMessage,'"');
   end else writeln('chacha20poly1305 decryption/authentication failed! [correct: missing additionalData]');

  if (crypto_aead_chacha20poly1305_decrypt(@testMessage[1], decryptLen, nil, @cryptBuf[1], length(cryptBuf),
                                           @additionalData, length(additionalData), @nonce, @key) = 0) then begin
    writeln('chacha20poly1305 decrypted message = "',testMessage,'"');
   end else writeln('chacha20poly1305 decryption/authentication failed!');

end;


//NOTE: cryptBuf and testMessage can overlap, making in-place encryption possible (no need for 2 buffers).
//      However do not forget that crypto_secretbox_MACBYTES extra bytes are required
//      to prepend the tag.
//http://doc.libsodium.org/secret-key_cryptography/authenticated_encryption.html
procedure LibSodiumCryptoSecretBoxDemo;
var testMessage,cryptBuf: AnsiString;
    nonce: array [0..ls_crypto_secretbox_NONCEBYTES-1] of byte;
    key: array [0..ls_crypto_secretbox_KEYBYTES-1] of byte;
    cryptLen: UINT64;
    intNonce: UINT64 absolute nonce;  //nonce is 8 bytes, so can be directly mapped to a UINT64
begin
  randombytes_buf(@nonce,ls_crypto_secretbox_NONCEBYTES);
  randombytes_buf(@key,ls_crypto_secretbox_KEYBYTES);
  testMessage := 'my secret message';

  cryptLen := length(testMessage)+ls_crypto_secretbox_MACBYTES;
  SetLength(cryptBuf,cryptLen);

  crypto_secretbox_easy(@cryptBuf[1], @testMessage[1], length(testMessage), @nonce, @key);

  FillChar(testMessage[1],length(testMessage),0);
  SetLength(testMessage,cryptLen-ls_crypto_secretbox_MACBYTES);

  intNonce := intNonce + 1;

  if (crypto_secretbox_open_easy(@testMessage[1], @cryptBuf[1], length(cryptBuf), @nonce, @key) = 0) then begin
    writeln('secretbox decrypted message = "',testMessage,'"');
   end else writeln('secretbox decryption/authentication failed! [correct: wrong nonce]');

  intNonce := intNonce - 1;

  if (crypto_secretbox_open_easy(@testMessage[1], @cryptBuf[1], length(cryptBuf), @nonce, @key) = 0) then begin
    writeln('secretbox decrypted message = "',testMessage,'"');
   end else writeln('secretbox decryption/authentication failed!');

end;


//http://doc.libsodium.org/secret-key_cryptography/secret-key_authentication.html
procedure LibSodiumCryptoAuthDemo;
var testMessage,cryptBuf,hexMac: AnsiString;
    mac: array [0..ls_crypto_auth_BYTES-1] of byte;
    key: array [0..ls_crypto_auth_KEYBYTES-1] of byte;
    binLen: DWORD{dwSIZE_T};
begin
  randombytes_buf(@mac,ls_crypto_auth_BYTES);
  randombytes_buf(@key,ls_crypto_auth_KEYBYTES);
  testMessage := 'my authenticated message';

  crypto_auth(@mac, @testMessage[1], length(testMessage), @key);

  //http://doc.libsodium.org/helpers/index.html
  SetLength(hexMac,ls_crypto_auth_BYTES*2+1);
  sodium_bin2hex(@hexMac[1],length(hexMac),@mac,ls_crypto_auth_BYTES);

  writeln('auth macHex = ',hexMac);

  FillChar(mac,sizeof(mac),0);
  sodium_hex2bin(@mac,ls_crypto_auth_BYTES,@hexMac[1],length(hexMac),nil,binLen,nil);

  if (crypto_auth_verify(@mac, @testMessage[1], length(testMessage), @key) = 0) then begin
    writeln('auth authenticated message = "',testMessage,'"');
   end else writeln('auth authentication failed!');

end;


//http://doc.libsodium.org/advanced/scalar_multiplication.html
//Curve25519, a state-of-the-art Diffie-Hellman function suitable for a wide variety of applications
procedure LibSodiumCryptoDHCurve25519Demo;
var client_publickey,server_publickey: array [0..ls_crypto_box_PUBLICKEYBYTES-1] of byte;
    client_secretkey,server_secretkey: array [0..ls_crypto_box_SECRETKEYBYTES-1] of byte;
    scalarmult_q_by_client,scalarmult_q_by_server: array [0..ls_crypto_scalarmult_BYTES-1] of byte;
    sharedkey_by_client,sharedkey_by_server: array [0..ls_crypto_generichash_BYTES-1] of byte;
    h: crypto_generichash_state;
    hexBuf: AnsiString;
begin
  // Create client's secret and public keys
  randombytes(@client_secretkey, sizeof(client_secretkey));
  crypto_scalarmult_base(@client_publickey, @client_secretkey);

  // Create server's secret and public keys
  randombytes(@server_secretkey, sizeof(server_secretkey));
  crypto_scalarmult_base(@server_publickey, @server_secretkey);

  SetLength(hexBuf,ls_crypto_box_PUBLICKEYBYTES*2+1);
  sodium_bin2hex(@hexBuf[1],length(hexBuf),@server_publickey,ls_crypto_box_PUBLICKEYBYTES);
  writeln('Curve25519: server_publickey = ',hexBuf);

  sodium_bin2hex(@hexBuf[1],length(hexBuf),@client_publickey,ls_crypto_box_PUBLICKEYBYTES);
  writeln('Curve25519: client_publickey = ',hexBuf);

  // The client derives a shared key from its secret key and the server's public key
  // shared key = h(q || client_publickey || server_publickey)
  crypto_scalarmult(@scalarmult_q_by_client, @client_secretkey, @server_publickey);
  crypto_generichash_init(h, nil, 0, ls_crypto_generichash_BYTES);
  crypto_generichash_update(h, @scalarmult_q_by_client, sizeof(scalarmult_q_by_client));
  crypto_generichash_update(h, @client_publickey, sizeof(client_publickey));
  crypto_generichash_update(h, @server_publickey, sizeof(server_publickey));
  crypto_generichash_final(h, @sharedkey_by_client, sizeof(sharedkey_by_client));

  // The server derives a shared key from its secret key and the client's public key
  // shared key = h(q || client_publickey || server_publickey)
  crypto_scalarmult(@scalarmult_q_by_server, @server_secretkey, @client_publickey);
  crypto_generichash_init(h, nil, 0, ls_crypto_generichash_BYTES);
  crypto_generichash_update(h, @scalarmult_q_by_server, sizeof(scalarmult_q_by_server));
  crypto_generichash_update(h, @client_publickey, sizeof(client_publickey));
  crypto_generichash_update(h, @server_publickey, sizeof(server_publickey));
  crypto_generichash_final(h, @sharedkey_by_server, sizeof(sharedkey_by_server));

  // sharedkey_by_client and sharedkey_by_server are identical

  if (sodium_memcmp(@sharedkey_by_client,@sharedkey_by_server,ls_crypto_generichash_BYTES) = 0) then begin
    SetLength(hexBuf,ls_crypto_generichash_BYTES*2+1);
    sodium_bin2hex(@hexBuf[1],length(hexBuf),@sharedkey_by_client,ls_crypto_box_PUBLICKEYBYTES);
    writeln('Curve25519: SUCCESS :: sharedPrivateKey = ',hexBuf);
   end else writeln('Curve25519: FAILED :: Shared Key Mismatch');

end;


procedure LibSodiumRandomDemo;
var buf: array[0..7] of byte;
    i: integer;
begin

  write('randombytes_buf(8) = ');
  randombytes_buf(@buf,8);
  for i:= 0 to 7 do write(buf[i],' '); writeln;

  write('randombytes_buf(8) = ');
  randombytes_buf(@buf,8);
  for i:= 0 to 7 do write(buf[i],' '); writeln;

  writeln('randombytes_uniform(0..1000) = ',randombytes_uniform(1000));
  writeln('randombytes_uniform(0..1000000) = ',randombytes_uniform(1000000));
  writeln('randombytes_uniform(0..1000000000) = ',randombytes_uniform(1000000000));
end;


procedure TestLibSodium;
var lsHandle: integer;
    rb: randombytes_implementation;
    buf: array[0..7] of byte;
    i: integer;
begin
  lsHandle := sodium_init;

  writeln('delphi wrapper/bridge to libsodium.dll version = ',sodium_version_string);
  writeln;

  LibSodiumRandomDemo;
  writeln;

  LibSodiumHmacSha2AuthDemo;
  Writeln;

  LibSodiumAeadChacha20poly1305Demo;
  writeln;

  LibSodiumCryptoSecretBoxDemo;
  writeln;

  LibSodiumCryptoAuthDemo;
  writeln;

  LibSodiumCryptoDHCurve25519Demo;
  writeln;

  LibSodiumBlake2HashDemo;
  writeln;

  LibSodiumSalsa208sha256PasswordHashingDemo;
  writeln;

end;


//main
begin
  TestLibSodium;
end.

