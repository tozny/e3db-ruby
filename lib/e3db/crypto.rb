#
# crypto.rb --- E3DB cryptographic operations.
#
# Copyright (C) 2017, Tozny, LLC.
# All Rights Reserved.
#

module E3DB
  module Crypto
    private

    # Create a new, random access key. Returns a
    # string of bytes representing the key.
    def new_access_key
      RbNaCl::Random.random_bytes(RbNaCl::SecretBox.key_bytes)
    end

    alias :new_data_key :new_access_key

    def decode_public_key(s)
      RbNaCl::PublicKey.new(base64decode(s))
    end

    def encode_public_key(k)
      base64encode(k.to_bytes)
    end

    def decode_private_key(s)
      RbNaCl::PrivateKey.new(base64decode(s))
    end

    def encode_private_key(k)
      base64encode(k.to_bytes)
    end

    def box_random_nonce
      RbNaCl::Random.random_bytes(RbNaCl::Box.nonce_bytes)
    end

    def secret_box_random_nonce
      RbNaCl::Random.random_bytes(RbNaCl::SecretBox.nonce_bytes)
    end

    def base64encode(x)
      Base64.urlsafe_encode64(x, padding: false)
    end

    def base64decode(x)
      Base64.urlsafe_decode64(x)
    end

    def decrypt_box(encrypted, pub, priv)
      pub = decode_public_key(pub) unless pub.is_a? RbNaCl::PublicKey
      priv = decode_private_key(priv) unless priv.is_a? RbNaCl::PrivateKey

      ciphertext, nonce = encrypted.split('.', 2).map { |f| base64decode(f) }
      RbNaCl::Box.new(pub, priv).decrypt(nonce, ciphertext)
    end

    def encrypt_box(plain, pub, priv)
      pub = decode_public_key(pub) unless pub.is_a? RbNaCl::PublicKey
      priv = decode_private_key(priv) unless priv.is_a? RbNaCl::PrivateKey

      nonce = box_random_nonce
      encrypted = RbNaCl::Box.new(pub, priv).encrypt(nonce, plain)
      [encrypted, nonce].map { |f| base64encode(f) }.join(".")
    end
  end

  private_constant :Crypto
end
