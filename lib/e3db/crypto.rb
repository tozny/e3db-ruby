#
# crypto.rb --- E3DB cryptographic operations.
#
# Copyright (C) 2017, Tozny, LLC.
# All Rights Reserved.
#


module E3DB
  class Client
    private
    def get_access_key(writer_id, user_id, reader_id, type)
      ak_cache_key = [writer_id, user_id, type]
      if @ak_cache.key? ak_cache_key
        return @ak_cache[ak_cache_key]
      end

      url = sprintf('%s/access_keys/%s/%s/%s/%s', @config.api_base_url, writer_id, user_id, reader_id, type)
      resp = @conn.get(url)
      json = JSON.parse(resp.body, symbolize_names: true)

      k = json[:authorizer_public_key][:curve25519]
      authorizer_pubkey = Crypto.decode_public_key(k)

      fields     = json[:eak].split('.', 2)
      ciphertext = Crypto.base64decode(fields[0])
      nonce      = Crypto.base64decode(fields[1])
      box        = RbNaCl::Box.new(authorizer_pubkey, @private_key)

      ak = box.decrypt(nonce, ciphertext)
      @ak_cache[ak_cache_key] = ak
      ak
    end

    def put_access_key(writer_id, user_id, reader_id, type, ak)
      ak_cache_key = [writer_id, user_id, type]
      @ak_cache[ak_cache_key] = ak

      url = sprintf('%s/access_keys/%s/%s/%s/%s', @config.api_base_url, writer_id, user_id, reader_id, type)

      reader_key = Crypto.decode_public_key(client_info(reader_id).public_key.curve25519)

      nonce = RbNaCl::Random.random_bytes(RbNaCl::Box.nonce_bytes)
      eak   = RbNaCl::Box.new(reader_key, @private_key).encrypt(nonce, ak)

      encoded_eak = sprintf('%s.%s', Crypto.base64encode(eak), Crypto.base64encode(nonce))
      @conn.put(url, { :eak => encoded_eak })
    end

    def decrypt_record(encrypted_record)
      record = Record.new(meta: encrypted_record.meta.clone, data: Hash.new)

      writer_id = record.meta.writer_id
      user_id = record.meta.user_id
      type = record.meta.type
      ak = get_access_key(writer_id, user_id, @config.client_id, type)

      encrypted_record.data.each do |k, v|
        fields = v.split('.', 4)

        edk =  Crypto.base64decode(fields[0])
        edkN = Crypto.base64decode(fields[1])
        ef =   Crypto.base64decode(fields[2])
        efN =  Crypto.base64decode(fields[3])

        dk = RbNaCl::SecretBox.new(ak).decrypt(edkN, edk)
        pv = RbNaCl::SecretBox.new(dk).decrypt(efN, ef)

        record.data[k] = pv
      end

      record
    end

    def encrypt_record(plaintext_record)
      record = Record.new(meta: plaintext_record.meta.clone, data: Hash.new)

      writer_id = record.meta.writer_id
      user_id   = record.meta.user_id
      type      = record.meta.type

      begin
        ak = get_access_key(writer_id, user_id, @config.client_id, type)
      rescue Faraday::ResourceNotFound
        ak = RbNaCl::Random.random_bytes(RbNaCl::SecretBox.key_bytes)
        put_access_key(writer_id, user_id, @config.client_id, type, ak)
      end

      plaintext_record.data.each do |k, v|
        dk =   Crypto.secret_box_random_key
        efN =  Crypto.secret_box_random_nonce
        ef =   RbNaCl::SecretBox.new(dk).encrypt(efN, v)
        edkN = Crypto.secret_box_random_nonce
        edk =  RbNaCl::SecretBox.new(ak).encrypt(edkN, dk)

        record.data[k] = sprintf('%s.%s.%s.%s',
                                 Crypto.base64encode(edk), Crypto.base64encode(edkN),
                                 Crypto.base64encode(ef), Crypto.base64encode(efN))
      end

      record
    end
  end

  class Crypto
    def self.decode_public_key(s)
      RbNaCl::PublicKey.new(base64decode(s))
    end

    def self.encode_public_key(k)
      base64encode(k.to_bytes)
    end

    def self.decode_private_key(s)
      RbNaCl::PrivateKey.new(base64decode(s))
    end

    def self.encode_private_key(k)
      base64encode(k.to_bytes)
    end

    def self.secret_box_random_key
      RbNaCl::Random.random_bytes(RbNaCl::SecretBox.key_bytes)
    end

    def self.secret_box_random_nonce
      RbNaCl::Random.random_bytes(RbNaCl::SecretBox.nonce_bytes)
    end

    def self.base64encode(x)
      Base64.urlsafe_encode64(x, padding: false)
    end

    def self.base64decode(x)
      Base64.urlsafe_decode64(x)
    end
  end

  private_constant :Crypto
end
