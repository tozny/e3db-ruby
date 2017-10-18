#
# client.rb --- E3DB API client.
#
# Copyright (C) 2017, Tozny, LLC.
# All Rights Reserved.
#


require 'faraday'
require 'faraday_middleware'
require 'oauth2'
require 'rbnacl'
require 'base64'
require 'lru_redux'

module E3DB
  # Faraday middleware to automatically refresh authentication tokens and
  # pass them to API requests.
  class TokenHelper < Faraday::Middleware
    def initialize(app, client)
      super(app)
      @client = client
      @token = nil
    end

    def call(env)
      if @token.nil? or @token.expired?
        @token = @client.client_credentials.get_token
      end

      env[:request_headers]['Authorization'] ||= %(Bearer #{@token.token})
      @app.call env
    end
  end

  private_constant :TokenHelper

  # Exception thrown by {Client#update} when a concurrent modification
  # is detected. Upon catching this exception, a client should re-fetch
  # the affected record and retry the update operation.
  class ConflictError < StandardError
    def initialize(record)
      super('Conflict updating record: ' + record.meta.record_id)
      @record = record
    end

    # Return the record from the failing update attempt.
    #
    # @return [Record] the affected record
    def record
      @record
    end
  end

  # A client's public key information.
  #
  # @!attribute curve25519
  #   @return [String] a Base64URL Encoded Curve25519 public key
  class PublicKey < Dry::Struct
    attribute :curve25519, Types::Strict::String
  end

  # Information sent by the E3DB service about a client.
  #
  # @!attribute client_id
  #   @return [String] the client's unique ID string
  # @!attribute public_key
  #   @return [PublicKey] the client's public key information
  # @!attribute validated
  #   @return [Bool]
  class ClientInfo < Dry::Struct
    attribute :client_id, Types::Strict::String
    attribute :public_key, PublicKey
    attribute :validated, Types::Strict::Bool
  end

  # Information about a newly-created E3DB client
  #
  # @!attribute client_id
  #   @return [String] the client's unique ID string
  # @!attribute api_key_id
  #   @return [String]
  # @!attribute api_secret
  #   @return [String]
  # @!attribute public_key
  #   @return [PublicKey] the client's public key information
  # @!attribute name
  #   @return [String] the client's name.
  class ClientDetails < Dry::Struct
    attribute :client_id, Types::Strict::String
    attribute :api_key_id, Types::Strict::String
    attribute :api_secret, Types::Strict::String
    attribute :public_key, PublicKey
    attribute :name, Types::Strict::String
  end

  # Meta-information about an E3DB record, such as who wrote it,
  # when it was written, and the type of data stored.
  #
  # @!attribute record_id
  #   @return [String,nil] the unique ID of this record, or nil if not yet written
  # @!attribute writer_id
  #   @return [String] the client ID that wrote this record
  # @!attribute user_id
  #   @return [String] the subject client ID (currently == writer_id)
  # @!attribute type
  #   @return [String] a free-form description of record content type
  # @!attribute plain
  #   @return [Hash<String, String>] this record's plaintext record metadata
  # @!attribute created
  #   @return [Time, nil] when this record was created, or nil if unavailable
  # @!attribute last_modified
  #   @return [Time, nil] when this record was last modified, or nil if unavailable
  # @!attribute version
  #   @return [String] opaque version identifier updated by server on changes
  class Meta < Dry::Struct
    attribute :record_id, Types::Strict::String.optional
    attribute :writer_id, Types::Strict::String
    attribute :user_id, Types::Strict::String
    attribute :type, Types::Strict::String
    attribute :plain, Types::Strict::Hash.default { Hash.new }
    attribute :created, Types::Json::DateTime.optional
    attribute :last_modified, Types::Json::DateTime.optional
    attribute :version, Types::Strict::String.optional
  end

  # A E3DB record containing data and metadata. Records are
  # a key/value mapping containing data serialized
  # into strings. All records are encrypted prior to sending them
  # to the server for storage, and decrypted in the client after
  # they are read.
  #
  # New records are written to the database by calling the
  # {Client#write} method.
  #
  # To read a record by their unique ID, use {Client#read}, or to
  # query a set of records based on their attributes, use {Client#query}.
  #
  # @!attribute meta
  #   @return [Meta] meta-information about this record
  # @!attribute data
  #   @return [Hash<String, String>] this record's application-specific data
  class Record < Dry::Struct
    attribute :meta, Meta
    attribute :data, Types::Strict::Hash.default { Hash.new }

    # Allow updating metadata, used on destructive update.
    def meta=(meta)
      @meta = meta
    end
  end

  # Information about records shared with this client.
  #
  # The {Client#incoming_sharing} method returns a list of
  # {IncomingSharingPolicy} instances, each of which describes
  # a rule allowing this client to read records of a specific
  # type, written by another client.
  #
  # @!attribute writer_id
  #   @return [String] unique ID of the writer that shared with this client
  # @!attribute writer_name
  #   @return [String] display name of the writer, if available
  # @!attribute record_type
  #   @return [String] type of record shared with this client
  class IncomingSharingPolicy < Dry::Struct
    attribute :writer_id, Types::Strict::String
    attribute :writer_name, Types::Strict::String.optional
    attribute :record_type, Types::Strict::String
  end

  # Information about records shared with another client.
  #
  # The {Client#outgoing_sharing} method returns a list of
  # {OutgoingSharingPolicy} instances, each of which describes
  # a rule allowing other E3DB clients to read records of a
  # specific type.
  #
  # @!attribute reader_id
  #   @return [String] unique ID of the authorized reader
  # @!attribute reader_name
  #   @return [String] display name of reader, if available
  # @!attribute record_type
  #   @return [String] type of record shared with reader
  class OutgoingSharingPolicy < Dry::Struct
    attribute :reader_id, Types::Strict::String
    attribute :reader_name, Types::Strict::String.optional
    attribute :record_type, Types::Strict::String
  end

  # Represents an "encrypted access key" that can be used to encrypt
  # and decrypt records.
  #
  # Should only be obtained by calling {Client#create_writer_key} or
  # {Client#get_reader_key}.
  #
  # To serialize to JSON (for storage), use `JSON.dump(eak.to_hash)`. 
  # To load from JSON, use `E3DB::EAK.new(JSON.parse(eak, symbolize_names: true))`.
  class EAK < Dry::Struct
    attribute :eak, Types::Strict::String
    attribute :authorizer_public_key, PublicKey
    attribute :authorizer_id, Types::Strict::String
  end

  # A connection to the E3DB service used to perform database operations.
  #
  # @!attribute [r] config
  #   @return [Config] the client configuration object
  class Client
    include Crypto
    class << self
      include Crypto
    end

    attr_reader :config

    # Register a new client with a specific account given that account's registration token
    #
    # @param registration_token [String]  Token for a specific InnoVault account
    # @param client_name        [String]  Unique name for the client being registered
    # @param public_key         [String]  Base64URL-encoded public key component of a Curve25519 keypair
    # @param private_key        [String]  Optional Base64URL-encoded private key component of a Curve25519 keypair
    # @param backup             [Boolean] Optional flag to automatically back up the newly-created credentials to the account service
    # @param api_url            [String]  Optional URL of the API against which to register
    # @return [ClientDetails] Credentials and details about the newly-created client
    def self.register(registration_token, client_name, public_key, private_key=nil, backup=false, api_url=E3DB::DEFAULT_API_URL)
      url = "#{api_url.chomp('/')}/v1/account/e3db/clients/register"
      payload = JSON.generate({:token => registration_token, :client => {:name => client_name, :public_key => {:curve25519 => public_key}}})

      conn = Faraday.new(api_url) do |faraday|
        faraday.request :json
        faraday.response :raise_error
        faraday.adapter :net_http_persistent
      end

      resp = conn.post(url, payload)
      client_info = ClientDetails.new(JSON.parse(resp.body, symbolize_names: true))
      backup_client_id = resp.headers['x-backup-client']

      if backup
        if private_key.nil?
          raise 'Cannot back up client credentials without a private key!'
        end

        # Instantiate a client
        config = E3DB::Config.new(
            :version      => 1,
            :client_id    => client_info.client_id,
            :api_key_id   => client_info.api_key_id,
            :api_secret   => client_info.api_secret,
            :client_email => '',
            :public_key   => public_key,
            :private_key  => private_key,
            :api_url      => api_url,
            :logging      => false
        )
        client = E3DB::Client.new(config)

        # Back the client up
        client.backup(backup_client_id, registration_token)
      end

      client_info
    end

    # Generate a random Curve25519 keypair.
    #
    # @return [Array<String>] A two element array containing the public and private keys (respectively) for the new keypair.
    def self.generate_keypair
      keys = RbNaCl::PrivateKey.generate

      return encode_public_key(keys.public_key), encode_private_key(keys)
    end

    # Create a connection to the E3DB service given a configuration.
    #
    # @param config [Config] configuration and credentials to use
    # @return [Client] a connection to the E3DB service
    def initialize(config)
      @config = config
      @public_key = RbNaCl::PublicKey.new(base64decode(@config.public_key))
      @private_key = RbNaCl::PrivateKey.new(base64decode(@config.private_key))

      @oauth_client = OAuth2::Client.new(
          config.api_key_id,
          config.api_secret,
          :site => config.api_url,
          :token_url => '/v1/auth/token',
          :auth_scheme => :basic_auth,
          :raise_errors => false)

      if config.logging
        @oauth_client.connection.response :logger, ::Logger.new($stdout)
      end

      @conn = Faraday.new(DEFAULT_API_URL) do |faraday|
        faraday.use TokenHelper, @oauth_client
        faraday.request :json
        faraday.response :raise_error
        if config.logging
          faraday.response :logger, nil, :bodies => true
        end
        faraday.adapter :net_http_persistent
      end

      @ak_cache = LruRedux::ThreadSafeCache.new(1024)
    end

    # Query the server for information about an E3DB client.
    #
    # @param client_id [String] client ID to look up
    # @return [ClientInfo] information about this client
    def client_info(client_id)
      if client_id.include? "@"
        raise "Client discovery by email is not supported!"
      else
        resp = @conn.get(get_url('v1', 'storage', 'clients', client_id))
      end

      ClientInfo.new(JSON.parse(resp.body, symbolize_names: true))
    end

    # Query the server for a client's public key.
    #
    # @param client_id [String] client ID to look up
    # @return [RbNaCl::PublicKey] decoded Curve25519 public key
    def client_key(client_id)
      if client_id == @config.client_id
        @public_key
      else
        decode_public_key(client_info(client_id).public_key.curve25519)
      end
    end

    # Read a single record by ID from E3DB and return it without
    # decrypting the data fields.
    #
    # @param record_id [String] record ID to look up
    # @return [Record] encrypted record object
    def read_raw(record_id)
      resp = @conn.get(get_url('v1', 'storage', 'records', record_id))
      json = JSON.parse(resp.body, symbolize_names: true)
      Record.new(json)
    end

    # Read a single record by ID from E3DB and return it.
    #
    # @param record_id [String] record ID to look up
    # @return [Record] decrypted record object
    def read(record_id)
      resp = @conn.get(get_url('v1', 'storage', 'records', record_id))
      record = Record.new(JSON.parse(resp.body, symbolize_names: true))
      writer_id = record.meta.writer_id
      user_id = record.meta.user_id
      type = record.meta.type
      decrypt_record(record, get_eak(writer_id, user_id, type))
    end

    # Write a new record to the E3DB storage service.
    #
    # @param type [String] free-form content type name of this record
    # @param data [Hash<String, String>] record data to be stored encrypted
    # @param plain [Hash<String, String>] record data to be stored unencrypted for querying
    # @return [Record] the newly created record object (with decrypted values).
    def write(type, data, plain=Hash.new)
      url = get_url('v1', 'storage', 'records')
      id = @config.client_id

      begin
        eak = get_eak(id, id, type)
      rescue Faraday::ClientError => e
        if e.response[:status] == 404
          eak = create_writer_key(type)
        else
          raise e
        end
      end

      resp = @conn.post(url, encrypt_record(type, data, plain, id, eak).to_hash)
      decrypt_record(resp.body, eak)
    end

    # Update an existing record in the E3DB storage service.
    #
    # If the record has been modified by another client since it was
    # read, this method raises {ConflictError}, which should be caught
    # by the caller so that the record can be re-fetched and the update retried.
    #
    # The metadata of the input record will be updated in-place to reflect
    # the new version number and modification time returned by the server.
    #
    # @param record [Record] the record to update
    # @return [Nil] Always returns nil.
    def update(record)
      record_id = record.meta.record_id
      version = record.meta.version
      url = get_url('v1', 'storage', 'records', 'safe', record_id, version)

      begin
        type = record.meta.type
        encrypted_record = encrypt_existing(record, get_eak(@config.client_id, @config.client_id, record.meta.type))
        resp = @conn.put(url, encrypted_record.to_hash)
        json = JSON.parse(resp.body, symbolize_names: true)
        record.meta = Meta.new(json[:meta])
        nil
      rescue Faraday::ClientError => e
        if e.response[:status] == 409
          raise E3DB::ConflictError, record
        else
          raise e   # re-raise on other failures
        end
     end
    end

    # Delete a record from the E3DB storage service.
    #
    # @param record_id [String] unique ID of record to delete
    # @return [Nil] Always returns nil.
    def delete(record_id)
      @conn.delete(get_url('v1', 'storage', 'records', record_id))
      nil
    end

    # Back up the client's configuration to E3DB in a serialized
    # format that can be read by the Admin Console. The stored
    # configuration will be shared with the specified client, and the
    # account service notified that the sharing has taken place.
    #
    # @param client_id          [String] Unique ID of the client to which we're backing up
    # @param registration_token [String] Original registration token used to create the client
    # @return [Nil] Always returns nil.
    def backup(client_id, registration_token)
      credentials = {
          :version      => '1',
          :client_id    => @config.client_id.to_json,
          :api_key_id   => @config.api_key_id.to_json,
          :api_secret   => @config.api_secret.to_json,
          :client_email => @config.client_email.to_json,
          :public_key   => @config.public_key.to_json,
          :private_key  => @config.private_key.to_json,
          :api_url      => @config.api_url.to_json
      }

      write('tozny.key_backup', credentials, {:client => @config.client_id})
      share('tozny.key_backup', client_id)

      url = get_url('v1', 'account', 'backup', registration_token, @config.client_id)
      @conn.post(url)

      nil
    end

    class Query < Dry::Struct
      attribute :count,               Types::Int
      attribute :include_data,        Types::Bool.optional
      attribute :writer_ids,          Types::Coercible::Array.member(Types::String).optional
      attribute :user_ids,            Types::Coercible::Array.member(Types::String).optional
      attribute :record_ids,          Types::Coercible::Array.member(Types::String).optional
      attribute :content_types,       Types::Coercible::Array.member(Types::String).optional
      attribute :plain,               Types::Hash.optional
      attribute :after_index,         Types::Int.optional
      attribute :include_all_writers, Types::Bool.optional

      def after_index=(index)
        @after_index = index
      end

      def as_json
        JSON.generate(to_hash.reject { |k, v| v.nil? })
      end
    end

    private_constant :Query

    DEFAULT_QUERY_COUNT = 100
    private_constant :DEFAULT_QUERY_COUNT

    # A set of records returned by {Client#query}. This implements the
    # `Enumerable` interface which can be used to loop over the records
    # in the result set (using eg: `Enumerable#each`).
    #
    # Every traversal of the result set will execute a query to the server,
    # so if multiple in-memory traversals are needed, use `Enumerable#to_a` to
    # fetch all records into an array first.
    class Result
      include Enumerable
      include Crypto

      def initialize(client, query, raw)
        @client = client
        @query = query
        @raw = raw
      end

      # Invoke a block for each record matching a query.
      def each
        # Every invocation of 'each' gets its own copy of the query since
        # it will be modified as we loop through the result pages. This
        # allows multiple traversals of the same result set to start from
        # the beginning each time.
        q = Query.new(@query.to_hash)
        loop do
          json = @client.instance_eval { query1(q) }
          results = json[:results]
          results.each do |r|
            if q.include_data
              if !@raw
                record = @client.decrypt_record(Record.new({ :meta => r[:meta], :data => r[:record_data] }), EAK.new(r[:access_key]))
              else
                record = Record.new(data: r[:record_data], meta: Meta.new(r[:meta]))
              end
            else
              record = Record.new(data: Hash.new, meta: Meta.new(r[:meta]))
            end

            yield record
          end

          if results.length < q.count
            break
          end

          q.after_index = json[:last_index]
        end
      end
    end

    # Query E3DB records according to a set of selection criteria.
    #
    # The default behavior is to return all records written by the
    # current authenticated client.
    #
    # To restrict the results to a particular type, pass a type or
    # list of types as the `type` argument.
    #
    # To restrict the results to a set of clients, pass a single or
    # list of client IDs as the `writer` argument. To list records
    # written by any client that has shared with the current client,
    # pass the special token `:any` as the `writer` argument.
    #
    # If a block is supplied, each record matching the query parameters
    # is fetched from the server and yielded to the block.
    #
    # If no block is supplied, a {Result} is returned that will
    # iterate over the records matching the query parameters. This
    # iterator is lazy and will query the server each time it is used,
    # so calling `Enumerable#to_a` to convert to an array is recommended
    # if multiple traversals are necessary.
    #
    # @param writer [String,Array<String>,:all] select records written by these client IDs or :all for all writers
    # @param record [String,Array<String>] select records with these record IDs
    # @param type [String,Array<string>] select records with these types
    # @param plain [Hash] plaintext query expression to select
    # @param data [Boolean] include data in records
    # @param raw [Boolean] when true don't decrypt record data
    # @param page_size [Integer] number of records to fetch per request
    # @return [Result] a result set object enumerating matched records
    def query(data: true, raw: false, writer: nil, record: nil, type: nil, plain: nil, page_size: DEFAULT_QUERY_COUNT)
      all_writers = false
      if writer == :all
        all_writers = true
        writer = []
      end

      q = Query.new(after_index: 0, include_data: data, writer_ids: writer,
                    record_ids: record, content_types: type, plain: plain,
                    user_ids: nil, count: page_size,
                    include_all_writers: all_writers)
      result = Result.new(self, q, raw)
      if block_given?
        result.each do |rec|
          yield rec
        end
      else
        result
      end
    end

    # Grant another E3DB client access to records of a particular type.
    #
    # @param type [String] type of records to share
    # @param reader_id [String] client ID of reader to grant access to
    # @return [Nil] Always returns nil.
    def share(type, reader_id)
      if reader_id == @config.client_id
        return
      elsif reader_id.include? "@"
        reader_id = client_info(reader_id).client_id
      end

      id = @config.client_id
      ak = get_access_key(id, id, type)

      begin
        put_access_key(id, id, reader_id, type, ak)
      rescue Faraday::ClientError => e
        # Ignore 403, means AK already exists.
        if e.response[:status] != 403
          raise e
        end
      end

      url = get_url('v1', 'storage', 'policy', id, id, reader_id, type)
      @conn.put(url, JSON.generate({:allow => [{:read => {}}]}))
      nil
    end

    # Revoke another E3DB client's access to records of a particular type.
    #
    # @param type [String] type of records to revoke access to
    # @param reader_id [String] client ID of reader to revoke access from    
    # @return [Nil] Always returns nil.
    def revoke(type, reader_id)
      if reader_id == @config.client_id
        return
      elsif reader_id.include? "@"
        reader_id = client_info(reader_id).client_id
      end

      id = @config.client_id
      url = get_url('v1', 'storage', 'policy', id, id, reader_id, type)
      @conn.put(url, JSON.generate({:deny => [{:read => {}}]}))

      delete_access_key(id, id, reader_id, type)
      nil
    end

    # Gets a list of record types that this client has shared with
    # others.
    #
    # @return [Array<OutgoingSharingPolicy>]
    def outgoing_sharing
      url = get_url('v1', 'storage', 'policy', 'outgoing')
      resp = @conn.get(url)
      json = JSON.parse(resp.body, symbolize_names: true)
      return json.map {|x| OutgoingSharingPolicy.new(x)}
    end

    # Gets a list of record types that others have shared with this
    # client.
    #
    # @return [Array<IncomingSharingPolicy>]
    def incoming_sharing
      url = get_url('v1', 'storage', 'policy', 'incoming')
      resp = @conn.get(url)
      json = JSON.parse(resp.body, symbolize_names: true)
      return json.map {|x| IncomingSharingPolicy.new(x)}
    end

    # Create and return a key for encrypting the given record type.
    # The value returned is encrypted such that it can only be used by this
    # client.
    #
    # Can be saved for use with {#encrypt_existing}, {#encrypt_record}
    # and {#decrypt_record} later.
    #
    # @return [EAK]
    def create_writer_key(type)
      id = @config.client_id
      begin
        put_access_key(id, id, id, type, new_access_key)
      rescue Faraday::ClientError => e
        # Ignore 409, as it means a key already exists. Otherwise, raise.
        if e.response[:status] != 409
          raise e
        end
      end

      get_eak(id, id, type)
    end

    # Retrieve a key for reading records shared with this client. 
    #
    # +writer_id+ is the ID of the client who wrote the shared records. +user_id+
    # is the ID of the user that the record pertains to. +type+ is the type of
    # the shared record.
    #
    # The value returned is encrypted such that it can only be used by
    # this client.
    #
    # @return [EAK]
    def get_reader_key(writer_id, user_id, type)
      get_eak(writer_id, user_id, type)
    end

    # Encrypts an existing record. The record must contain plaintext values.
    #
    # +plain_record+ should be a {Record} instance to encrypt. 
    # +eak+ should be an {EAK} instance.
    #
    # @return [Record] An instance containg the encrypted data.
    def encrypt_existing(plain_record, eak)
      cache_key = [plain_record.meta.writer_id, plain_record.meta.user_id, plain_record.meta.type]
      if ! @ak_cache.has_key? cache_key
        @ak_cache[cache_key] = { :eak => eak, :ak => decrypt_box(eak.eak, eak.authorizer_public_key.curve25519, @private_key) }
      end
      ak = @ak_cache[cache_key][:ak]

      encrypted_record = Record.new(meta: plain_record.meta, data: Hash.new)
      plain_record.data.each do |k, v|
        dk =   new_data_key
        efN =  secret_box_random_nonce
        ef =   RbNaCl::SecretBox.new(dk).encrypt(efN, v)

        edkN = secret_box_random_nonce
        edk =  RbNaCl::SecretBox.new(ak).encrypt(edkN, dk)

        encrypted_record.data[k] = [edk, edkN, ef, efN].map { |f| base64encode(f) }.join(".")
      end

      encrypted_record
    end

    # Encrypt a new record consisting of the given data.
    #
    # +type+ is a string giving the record type. +data+ should be a
    # dictionary of string values. +plain+ should be a dictionary of
    # string values. +id+ should be the ID of the client creating the
    # record. +eak+ should be an {EAK} instance.
    #
    # @return [Record] An instance containing the encrypted data.
    def encrypt_record(type, data, plain, id, eak)
      meta = Meta.new(record_id: nil, writer_id: id, user_id: id,
                      type: type, plain: plain, created: nil,
                      last_modified: nil, version: nil)

      encrypt_existing(Record.new(:meta => meta, :data => data), eak)
    end

    # Decrypts a record using the given secret key.
    #
    # The record should be either a JSON document (as a string) or a
    # {Record} instance. +eak+ should be an {EAK} instance.
    #
    # @return [Record] An instance containing the decrypted data.
    def decrypt_record(encrypted_record, eak)
      encrypted_record = Record.new(JSON.parse(encrypted_record, symbolize_names: true)) if encrypted_record.is_a? String
      raise 'Can only decrypt JSON string or Record instance.' if ! encrypted_record.is_a? Record

      cache_key = [encrypted_record.meta.writer_id, encrypted_record.meta.user_id, encrypted_record.meta.type]
      if ! @ak_cache.has_key? cache_key
        @ak_cache[cache_key] = { :eak => eak, :ak => decrypt_box(eak.eak, eak.authorizer_public_key.curve25519, @private_key) }
      end
      ak = @ak_cache[cache_key][:ak]

      plain_record = Record.new(data: Hash.new, meta: Meta.new(encrypted_record.meta))
      encrypted_record[:data].each do |k, v|
        edk, edkN, ef, efN = v.split('.', 4).map { |f| base64decode(f) }

        dk = RbNaCl::SecretBox.new(ak).decrypt(edkN, edk)
        pv = RbNaCl::SecretBox.new(dk).decrypt(efN, ef)

        plain_record.data[k] = pv
      end

      plain_record
    end

    private

    # Returns the encrypted access key for this client for the
    # given writer/user/type combination. Throws
    # Faraday::ResourceNotFound if the key does not exist.
    #
    # Returns an instance of E3DB::EAK.
    def get_eak(writer_id, user_id, type)
      get_cached_key(writer_id, user_id, type)[:eak]
    end

    # Retrieve the access key for the given combination of writer,
    # user and typ with this client as reader. Throws
    # Faraday::ResourceNotFound if the key does not exist.
    #
    # Returns an string of bytes representing the access key.
    def get_access_key(writer_id, user_id, type)
      get_cached_key(writer_id, user_id, type)[:ak]
    end

    # Manages EAK caching, and goes to the server if a given access
    # key has not been fetched. Throws Faraday::ResourceNotFound if
    # the key does not exist.
    #
    # Returns a dictionary with +:eak+ and +:ak+ entries (containing
    # the encrypted and unencrypted versions of the key,
    # respectively).
    def get_cached_key(writer_id, user_id, type)
      cache_key = [writer_id, user_id, type]
      if @ak_cache.has_key? cache_key
        @ak_cache[cache_key]
      else
        url = get_url('v1', 'storage', 'access_keys', writer_id, user_id, @config.client_id, type)
        json = JSON.parse(@conn.get(url).body, symbolize_names: true)
        @ak_cache[cache_key] = {
          :eak => EAK.new(json),
          :ak => decrypt_box(json[:eak], json[:authorizer_public_key][:curve25519], @private_key)
        }
      end
    end

    # Store an access key for the given combination of writer, user,
    # reader and type. `ak` should be an string of bytes representing
    # the access key.
    #
    # If an access key for the given combination exists, this method
    # will have no effect.
    #
    # Returns +nil+ in all cases.
    def put_access_key(writer_id, user_id, reader_id, type, ak)
      if reader_id == @client_id
        reader_key = @public_key
      else
        resp = @conn.get(get_url('v1', 'storage', 'clients', reader_id))
        reader_key = decode_public_key(JSON.parse(resp.body, symbolize_names: true)[:public_key][:curve25519])
      end

      encoded_eak = encrypt_box(ak, reader_key, @private_key)

      url = get_url('v1', 'storage', 'access_keys', writer_id, user_id, reader_id, type)
      resp = @conn.put(url, { :eak => encoded_eak })
      cache_key = [writer_id, user_id, type]
      @ak_cache[cache_key] = {
        ak: ak,
        eak: EAK.new(
          {
            eak: encoded_eak,
            authorizer_public_key: {
              curve25519: encode_public_key(reader_key)
            },
            authorizer_id: @config.client_id
          }
        )
      }

      nil
    end

    # Delete the access key for the given combination of writer, user,
    # reader and type.
    #
    # Returns nil in all cases.
    def delete_access_key(writer_id, user_id, reader_id, type)
      url = get_url('v1', 'storage', 'access_keys', writer_id, user_id, reader_id, type)
      @conn.delete(url)

      cache_key = [writer_id, user_id, type]
      @ak_cache.delete(cache_key)

      nil
    end

    # Fetch a single page of query results. Used internally by {Client#query}.
    def query1(query)
      url = get_url('v1', 'storage', 'search')
      resp = @conn.post(url, query.as_json)
      return JSON.parse(resp.body, symbolize_names: true)
    end

    def get_url(*paths)
      "#{@config.api_url.chomp('/')}/#{ paths.map { |x| CGI.escape x }.join('/')}"
    end
  end
end
