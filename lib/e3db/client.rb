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
  class ClientInfo < Dry::Struct
    attribute :client_id, Types::Strict::String
    attribute :public_key, PublicKey
    attribute :validated, Types::Strict::Bool
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
  class Meta < Dry::Struct
    attribute :record_id, Types::Strict::String.optional
    attribute :writer_id, Types::Strict::String
    attribute :user_id, Types::Strict::String
    attribute :type, Types::Strict::String
    attribute :plain, Types::Strict::Hash.default { Hash.new }
    attribute :created, Types::Json::DateTime.optional
    attribute :last_modified, Types::Json::DateTime.optional
  end

  # A E3DB record containing data and metadata. Records are
  # a key/value mapping containing data serialized
  # into strings. All records are encrypted prior to sending them
  # to the server for storage, and decrypted in the client after
  # they are read.
  #
  # The {Client#new_record} method should be used to create a
  # new record that can be written to the database with
  # {Client#write}.
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
  end

  # A connection to the E3DB service used to perform database operations.
  #
  # @!attribute [r] config
  #   @return [Config] the client configuration object
  class Client
    attr_reader :config

    # Create a connection to the E3DB service given a configuration.
    #
    # @param config [Config] configuration and credentials to use
    # @return [Client] a connection to the E3DB service
    def initialize(config)
      @config = config
      @public_key = RbNaCl::PublicKey.new(Crypto.base64decode(@config.public_key))
      @private_key = RbNaCl::PrivateKey.new(Crypto.base64decode(@config.private_key))

      @ak_cache = LruRedux::ThreadSafeCache.new(1024)
      @oauth_client = OAuth2::Client.new(
          config.api_key_id,
          config.api_secret,
          :site => config.auth_url,
          :token_url => '/v1/token',
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
    end

    # Query the server for information about an E3DB client.
    #
    # @param client_id [String] client ID to look up
    # @return [ClientInfo] information about this client
    def client_info(client_id)
      resp = @conn.get(get_url('clients', client_id))
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
        Crypto.decode_public_key(client_info(client_id).public_key.curve25519)
      end
    end

    # Read a single record by ID from E3DB and return it without
    # decrypting the data fields.
    #
    # @param record_id [String] record ID to look up
    # @return [Record] encrypted record object
    def read_raw(record_id)
      resp = @conn.get(get_url('records', record_id))
      json = JSON.parse(resp.body, symbolize_names: true)
      Record.new(json)
    end

    # Read a single record by ID from E3DB and return it.
    #
    # @param record_id [String] record ID to look up
    # @return [Record] decrypted record object
    def read(record_id)
      decrypt_record(read_raw(record_id))
    end

    # Create a new, empty record that can be written to E3DB
    # by calling {Client#write}.
    #
    # @param type [String] free-form content type of this record
    # @return [Record] an empty record of `type`
    def new_record(type)
      id = @config.client_id
      meta = Meta.new(record_id: nil, writer_id: id, user_id: id,
                      type: type, plain: Hash.new, created: nil,
                      last_modified: nil)
      Record.new(meta: meta, data: Hash.new)
    end

    # Write a new record to the E3DB storage service.
    #
    # Create new records with {Client#new_record}.
    #
    # @param record [Record] record to write
    # @return [String] the unique ID of the written record
    def write(record)
      url = get_url('records')
      resp = @conn.post(url, encrypt_record(record).to_hash)
      json = JSON.parse(resp.body, symbolize_names: true)
      json[:meta][:record_id]
    end

    # Delete a record from the E3DB storage service.
    #
    # @param record_id [String] unique ID of record to delete
    def delete(record_id)
      resp = @conn.delete(get_url('records', record_id))
    end

    class Query < Dry::Struct
      attribute :count,         Types::Int
      attribute :include_data,  Types::Bool.optional
      attribute :writer_ids,    Types::Coercible::Array.member(Types::String).optional
      attribute :user_ids,      Types::Coercible::Array.member(Types::String).optional
      attribute :record_ids,    Types::Coercible::Array.member(Types::String).optional
      attribute :content_types, Types::Coercible::Array.member(Types::String).optional
      attribute :plain,         Types::Hash.optional
      attribute :after_index,   Types::Int.optional

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

    # Query E3DB records according to a set of selection criteria.
    #
    # Each record (optionally including data) is yielded to the block
    # argument.
    #
    # @param writer [String,Array<String>] select records written by these client IDs
    # @param record [String,Array<String>] select records with these record IDs
    # @param type [String,Array<string>] select records with these types
    # @param plain [Hash] plaintext query expression to select
    # @param data [Boolean] include data in records
    # @param raw [Boolean] when true don't decrypt record data
    def query(data: true, raw: false, writer: nil, record: nil, type: nil, plain: nil)
      q = Query.new(after_index: 0, include_data: data, writer_ids: writer,
                    record_ids: record, content_types: type, plain: plain,
                    user_ids: nil, count: DEFAULT_QUERY_COUNT)
      url = get_url('search')
      loop do
        resp = @conn.post(url, q.as_json)
        json = JSON.parse(resp.body, symbolize_names: true)
        results = json[:results]
        results.each do |r|
          record = Record.new(meta: r[:meta], data: r[:record_data] || Hash.new)
          if data && !raw
            record = decrypt_record(record)
          end
          yield record
        end

        if results.length < q.count
          break
        end

        q.after_index = json[:last_index]
      end
    end

    # Grant another E3DB client access to records of a particular type.
    #
    # @param type [String] type of records to share
    # @param reader_id [String] client ID of reader to grant access to
    def share(type, reader_id)
      if reader_id == @config.client_id
        return
      end

      id = @config.client_id
      ak = get_access_key(id, id, id, type)
      put_access_key(id, id, reader_id, type, ak)

      url = get_url('policy', id, id, reader_id, type)
      @conn.put(url, JSON.generate({:allow => [{:read => {}}]}))
    end

    # Revoke another E3DB client's access to records of a particular type.
    #
    # @param type [String] type of records to revoke access to
    # @param reader_id [String] client ID of reader to revoke access from
    def revoke(type, reader_id)
      if reader_id == @config.client_id
        return
      end

      id = @config.client_id
      url = get_url('policy', id, id, reader_id, type)
      @conn.put(url, JSON.generate({:deny => [{:read => {}}]}))
    end

    private
    def get_url(*paths)
      sprintf('%s/%s', @config.api_url, paths.map { |x| URI.escape x }.join('/'))
    end
  end
end
