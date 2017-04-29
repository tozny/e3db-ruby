#
# config.rb --- E3DB configuration files.
#
# Copyright (C) 2017, Tozny, LLC.
# All Rights Reserved.
#


module E3DB
  DEFAULT_AUTH_URL = 'https://api.dev.tot.tozny.com/v1'
  DEFAULT_API_URL = 'https://api.dev.e3db.tozny.com/v1'

  # Configuration and credentials for E3DB.
  #
  # Typically a configuration is loaded from a JSON file generated
  # during registration via the E3DB administration console
  # or command-line tool. To load a configuration from a JSON file,
  # use {Config.load}.
  #
  # @!attribute client_id
  #   @return [String] the client's unique client identifier
  # @!attribute api_key_id
  #   @return [String] the client's non-secret API key component
  # @!attribute api_secret
  #   @return [String] the client's confidential API key component
  # @!attribute public_key
  #   @return [String] the client's Base64URL encoded Curve25519 public key
  # @!attribute private_key
  #   @return [String] the client's Base64URL encoded Curve25519 private key
  # @!attribute api_base_url
  #   @return [String] the base URL for the E3DB API service
  # @!attribute auth_base_url
  #   @return [String] the base URL for the E3DB authentication service
  # @!attribute logging
  #   _Warning:_ Log output will contain confidential authentication
  #   tokens---do not enable in production if log output isn't confidential!
  #   @return [Boolean] a flag to enable HTTP logging when true
  class Config < Dry::Struct
    constructor_type :symbolized
    attribute :client_id, Types::String
    attribute :api_key_id, Types::String
    attribute :api_secret, Types::String
    attribute :public_key, Types::String
    attribute :private_key, Types::String
    attribute :api_base_url, Types::String.default(DEFAULT_API_URL)
    attribute :auth_base_url, Types::String.default(DEFAULT_AUTH_URL)
    attribute :logging, Types::Bool

    # Load configuration from a JSON file created during registration
    # or with {Config.save}.
    #
    # @param filename [String] pathname of JSON configuration to load
    # @return [Config] the configuration object loaded from the file
    def self.load(filename)
      Config.new(JSON.parse(File.read(filename)))
    end

    def logging=(value)
      @logging = value
    end
  end
end
