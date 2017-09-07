# This program provides a simple example illustrating how to programmatically
# register a client with InnoVault and e3db. In some situations, it's preferable
# to register a client from the server or system that will be using its
# credentials (to ensure that all data is truly encrypted from end-to-end
# with no possibilities of a credential leak). For more detailed information,
# please see the documentation home page: https://tozny.com/documentation/e3db
#
# Author::    Eric Mann (eric@tozny.com)
# Copyright:: Copyright (c) 2017 Tozny, LLC
# License::   Public Domain

# ---------------------------------------------------------
# Initialization
# ---------------------------------------------------------

require 'e3db'

# A registration token is required to set up a client. In this situation,
# we assume an environment variable called REGISTRATION_TOKEN is set
token = ENV["REGISTRATION_TOKEN"]

# Clients can either create new cryptographic keypairs, or load in a pre-defined
# pair of Curve25519 keys. In this situation, we will generate a new keypair.
public_key, private_key = E3DB::Client.generate_keypair

puts("Public Key:  " + public_key)
puts("Private Key: " + private_key)

# The e3db server keeps track of the name of the curve used with public keys,
# so we need to wrap the generated version with an object helper
wrapped_key = E3DB::PublicKey.new(:curve25519 => public_key)

# Clients must be registered with a name unique to your account to help
# differentiate between different sets of credentials in the Admin Console.
# In this example, the name is set at random
client_name = sprintf("client_%s", SecureRandom.hex)

puts("Client Name: " + client_name)

# Passing all of the data above into the registration routine will create
# a new client with the system. Remember to keep your private key private!
client_info = E3DB::Client.register(token, client_name, wrapped_key)

# Optionally, you can automatically back up the credentials of the newly-created
# client to your InnoVault account (accessible via https://console.tozny.com) by
# passing your private key and a backup flag when registering. The private key is
# not sent anywhere, but is used by the newly-created client to sign an encrypted
# copy of its credentials that is itself stored in e3db for later use.

# client_info = E3DB::Client.register(token, client_name, wrapped_key, private_key, true)

puts("Client ID:   " + client_info.client_id)
puts("API Key ID:  " + client_info.api_key_id)
puts("API Secret:  " + client_info.api_secret)

# ---------------------------------------------------------
# Usage
# ---------------------------------------------------------

# Once the client is registered, you can use it immediately to create the
# configuration used to instantiate a Client that can communicate with
# e3db directly.

config = E3DB::Config.new(
  :version      => 1,
  :client_id    => client_info.client_id,
  :api_key_id   => client_info.api_key_id,
  :api_secret   => client_info.api_secret,
  :client_email => '',
  :public_key   => public_key,
  :private_key  => private_key,
  :api_url      => 'https://api.e3db.com',
  :logging      => false
)

# Now create a client using that configuration.
client = E3DB::Client.new(config)

# From this point on, the new client can be used as any other client to read
# write, delete, and query for records. See the `simple.rb` documentation
# for more complete examples ...