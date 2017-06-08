# This program provides a few simple examples of reading, writing, and
# querying e3db records. For more detailed information, please see the
# documentation home page: https://tozny.com/documentation/e3db/
#
# Author::    Isaac Potoczny-Jones  (mailto:ijones@tozny.com)
# Copyright:: Copyright (c) 2017 Tozny, LLC
# License::   Public Domain

# ---------------------------------------------------------
# Initialization
# ---------------------------------------------------------

require 'e3db'

# Configuration files live in ~/.tozny and you can have several
# different "profiles" like *dev* and *production*.
config = E3DB::Config.default

# Now create a client using that configuration.
client = E3DB::Client.new(config)

# ---------------------------------------------------------
# Writing a record
# ---------------------------------------------------------

# Create a record by first creating a local version as a map:
record = client.new_record('test-contact')
record.data[:name]          = 'Jon Snow'
record.data[:what_he_knows] = 'Nothing'

# Now encrypt the *value* part of the record, write it to the server and
# the server returns a unique ID:
record_id = client.write(record)
puts("Wrote:    " + record_id)

# ---------------------------------------------------------
# Simple reading and queries
# ---------------------------------------------------------

# Use the unique ID returned above to read a single record from E3DB:
newRecord = client.read(record_id)
puts 'Record:   ' + newRecord.data[:name] + ' ' + record.data[:what_he_knows]

# Query for all records of type 'test-contact' and print out
# a little bit of data and metadata.
client.query(type: 'test-contact') do |record|
    puts 'Data:     ' + record.data[:name] + ' ' + record.data[:what_he_knows]
    puts 'Metadata: ' + record.meta.record_id + ' ' + record.meta.type
end

# ---------------------------------------------------------
# Simple sharing by record type
# ---------------------------------------------------------

# Share all of the records of type 'test-contact' with Isaac's client ID:
isaac_client_id = 'db1744b9-3fb6-4458-a291-0bc677dba08b'
client.share('test-contact', isaac_client_id)

# Share all of the records of type 'test-contact' with Isaac's email address.
# This only works if the client has opted into discovery of their client_id.
# TODO: Look up based on email address

# ---------------------------------------------------------
# More complex queries
# ---------------------------------------------------------

# Create some new records of the same type (note that they are also shared
# automatically since they are a type that we have shared above.

bran = client.new_record('test-contact')
bran.data[:name]           = 'Bran'
bran.data[:what_he_knows]  = 'Crow'

#Add unencrypted metadata for queries:
bran.meta.plain[:house]    = 'Stark'
bran.meta.plain[:ageRange] = 'child'
record_id = client.write(bran)

record = client.new_record('test-contact')
record.data[:name]           = 'Hodor'
record.data[:what_he_knows]  = 'Hodor'
record.meta.plain[:house]    = 'Stark'
record.meta.plain[:ageRange] = 'adult'
client.write(record)

record = client.new_record('test-contact')
record.data[:name]           = 'Doran'
record.data[:what_he_knows]  = 'Oberyn'
record.meta.plain[:house]    = 'Martell'
record.meta.plain[:ageRange] = 'adult'
client.write(record)

# Create a query that finds everyone from house Stark, but not others:
queryWesteros = Hash.new
queryWesteros = {:eq => {:name => 'house', :value => 'Stark'} }

# Execute that query:
client.query(plain: queryWesteros) do |record|
    puts record.data[:name]
end

# Now create a  more complex query with only the adults from house Stark:
queryWesteros = {:and => [
                       {:eq => {:name => 'house', :value => 'Stark'} },
                       {:eq => {:name => 'ageRange', :value => 'adult'} }
                       ]}

# Execute that query:
client.query(plain: queryWesteros) do |record|
    puts record.data[:name]
end

# ---------------------------------------------------------
# Learning about other clients
# ---------------------------------------------------------
isaac_client_info = client.client_info(isaac_client_id)
puts isaac_client_info.inspect

# TODO: Find Isaac's client_id based on his email address
# client.find('ijones+feedback@tozny.com')

# Fetch the public key:
isaac_pub_key = client.client_key(isaac_client_id)
puts isaac_pub_key.inspect

# ---------------------------------------------------------
# More reading and inspection of records
# ---------------------------------------------------------

# read_raw gets a record without decrypting its data
rawRecord = client.read_raw(record_id)
newRecord = client.read(record_id)

# So let's compare them:

puts (rawRecord.meta == newRecord.meta).to_s # true
puts (rawRecord.data == newRecord.data).to_s # false

puts newRecord.data[:name] + ' encrypts to ' + rawRecord.data[:name]

# Records contain a few other fields that are fun to look at, and this gives
# you a good sense for what's encrypted and what's not:
puts rawRecord.inspect

# ---------------------------------------------------------
# Clean up - Comment these out if you want to experiment
# ---------------------------------------------------------

# Revoke the sharing created by the client.share
client.revoke('test-contact', 'db1744b9-3fb6-4458-a291-0bc677dba08b')

# Delete the record we created above
client.delete(record_id)

# Delete all of the records of type test-contact from previous runs:
client.query(type: 'test-contact') do |record|
    client.delete(record.meta.record_id)
end
