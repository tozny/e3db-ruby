[![Gem Version][gem-image]][gem-url] [![Build Status][travis-image]][travis-url] [![Coverage Status][coveralls-image]][coveralls-url]

# Introduction

The Tozny End-to-End Encrypted Database (E3DB) is a storage platform
with powerful sharing and consent management features.
[Read more on our blog.](https://tozny.com/blog/announcing-project-e3db-the-end-to-end-encrypted-database/)

E3DB provides a familiar JSON-based NoSQL-style API for reading, writing,
and querying data stored securely in the cloud.

# Installation

Add this line to your application's Gemfile:

```ruby
gem 'e3db'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install e3db

At runtime, you will need the `libsodium` cryptography library
required by the native RbNaCl Ruby library. On most platforms
a package is available by default:

```shell
$ brew install libsodium            (Mac OS X)
$ apt-get install libsodium-dev     (Ubuntu)
```

For more information including libsodium installation instructions
for Windows, see the [libsodium web site](https://download.libsodium.org/doc/installation/).

_Windows Users:_ Make sure to download a recent "MSVC" build. Once downloaded, find the most recent `libsodium.dll` inside the ZIP file and copy it to somewhere in your `PATH`.

## Registering a client

1. Download and install the E3DB Command-Line interface (CLI) from our
   [GitHub releases page](https://github.com/tozny/e3db-go/releases).

2. Register an account using the CLI:

   ```shell
   $ e3db register me@mycompany.com
   ```

   This will create a new default configuration with a randomly
   generated key pair and API credentials, saving it in `$HOME/.tozny/e3db.json`.

## Loading configuration and creating a client

Use the `E3DB::Config.default` class method to load the default
client configuration, and pass it to the `E3DB::Client` constructor:

```ruby
require 'e3db'
config = E3DB::Config.default
client = E3DB::Client.new(config)
```

### Using profiles to manage multiple configurations

The E3DB Command-Line Interface allows you to register and manage
multiple keys and credentials using _profiles_. To register a new
client under a different profile:

```shell
$ e3db register --profile=development developers@mycompany.com
```

You can then use `E3DB::Config.load_profile` to load a specific profile
inside your Ruby application:

```ruby
config = E3DB::Config.load_profile('development')
client = E3DB::Client.new(config)
```

## Writing a record

To write new records to the database, call the `E3DB::Client#write`
method with a string describing the type of data to be written,
along with a hash containing the fields of the record.  `E3DB::Client#write`
returns the newly created record.

```ruby
record = client.write('contact', {
  :first_name => 'Jon',
  :last_name => 'Snow',
  :phone => '555-555-1212'
})
printf("Wrote record %s\n", record.meta.record_id)
```

## Querying Records

E3DB supports many options for querying records based on the fields
stored in record metadata. Refer to the API documentation for the
complete set of options that can be passed to `E3DB::Client#query`.

For example, to list all records of type `contact` and print a
simple report containing names and phone numbers:

```ruby
client.query(type: 'contact') do |record|
  fullname = record.data[:first_name] + ' ' + record.data[:last_name]
  printf("%-40s %s\n", fullname, record.data[:phone])
end
```

In this example, the `E3DB::Client#query` method takes a block that will
execute for each record that matches the query. Records will be streamed
efficiently from the server in batches, allowing processing of large data
sets without consuming excessive memory.

In some cases, it is more convenient to load all results into memory
for processing. To achieve this, instead of passing a block to
`E3DB::Client#query`, you can call `Enumerable` methods on the query result,
including `Enumerable#to_a` to convert the results to an array.

For example:

```ruby
results = client.query(type: 'contact').to_a
printf("There were %d results.\n", results.length)
results.each do |record|
  puts record
end
```

## More examples
See the [simple example code](examples/simple.rb) for runnable detailed examples.

## Development

Before running tests, register an `integration-test` profile using
the E3DB command-line tool:

```shell
$ e3db -p integration-test register me+test@mycompany.com
```

After checking out the repo, run `bin/setup` to install dependencies. Then,
run `rake spec` to run the tests. You can also run `bin/console` for an
interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`.
To release a new version, update the version number in `version.rb`, and
then run `bundle exec rake release`, which will create a git tag for the
version, push git commits and tags, and push the `.gem` file to
[rubygems.org](https://rubygems.org).

## Documentation

General E3DB documentation is [on our web site](https://tozny.com/documentation/e3db/).

Comprehensive documentation for the SDK can be found online [via RubyDoc.info](http://www.rubydoc.info/gems/e3db/2.0.0.rc1).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/tozny/e3db-ruby.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

[gem-image]: https://badge.fury.io/rb/e3db.svg
[gem-url]: https://rubygems.org/gems/e3db
[travis-image]: https://travis-ci.org/tozny/e3db-ruby.svg?branch=master
[travis-url]: https://travis-ci.org/tozny/e3db-ruby
[coveralls-image]: https://coveralls.io/repos/github/tozny/e3db-ruby/badge.svg?branch=master
[coveralls-url]: https://coveralls.io/github/tozny/e3db-ruby
