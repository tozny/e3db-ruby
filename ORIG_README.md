
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

## Loading configuration and creating a client

```ruby
require 'e3db'
config = E3DB::Config.load('e3db.json')
client = E3DB::Client.new(config)
```

## Writing a record

```ruby
# Write a name and phone number, printing the ID of the new record.
record = client.new_record('contact')
record.data[:first_name] = 'Jon'
record.data[:last_name] = 'Snow'
record.data[:phone] = '555-555-1212'
record_id = client.write(record)
printf("Wrote record %s\n", record_id)
```

## Querying Records

```ruby
# Print all names and phone numbers from contacts.
client.query(content_types: ['contact'], include_data: true) do |record|
  fullname = record.data[:first_name] + ' ' + record.data[:last_name]
  printf("%-40s %s\n", fullname, record.data[:phone])
end
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/tozny/e3db-ruby.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
