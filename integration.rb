#! /usr/bin/env ruby
require 'e3db'

@config = E3DB::Config.default
@client = E3DB::Client.new(@config)
@record = { 'test' => 'Supercalifragilisticexpialidocious' }

def write(type)
  record = @client.write(type, @record)
  puts "Wrote #{record.meta.record_id} (#{record.meta.type})."
end

def read(*types)
  did_read = {}
  types = types[0].split(",")
  @client.query(type: types).each do |record|
    puts "Confirming #{record.meta.record_id} (#{record.meta.type})"
    raise "(actual) #{record.data[:test]}, (expected) #{@record['test']}; (#{record.meta.type})" if @record['test'] != record.data[:test]
    raise "(actual) #{record.meta.plain}, (expected) {}; (#{record.meta.type})" if record.meta.plain != {}
    did_read[record.meta.type.to_s] = true
  end

  raise "Failed to read any records." unless did_read.length
  raise "Did not read records for all types. (actual) #{did_read.keys}, (expected) #{types}" unless types.all? do |type|
    did_read.has_key? type.to_s
  end
end

def delete(type)
  @client.query(type: type).each do |record|
    puts "Deleting #{record.meta.record_id}/#{record.meta.version} (#{record.meta.type})"
    @client.delete(record.meta.record_id, record.meta.version)
  end
end

def usage(err)
  if err
    puts err
    puts ""
  end

  puts <<-USAGE
integration.rb <command>

  Read, write and delete integration test records. This script uses
  the default credentials found at ~/.tozny/e3db.json.

where <command> is one of:

  read [type[, type, ...]]
    Read records of the given type(s). Multiple types should be
    provided in a comma separated list. An error will be raised if no
    record exists for a given type.

  write
    Write a test record with the type 'ruby'.

  delete
    Delete all records of type 'ruby'.

USAGE

  exit(1)
end

if $0 == __FILE__
  usage("Please provide a command.") if ARGV.length == 0
  case ARGV[0]
  when "read"
    usage("Please provide types to read.") if ARGV.length == 1
    read(*ARGV.drop(1))
  when "write"
    write("ruby")
  when "delete"
    delete("ruby")
  else
    usage("Unrecognized command: #{ARGV[0]}")
  end

  exit(0)
end
