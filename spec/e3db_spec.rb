require 'spec_helper'
require 'securerandom'

describe E3DB do
  opts = E3DB::Config.load('.integration-test.json')
  opts.logging = false
  client = E3DB::Client.new(opts)

  it 'has a version number' do
    expect(E3DB::VERSION).not_to be nil
  end

  it 'can obtain its own client info' do
    info = client.client_info(client.config.client_id)
    expect(info.client_id).to eq(client.config.client_id)
  end

  # TODO: We should throw an E3DB-specific exception.
  it 'throws an error when a client doesn''t exist' do
    expect { client.client_info('doesnt exist') }.to raise_error(Faraday::ResourceNotFound)
  end

  it 'can write then read a record' do
    rec1 = client.new_record('test_result')
    rec1.data[:timestamp] = DateTime.now.iso8601
    record_id = client.write(rec1)

    rec2 = client.read(record_id)
    expect(rec1.data).to eq(rec2.data)
    expect(rec1.data).not_to be equal(rec2.data)
  end

  it 'can query records by type' do
    type = sprintf('test-type-%s', SecureRandom.uuid)
    rec1 = client.new_record(type)
    rec1.data[:timestamp] = DateTime.now.iso8601
    client.write(rec1)

    client.query(type: type) do |r|
      expect(r.data).to eq(rec1.data)
    end
  end

  it 'can query records by record id and delete' do
    type = sprintf('test-type-%s', SecureRandom.uuid)

    rec1 = client.new_record(type)
    rec1.data[:timestamp] = DateTime.now.iso8601
    rec1_id = client.write(rec1)

    rec2 = client.new_record(type)
    rec2.data[:timestamp] = DateTime.now.iso8601
    rec2_id = client.write(rec2)

    client.query(record: [rec1_id, rec2_id], data: false) do |r|
      expect(r.meta.type).to eq(type)
    end

    client.delete(rec1_id)
    client.delete(rec2_id)

    count = 0
    client.query(record: [rec1_id, rec2_id], data: false) do |r|
      count += 1
    end

    expect(count).to eq(0)
  end

  it 'can query records by writer id' do
    client.query(writer: client.config.client_id, data: false) do |r|
      expect(r.meta.writer_id).to eq(client.config.client_id)
    end
  end

  it 'can query records by plaintext meta' do
    plain_id = sprintf("id-%s", SecureRandom.uuid)
    rec = client.new_record('test-plain')
    rec.data[:timestamp] = DateTime.now.iso8601
    rec.meta.plain[:id] = plain_id
    rec_id = client.write(rec)

    client.query(plain: { 'eq' => { 'name' => 'id', 'value' => plain_id }}) do |r|
      expect(r.meta.record_id).to eq(rec_id)
    end
  end
end
