require 'spec_helper'
require 'securerandom'

# jamesjb scratch profile on development instance
TEST_SHARE_CLIENT = 'dac7899f-c474-4386-9ab8-f638dcc50dec'
TEST_EMAIL = 'ijones+feedback@tozny.com'

describe E3DB do
  opts = E3DB::Config.load_profile('integration-test')
  opts.logging = false
  client = E3DB::Client.new(opts)

  it 'has a version number' do
    expect(E3DB::VERSION).not_to be nil
  end

  it 'can obtain its own client info' do
    info = client.client_info(client.config.client_id)
    expect(info.client_id).to eq(client.config.client_id)
  end

  it 'can look up a client by e-mail address' do
    info = client.client_info(TEST_EMAIL)
  end

  # TODO: We should throw an E3DB-specific exception.
  it 'throws an error when a client doesn''t exist' do
    expect { client.client_info('doesnt exist') }.to raise_error(Faraday::ResourceNotFound)
  end

  it 'can write then read a record' do
    rec1 = client.write('test_result', {
      :timestamp => DateTime.now.iso8601
    })

    rec2 = client.read(rec1.meta.record_id)
    expect(rec1.data).to eq(rec2.data)
    expect(rec1.data).not_to be equal(rec2.data)
  end

  def inc_field(rec, field)
    rec.data[field] = (rec.data[field].to_i + 1).to_s
  end

  it 'can write, update, then read a record' do
    rec = client.write('test_result', {
      :counter => '0'
    })

    inc_field(rec, :counter)
    old_version = rec.meta.version
    client.update(rec)
    new_version = rec.meta.version

    expect(rec.data[:counter]).to eq('1')
    expect(old_version).not_to eq(new_version)
  end

  it 'can raise an exception on conflicting updates' do
    rec = client.write('test_result', {
      :counter => '0'
    })

    recA = E3DB::Record.new(rec.to_hash)
    inc_field(recA, :counter)
    client.update(recA)

    recB = E3DB::Record.new(rec.to_hash)
    inc_field(recB, :counter)
    expect {
      client.update(recB)
    }.to raise_error(E3DB::ConflictError)
  end

  it 'can query records by type' do
    type = sprintf('test-type-%s', SecureRandom.uuid)
    rec1 = client.write(type, {
      :timestamp => DateTime.now.iso8601
    })

    results = client.query(type: type).to_a
    expect(results.count).to be >= 1

    results.each do |r|
      expect(r.data).to eq(rec1.data)
    end
  end

  it 'can query records by type by passing a block to query' do
    type = sprintf('test-type-%s', SecureRandom.uuid)
    rec1 = client.write(type, {
      :timestamp => DateTime.now.iso8601
    })

    count = 0
    client.query(type: type) do |r|
      expect(r.data).to eq(rec1.data)
      count += 1
    end

    expect(count).to be >= 1
  end

  it 'enumerates results multiple times properly' do
    type = sprintf('test-type-%s', SecureRandom.uuid)
    20.times do |n|
      client.write(type, {
        :timestamp => DateTime.now.iso8601
      })
    end

    result = client.query(type: type, page_size: 5)
    a1 = result.to_a
    a2 = result.to_a

    expect(a1).to eq(a2)
  end

  it 'can query records by record id and delete' do
    type = sprintf('test-type-%s', SecureRandom.uuid)

    rec1 = client.write(type, {
      :timestamp => DateTime.now.iso8601
    })
    rec1_id = rec1.meta.record_id

    rec2 = client.write(type, {
      :timestamp => DateTime.now.iso8601
    })
    rec2_id = rec2.meta.record_id

    results = client.query(record: [rec1_id, rec2_id], data: false).to_a
    expect(results.count).to eq(2)

    results.each do |r|
      expect(r.meta.type).to eq(type)
    end

    client.delete(rec1_id)
    client.delete(rec2_id)

    result = client.query(record: [rec1_id, rec2_id], data: false)
    expect(result.count).to eq(0)
  end

  it 'can query records by writer id' do
    client.query(writer: client.config.client_id, data: false).each do |r|
      expect(r.meta.writer_id).to eq(client.config.client_id)
    end
  end

  it 'can query records by plaintext meta' do
    plain_id = sprintf("id-%s", SecureRandom.uuid)
    rec = client.write('test-plain', {
      :timestamp => DateTime.now.iso8601
    }, {
      :id => plain_id
    })

    client.query(plain: { 'eq' => { 'name' => 'id', 'value' => plain_id }}).each do |r|
      expect(r.meta.record_id).to eq(rec.meta.record_id)
    end
  end

  it 'can share with another client' do
    type = sprintf('test-share-%s', SecureRandom.uuid)
    rec = client.write(type, {
      :timestamp => DateTime.now.iso8601
    })
    client.share(type, TEST_SHARE_CLIENT)
  end

  it 'can share by e-mail address' do
    type = sprintf('test-share-%s', SecureRandom.uuid)
    rec = client.write(type, {
      :timestamp => DateTime.now.iso8601
    })
    client.share(type, TEST_EMAIL)
  end

  it 'can list outgoing sharing' do
    type = sprintf('test-share-%s', SecureRandom.uuid)
    rec = client.write(type, {
      :timestamp => DateTime.now.iso8601
    })
    client.share(type, TEST_SHARE_CLIENT)

    found = false
    client.outgoing_sharing.each do |osp|
      if osp.reader_id == TEST_SHARE_CLIENT and osp.record_type == type
        found = true
      end
    end

    expect(found).to eq(true)
  end

  it 'can list incoming sharing' do
    isps = client.incoming_sharing
    expect(isps).to eq([])      # could do better with a 2nd test client
  end
end
