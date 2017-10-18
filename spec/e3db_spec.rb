require 'spec_helper'
require 'securerandom'

describe E3DB do

  raise "REGISTRATION_TOKEN environment variable must be defined." unless ENV["REGISTRATION_TOKEN"]
  raise "API_URL environment variable must be defined." unless ENV["API_URL"]

  token = ENV["REGISTRATION_TOKEN"]
  api_url = ENV["API_URL"]

  client1_public_key, client1_private_key = E3DB::Client.generate_keypair
  client2_public_key, client2_private_key = E3DB::Client.generate_keypair

  client1_name = sprintf("test_client_%s", SecureRandom.hex)
  client2_name = sprintf("share_client_%s", SecureRandom.hex)

  test_client1 = E3DB::Client.register(token, client1_name, client1_public_key, nil, false, api_url)
  test_client2 = E3DB::Client.register(token, client2_name, client2_public_key, nil, false, api_url)

  client1_opts = E3DB::Config.new(
    :version      => 1,
    :client_id    => test_client1.client_id,
    :api_key_id   => test_client1.api_key_id,
    :api_secret   => test_client1.api_secret,
    :client_email => sprintf('eric+%s@tozny.com', test_client1.name),
    :public_key   => client1_public_key,
    :private_key  => client1_private_key,
    :api_url      => api_url,
    :logging      => false
  )
  client = E3DB::Client.new(client1_opts)

  # set up the shared client:
  client2_opts = E3DB::Config.new(
      :version      => 1,
      :client_id    => test_client2.client_id,
      :api_key_id   => test_client2.api_key_id,
      :api_secret   => test_client2.api_secret,
      :client_email => sprintf('eric+%s@tozny.com', test_client2.name),
      :public_key   => client2_public_key,
      :private_key  => client2_private_key,
      :api_url      => api_url,
      :logging      => false
  )
  client2 = E3DB::Client.new(client2_opts)

  # The sharing client data:
  test_email = client2.config.client_email
  test_share_client = client2.config.client_id

  it 'can register clients' do
    public_key, _ = E3DB::Client.generate_keypair
    name = sprintf("client_%s", SecureRandom.hex)

    test_client = E3DB::Client.register(token, name, public_key, nil, false, api_url)

    expect(test_client.name).to eq(name)
    expect(test_client.public_key.curve25519).to eq(public_key)

    expect(test_client.client_id).not_to be eq("")
    expect(test_client.api_key_id).not_to be eq("")
    expect(test_client.api_secret).not_to be eq("")
  end

  it 'has a version number' do
    expect(E3DB::VERSION).not_to be nil
  end

  it 'can obtain its own client info' do
    info = client.client_info(client.config.client_id)
    expect(info.client_id).to eq(client.config.client_id)
  end

  # TODO: We should throw an E3DB-specific exception.
  it "throws an error when a client doesn't exist" do
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

  it 'can filter fields when reading single records' do
    record = client.write('field_test', {
        :visible => 'This is visible',
        :alsovisible => 'So is this',
        :hidden => 'This will be filtered out'
    })

    retrieved = client.read(record.meta.record_id, ['visible', 'alsovisible'])

    expect(retrieved.meta.record_id).to eq(record.meta.record_id)
    expect(retrieved.data).to have_key(:visible)
    expect(retrieved.data).to have_key(:alsovisible)
    expect(retrieved.data).not_to have_key(:hidden)
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

  it 'can raise an exception on conflicting delete' do
    rec = client.write('test_result', {
      :counter => '0'
    })

    recA = E3DB::Record.new(rec.to_hash)
    inc_field(recA, :counter)
    client.update(recA)

    expect {
      client.delete(rec.meta.record_id, rec.meta.version)
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

  it 'can query records from any writer' do
    isps = client.incoming_sharing
    incoming_writers = isps.map {|x| x.writer_id} + [client.config.client_id]

    # List all records that are readable and make sure they are written
    # by one of the readers that has shared with us, or ourselves.
    results = client.query(writer: :all)
    results.each do |rec|
      expect(incoming_writers).to include(rec.meta.writer_id)
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
    client.share(type, test_share_client)

    rec2 = client2.read(rec.meta.record_id)
    expect(rec.data).to eq(rec2.data)
  end

  it 'can list outgoing sharing' do
    type = sprintf('test-share-%s', SecureRandom.uuid)
    rec = client.write(type, {
      :timestamp => DateTime.now.iso8601
    })
    client.share(type, test_share_client)

    found = false
    client.outgoing_sharing.each do |osp|
      if osp.reader_id == test_share_client and osp.record_type == type
        found = true
      end
    end

    expect(found).to eq(true)
  end

  it 'can list incoming sharing' do
    isps = client.incoming_sharing
    expect(isps).to eq([])      # could do better with a 2nd test client
  end

  it 'can create & retrieve access keys' do
    client1 = E3DB::Client.new(client1_opts)
    type = sprintf('test-share-%s', SecureRandom.uuid)
    rec = client1.write(type, {
      :timestamp => DateTime.now.iso8601
    })
    eak = client.get_reader_key(client1_opts.client_id, client1_opts.client_id, type)
    expect(eak).not_to be eq(nil)
  end

  it 'can encrypt and decrypt locally' do
    client1 = E3DB::Client.new(client1_opts)
    type = sprintf('test-share-%s', SecureRandom.uuid)
    # Create AK & share before writing (simulating creating AK during registration)
    client1_eak = client1.create_writer_key(type)
    client1.share(type, client2_opts.client_id)

    plain_rec = {
      :timestamp => DateTime.now.iso8601.to_s
    }

    encrypted_rec = client1.encrypt_record(type, plain_rec, nil, client1_opts.client_id, client1_eak)
    # Decrypt JSON
    decrypted_rec = client1.decrypt_record(JSON.dump(encrypted_rec.to_hash), client1_eak)

    expect(decrypted_rec.meta.user_id).to eq(encrypted_rec.meta.user_id)
    expect(decrypted_rec.meta.type).to eq(encrypted_rec.meta.type)
    expect(decrypted_rec.meta.plain).to eq(encrypted_rec.meta.plain)
    expect(decrypted_rec.data[:timestamp]).to eq(plain_rec[:timestamp])

    # Decrypt encrypred Record instance.
    decrypted_rec2 = client1.decrypt_record(encrypted_rec, client1_eak)
    expect(decrypted_rec2.meta.user_id).to eq(encrypted_rec.meta.user_id)
    expect(decrypted_rec2.meta.type).to eq(encrypted_rec.meta.type)
    expect(decrypted_rec2.meta.plain).to eq(encrypted_rec.meta.plain)
    expect(decrypted_rec2.data[:timestamp]).to eq(plain_rec[:timestamp])
  end

  it 'can encrypt locally and another client can decrypt locally' do
    client1 = E3DB::Client.new(client1_opts)
    type = sprintf('test-share-%s', SecureRandom.uuid)
    # Create AK & share before writing (simulating creating AK during registration)
    client1_eak = client1.create_writer_key(type)
    client1.share(type, client2_opts.client_id)

    plain_rec = {
      :timestamp => DateTime.now.iso8601.to_s
    }

    # make sure client2 can still read encrypted recods
    encrypted_rec = client1.encrypt_record(type, plain_rec, nil, client1_opts.client_id, client1_eak)

    # make sure client2 can decrypt offline too
    client2 = E3DB::Client.new(client2_opts)
    client2_eak = client2.get_reader_key(client1_opts.client_id, client1_opts.client_id, type)
    decrypted_rec = client2.decrypt_record(JSON.dump(encrypted_rec.to_hash), client2_eak)

    expect(decrypted_rec.meta.user_id).to eq(encrypted_rec.meta.user_id)
    expect(decrypted_rec.meta.type).to eq(encrypted_rec.meta.type)
    expect(decrypted_rec.meta.plain).to eq(encrypted_rec.meta.plain)
    expect(decrypted_rec.data[:timestamp]).to eq(plain_rec[:timestamp])
  end

  it 'can serialize & deserialize EAKs' do
    client1 = E3DB::Client.new(client1_opts)
    type = sprintf('test-share-%s', SecureRandom.uuid)
    # Create AK & share before writing (simulating creating AK during registration)
    client1_eak = JSON.dump(client1.create_writer_key(type).to_hash)

    plain_rec = {
      :timestamp => DateTime.now.iso8601.to_s
    }

    # make sure client2 can still read encrypted recods
    encrypted_rec = client1.encrypt_record(
      type, plain_rec, nil, client1_opts.client_id, E3DB::EAK.new(JSON.parse(client1_eak, symbolize_names: true))
    )
    decrypted_rec = client1.decrypt_record(
      JSON.dump(encrypted_rec.to_hash), E3DB::EAK.new(JSON.parse(client1_eak, symbolize_names: true))
    )

    expect(decrypted_rec.meta.user_id).to eq(encrypted_rec.meta.user_id)
    expect(decrypted_rec.meta.type).to eq(encrypted_rec.meta.type)
    expect(decrypted_rec.meta.plain).to eq(encrypted_rec.meta.plain)
    expect(decrypted_rec.data[:timestamp]).to eq(plain_rec[:timestamp])
  end

  it 'can round-trip encryption' do
    client1 = E3DB::Client.new(client1_opts)
    type = sprintf('test-share-%s', SecureRandom.uuid)
    plain_rec = {
      :timestamp => DateTime.now.iso8601.to_s
    }
    
    record = client1.write(type, plain_rec)
    client1_eak1 = JSON.dump(client1.create_writer_key(type).to_hash)
    encrypted_rec = client1.encrypt_record(
      type, plain_rec, nil, client1_opts.client_id, E3DB::EAK.new(JSON.parse(client1_eak1, symbolize_names: true))
    )

    client1.share(type, client2_opts.client_id)
    client1_eak2 = JSON.dump(client1.create_writer_key(type).to_hash)

    client1a = E3DB::Client.new(client1_opts)
    decrypted_rec = client1a.decrypt_record(
      JSON.dump(encrypted_rec.to_hash), E3DB::EAK.new(JSON.parse(client1_eak1, symbolize_names: true))
    )
    
    expect(decrypted_rec.meta.user_id).to eq(encrypted_rec.meta.user_id)
    expect(decrypted_rec.meta.type).to eq(encrypted_rec.meta.type)
    expect(decrypted_rec.meta.plain).to eq(encrypted_rec.meta.plain)
    expect(decrypted_rec.data[:timestamp]).to eq(plain_rec[:timestamp])

    decrypted_rec = client1a.decrypt_record(
      JSON.dump(encrypted_rec.to_hash), E3DB::EAK.new(JSON.parse(client1_eak2, symbolize_names: true))
    )
    
    expect(decrypted_rec.meta.user_id).to eq(encrypted_rec.meta.user_id)
    expect(decrypted_rec.meta.type).to eq(encrypted_rec.meta.type)
    expect(decrypted_rec.meta.plain).to eq(encrypted_rec.meta.plain)
    expect(decrypted_rec.data[:timestamp]).to eq(plain_rec[:timestamp])
  end
end
