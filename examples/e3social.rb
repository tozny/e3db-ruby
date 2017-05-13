#!/usr/local/bin/ruby

require 'e3db'


# Menus ----------------------------------------
def main_menu
  puts "===== Menu ====="
  puts $foo
  puts "N)ew Status"
  puts "P)rofile"
  puts "T)imeline"
  puts "I)dentity"
  puts "F)riends"
  puts "Q)uit"
  print_and_flush "> "
end

# Helpers ----------------------------------------

def init_global(profile = nil)
  $identity = 'social1'
  $config = E3DB::Config.load_profile($identity)
  $client = E3DB::Client.new($config)
end

def main
  init_global()
  do_loop = true;
  while do_loop
    main_menu()
    choice = gets.chomp
    case choice.upcase
    when "N"
      new_status()
    when "P"
      profile();
    when "T"
      puts "===== Timeline ====="
      timeline();
    when "I"
      identity_function();
    when "F"
      friends()
    when "Q"
      do_loop = false;
    else
      puts "Unknown selection."
    end

  end

end

def not_implemented
  puts "Not Implemented.\n";
end

def print_and_flush(str)
  print str
  $stdout.flush
end

# Identity ----------------------------------------
def set_identity_client_persona (identity)
  $identity = identity
  $config = E3DB::Config.load_profile(identity)
  $client = E3DB::Client.new($config)
end

def identity_function
  print_and_flush "Set your identity [" + $identity + "]: "
  set_identity_client_persona(gets.chomp)
end

# Status / Timeline ----------------------------------------
def new_status
  puts "Type Status and hit ENTER"
  status=gets.chomp

  record = $client.new_record('status')
  record.data[:contents] = status
  record.data[:time] = Time.now.utc.iso8601
  record.data[:by] = get_profile_name();
  record_id = $client.write(record)
  puts "Status recorded and shared"
end

def timeline (client_id = nil)
  if client_id === nil
    client_id = $config.client_id
  end
  $client.query(type: 'status', writer:client_id) do |record|
    printf("%-25s %s  %s\n", record.data[:time], record.data[:by], record.data[:contents])
  end
end

# Profile ----------------------------------------
def profile_menu
  puts "===== Profile ====="
  puts "V)iew"
  puts "E)dit"
end

def get_profile (client_id = nil)
  if client_id === nil
    client_id = $config.client_id
  end
  $client.query(type: 'profile', writer:client_id) do |record|
    return record
  end
  return nil
end


def profile
  profile_menu()
  choice = gets.chomp
    case choice.upcase
    when "V"
      profile_view()
    when "E"
      profile_edit()
    else
      puts "Unknown selection."
    end
end

def get_profile_name (client_id = nil)
  p = get_profile(client_id)
  if (p === nil)
    return nil
  else
    return (p.data[:first_name] + " " + p.data[:last_name] + " (" + p.data[:nick_name] + ")")
  end
end

def profile_view (client_id = nil)
  puts get_profile_name(client_id)
end

def profile_edit
  old_profile = get_profile()
  
  print_and_flush "First name: "
  first_name = gets.chomp
  print_and_flush "Last name: "
  last_name = gets.chomp
  print_and_flush "Nickname: "
  nick_name = gets.chomp


  record = $client.new_record('profile')
  record.data[:first_name] = first_name
  record.data[:last_name] = last_name
  record.data[:nick_name] = nick_name
  record_id = $client.write(record)

  if old_profile != nil
    $client.delete old_profile.meta.record_id
  end

end

# Friends ----------------------------------------
def share_all_with_friend (client_id = nil)
  $client.share 'profile', client_id
  $client.share 'status',  client_id
end

def friends_menu
  puts "===== Friends [" + $identity + "] ====="
  puts "L)ist"
  puts "C)onnect"
  puts "P)ending Connects"
end

def friends_connect
  print_and_flush "Enter the client ID of your friend: "
  cid = gets.chomp
  record = $client.new_record('friend')
  record.data[:client_id] = cid
  record_id = $client.write(record)

  #share my profile and timeline with them.
  share_all_with_friend cid
end

def friends_list
  $client.query(type: 'friend') do |record|
    client_id = record.data[:client_id]
    puts "===== " + client_id + " ====="
    puts get_profile_name client_id
    timeline (client_id)
  end
end

def friends
  friends_menu()
  choice = gets.chomp
    case choice.upcase
    when "L"
      friends_list()
    when "C"
      friends_connect()
    when "P"
      not_implemented()
    else
      puts "Unknown selection."
    end
end


main()
