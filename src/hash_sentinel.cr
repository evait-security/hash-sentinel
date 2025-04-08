require "option_parser"

file_path = ""

OptionParser.parse do |parser|
  parser.banner = "Usage: hash-sentinel -f FILE"
  
  parser.on("-f FILE", "--file FILE", "File to read (e.g., enabled_users.txt)") do |file|
    file_path = file
  end

  parser.on("-h", "--help", "Show help message") do
    puts parser
    exit
  end
end

if file_path.empty?
  puts "⚠️ Error: No input file specified!"
  puts "Usage: hash-sentinel -f FILE"
  exit 1
end

nt_hash_map = Hash(String, Array(String)).new { |hash, key| hash[key] = [] of String }

begin
  File.each_line(file_path) do |line|
    line = line.strip
    next if line.empty?

    parts = line.split(":")
    if parts.size >= 4  # Make sure there are at least 4 parts
      username = parts[0]
      nt_hash = parts[3]

      nt_hash_map[nt_hash] << username
    else
      puts "⚠️ Warning: Skipping malformed line: #{line}"
    end
  end
rescue ex : File::NotFoundError
  puts "❌ Error: File '#{file_path}' not found!"
  exit 1
end

puts "🔍 Analyzing NT hashes...\n\n"

duplicates_found = false

nt_hash_map.each do |_, usernames|
  if usernames.size > 1
    duplicates_found = true
    user_text = usernames.join(", ")
    puts "⚠️ Duplicate password found: #{user_text}"
  end
end

unless duplicates_found
  puts "✅ No users with duplicate passwords were found."
end
