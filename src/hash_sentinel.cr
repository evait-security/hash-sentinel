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

puts "🔍 Analyzing NT hashes...\n"

duplicates_found = false
duplicate_groups = [] of Array(String)

nt_hash_map.each do |_, usernames|
  if usernames.size > 1
    duplicates_found = true
    duplicate_groups << usernames
  end
end

if duplicates_found
  total_duplicates = duplicate_groups.size
  total_affected_users = duplicate_groups.sum(&.size)
  
  puts "📊 Results: Found #{total_duplicates} duplicate password groups affecting #{total_affected_users} accounts\n"
  
  duplicate_groups.sort_by(&.size).reverse.each_with_index do |usernames, i|
    # Extract unique domains from this group - normalize to lowercase
    domains = Set(String).new
    processed_usernames = usernames.map do |username|
      if username.includes?("\\")
        parts = username.split("\\", 2)
        domains << parts[0].downcase  # Convert domain to lowercase for uniqueness
        parts[1] # Return just the username part without domain
      else
        username # Return the full username if no domain
      end
    end
    
    # Format domain information for the header
    domain_text = ""
    if !domains.empty?
      domain_list = domains.to_a.sort.join(", ")
      # Truncate if too long
      if domain_list.size > 40
        domain_text = " [Domains: #{domain_list[0..37]}...]"
      else
        domain_text = " [Domains: #{domain_list}]"
      end
    end
    
    puts "╔═ #{usernames.size} accounts with identical passwords#{domain_text} ══"
    
    # Display usernames without domains
    line = ""
    processed_usernames.each do |username|
      if line.empty?
        line = "║ • #{username}"
      else
        if line.size + username.size + 5 > 80
          puts line
          line = "║ • #{username}"
        else
          line += " │ #{username}"
        end
      end
    end
    
    puts line unless line.empty?
    puts "╚═══════════════════════════════════════════════════════════════════════\n"
  end
  
  puts "⚠️ WARNING: Users in the same group share identical passwords!"
  puts "🔒 Recommendation: Ensure each account has a unique, strong password."
else
  puts "✅ No users with duplicate passwords were found."
end
