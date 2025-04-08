require "option_parser"

file_path = ""
wordlist_path = ""

OptionParser.parse do |parser|
  parser.banner = "Usage: hash-sentinel -f FILE [-w WORDLIST]"
  
  parser.on("-f FILE", "--file FILE", "File to read (e.g., enabled_users.txt)") do |file|
    file_path = file
  end

  parser.on("-w FILE", "--wordlist FILE", "Optional: Wordlist to identify plaintext passwords (use small lists only!)") do |file|
    wordlist_path = file
    puts "⚠️  NOTE: This is NOT a password cracking tool and is very inefficient."
    puts "    Please use only small wordlists or POT files from existing cracking sessions (< 1000 entries)."
  end

  parser.on("-h", "--help", "Show help message") do
    puts parser
    exit
  end
end

# NT hash function implementation 
# NT hash is MD4(UTF-16LE(password))
def calculate_nt_hash(password : String) : String
  # Convert to UTF-16LE (little endian)
  utf16_bytes = encode_utf16le(password)
  # Calculate MD4 hash using our custom function
  md4_hash(utf16_bytes).upcase  # Return uppercase to match expected format
end

# Corrected UTF-16LE encoding function
def encode_utf16le(str : String) : Bytes
  # Allocate buffer directly - 2 bytes per character
  bytes = IO::Memory.new
  
  str.each_char do |char|
    cp = char.ord.to_u16
    bytes.write_bytes(cp, IO::ByteFormat::LittleEndian)
  end
  
  bytes.to_slice
end

# Corrected MD4 implementation based on RFC 1320
def md4_hash(input : Bytes) : String
  # Initialize state (A, B, C, D) - little endian
  a = 0x67452301_u32
  b = 0xefcdab89_u32
  c = 0x98badcfe_u32
  d = 0x10325476_u32

  # Get input length in bits and bytes
  input_len_bytes = input.size
  input_len_bits = input_len_bytes * 8

  # Calculate number of padding bytes needed
  # Need to pad to 64-byte boundary (512 bits)
  # Need at least 9 bytes: 1 for 0x80 and 8 for length
  # If less than 9 bytes remaining, need an additional block
  padding_bytes = 64 - (input_len_bytes % 64)
  padding_bytes = padding_bytes < 9 ? padding_bytes + 64 : padding_bytes

  # Create padded message
  padded_msg = Bytes.new(input_len_bytes + padding_bytes)
  
  # Copy input data
  input_len_bytes.times do |i|
    padded_msg[i] = input[i]
  end
  
  # Add padding: first byte is 0x80, rest are zeros
  padded_msg[input_len_bytes] = 0x80_u8
  
  # Add length as 64-bit integer at the end (little-endian)
  # For NT hash, we only need the first 32 bits
  padded_msg[padded_msg.size - 8] = (input_len_bits & 0xFF).to_u8
  padded_msg[padded_msg.size - 7] = ((input_len_bits >> 8) & 0xFF).to_u8
  padded_msg[padded_msg.size - 6] = ((input_len_bits >> 16) & 0xFF).to_u8
  padded_msg[padded_msg.size - 5] = ((input_len_bits >> 24) & 0xFF).to_u8
  
  # Process each 64-byte block
  0.step(by: 64, to: padded_msg.size - 1) do |i|
    break if i + 64 > padded_msg.size
    
    # Break chunk into 16 32-bit words (X array)
    x = Array(UInt32).new(16, 0_u32)
    16.times do |j|
      x[j] = padded_msg[i + 4*j].to_u32 |
             (padded_msg[i + 4*j + 1].to_u32 << 8) |
             (padded_msg[i + 4*j + 2].to_u32 << 16) |
             (padded_msg[i + 4*j + 3].to_u32 << 24)
    end
    
    # Save state
    aa = a
    bb = b
    cc = c
    dd = d
    
    # Round 1
    # [abcd k s]: a = (a + F(b,c,d) + X[k]) <<< s
    # F(x,y,z) = (x & y) | ((~x) & z)
    
    # a = round1_op(a, b, c, d, x[0], 3)
    a = ((a &+ ((b & c) | ((~b) & d)) &+ x[0]) << 3) | ((a &+ ((b & c) | ((~b) & d)) &+ x[0]) >> 29)
    d = ((d &+ ((a & b) | ((~a) & c)) &+ x[1]) << 7) | ((d &+ ((a & b) | ((~a) & c)) &+ x[1]) >> 25)
    c = ((c &+ ((d & a) | ((~d) & b)) &+ x[2]) << 11) | ((c &+ ((d & a) | ((~d) & b)) &+ x[2]) >> 21)
    b = ((b &+ ((c & d) | ((~c) & a)) &+ x[3]) << 19) | ((b &+ ((c & d) | ((~c) & a)) &+ x[3]) >> 13)
    
    a = ((a &+ ((b & c) | ((~b) & d)) &+ x[4]) << 3) | ((a &+ ((b & c) | ((~b) & d)) &+ x[4]) >> 29)
    d = ((d &+ ((a & b) | ((~a) & c)) &+ x[5]) << 7) | ((d &+ ((a & b) | ((~a) & c)) &+ x[5]) >> 25)
    c = ((c &+ ((d & a) | ((~d) & b)) &+ x[6]) << 11) | ((c &+ ((d & a) | ((~d) & b)) &+ x[6]) >> 21)
    b = ((b &+ ((c & d) | ((~c) & a)) &+ x[7]) << 19) | ((b &+ ((c & d) | ((~c) & a)) &+ x[7]) >> 13)
    
    a = ((a &+ ((b & c) | ((~b) & d)) &+ x[8]) << 3) | ((a &+ ((b & c) | ((~b) & d)) &+ x[8]) >> 29)
    d = ((d &+ ((a & b) | ((~a) & c)) &+ x[9]) << 7) | ((d &+ ((a & b) | ((~a) & c)) &+ x[9]) >> 25)
    c = ((c &+ ((d & a) | ((~d) & b)) &+ x[10]) << 11) | ((c &+ ((d & a) | ((~d) & b)) &+ x[10]) >> 21)
    b = ((b &+ ((c & d) | ((~c) & a)) &+ x[11]) << 19) | ((b &+ ((c & d) | ((~c) & a)) &+ x[11]) >> 13)
    
    a = ((a &+ ((b & c) | ((~b) & d)) &+ x[12]) << 3) | ((a &+ ((b & c) | ((~b) & d)) &+ x[12]) >> 29)
    d = ((d &+ ((a & b) | ((~a) & c)) &+ x[13]) << 7) | ((d &+ ((a & b) | ((~a) & c)) &+ x[13]) >> 25)
    c = ((c &+ ((d & a) | ((~d) & b)) &+ x[14]) << 11) | ((c &+ ((d & a) | ((~d) & b)) &+ x[14]) >> 21)
    b = ((b &+ ((c & d) | ((~c) & a)) &+ x[15]) << 19) | ((b &+ ((c & d) | ((~c) & a)) &+ x[15]) >> 13)
    
    # Round 2
    # [abcd k s]: a = (a + G(b,c,d) + X[k] + 0x5a827999) <<< s
    # G(x,y,z) = (x & y) | (x & z) | (y & z)
    a = ((a &+ ((b & c) | (b & d) | (c & d)) &+ x[0] &+ 0x5a827999_u32) << 3) | ((a &+ ((b & c) | (b & d) | (c & d)) &+ x[0] &+ 0x5a827999_u32) >> 29)
    d = ((d &+ ((a & b) | (a & c) | (b & c)) &+ x[4] &+ 0x5a827999_u32) << 5) | ((d &+ ((a & b) | (a & c) | (b & c)) &+ x[4] &+ 0x5a827999_u32) >> 27)
    c = ((c &+ ((d & a) | (d & b) | (a & b)) &+ x[8] &+ 0x5a827999_u32) << 9) | ((c &+ ((d & a) | (d & b) | (a & b)) &+ x[8] &+ 0x5a827999_u32) >> 23)
    b = ((b &+ ((c & d) | (c & a) | (d & a)) &+ x[12] &+ 0x5a827999_u32) << 13) | ((b &+ ((c & d) | (c & a) | (d & a)) &+ x[12] &+ 0x5a827999_u32) >> 19)
    
    a = ((a &+ ((b & c) | (b & d) | (c & d)) &+ x[1] &+ 0x5a827999_u32) << 3) | ((a &+ ((b & c) | (b & d) | (c & d)) &+ x[1] &+ 0x5a827999_u32) >> 29)
    d = ((d &+ ((a & b) | (a & c) | (b & c)) &+ x[5] &+ 0x5a827999_u32) << 5) | ((d &+ ((a & b) | (a & c) | (b & c)) &+ x[5] &+ 0x5a827999_u32) >> 27)
    c = ((c &+ ((d & a) | (d & b) | (a & b)) &+ x[9] &+ 0x5a827999_u32) << 9) | ((c &+ ((d & a) | (d & b) | (a & b)) &+ x[9] &+ 0x5a827999_u32) >> 23)
    b = ((b &+ ((c & d) | (c & a) | (d & a)) &+ x[13] &+ 0x5a827999_u32) << 13) | ((b &+ ((c & d) | (c & a) | (d & a)) &+ x[13] &+ 0x5a827999_u32) >> 19)
    
    a = ((a &+ ((b & c) | (b & d) | (c & d)) &+ x[2] &+ 0x5a827999_u32) << 3) | ((a &+ ((b & c) | (b & d) | (c & d)) &+ x[2] &+ 0x5a827999_u32) >> 29)
    d = ((d &+ ((a & b) | (a & c) | (b & c)) &+ x[6] &+ 0x5a827999_u32) << 5) | ((d &+ ((a & b) | (a & c) | (b & c)) &+ x[6] &+ 0x5a827999_u32) >> 27)
    c = ((c &+ ((d & a) | (d & b) | (a & b)) &+ x[10] &+ 0x5a827999_u32) << 9) | ((c &+ ((d & a) | (d & b) | (a & b)) &+ x[10] &+ 0x5a827999_u32) >> 23)
    b = ((b &+ ((c & d) | (c & a) | (d & a)) &+ x[14] &+ 0x5a827999_u32) << 13) | ((b &+ ((c & d) | (c & a) | (d & a)) &+ x[14] &+ 0x5a827999_u32) >> 19)
    
    a = ((a &+ ((b & c) | (b & d) | (c & d)) &+ x[3] &+ 0x5a827999_u32) << 3) | ((a &+ ((b & c) | (b & d) | (c & d)) &+ x[3] &+ 0x5a827999_u32) >> 29)
    d = ((d &+ ((a & b) | (a & c) | (b & c)) &+ x[7] &+ 0x5a827999_u32) << 5) | ((d &+ ((a & b) | (a & c) | (b & c)) &+ x[7] &+ 0x5a827999_u32) >> 27)
    c = ((c &+ ((d & a) | (d & b) | (a & b)) &+ x[11] &+ 0x5a827999_u32) << 9) | ((c &+ ((d & a) | (d & b) | (a & b)) &+ x[11] &+ 0x5a827999_u32) >> 23)
    b = ((b &+ ((c & d) | (c & a) | (d & a)) &+ x[15] &+ 0x5a827999_u32) << 13) | ((b &+ ((c & d) | (c & a) | (d & a)) &+ x[15] &+ 0x5a827999_u32) >> 19)
    
    # Round 3
    # [abcd k s]: a = (a + H(b,c,d) + X[k] + 0x6ed9eba1) <<< s
    # H(x,y,z) = x ^ y ^ z
    a = ((a &+ (b ^ c ^ d) &+ x[0] &+ 0x6ed9eba1_u32) << 3) | ((a &+ (b ^ c ^ d) &+ x[0] &+ 0x6ed9eba1_u32) >> 29)
    d = ((d &+ (a ^ b ^ c) &+ x[8] &+ 0x6ed9eba1_u32) << 9) | ((d &+ (a ^ b ^ c) &+ x[8] &+ 0x6ed9eba1_u32) >> 23)
    c = ((c &+ (d ^ a ^ b) &+ x[4] &+ 0x6ed9eba1_u32) << 11) | ((c &+ (d ^ a ^ b) &+ x[4] &+ 0x6ed9eba1_u32) >> 21)
    b = ((b &+ (c ^ d ^ a) &+ x[12] &+ 0x6ed9eba1_u32) << 15) | ((b &+ (c ^ d ^ a) &+ x[12] &+ 0x6ed9eba1_u32) >> 17)
    
    a = ((a &+ (b ^ c ^ d) &+ x[2] &+ 0x6ed9eba1_u32) << 3) | ((a &+ (b ^ c ^ d) &+ x[2] &+ 0x6ed9eba1_u32) >> 29)
    d = ((d &+ (a ^ b ^ c) &+ x[10] &+ 0x6ed9eba1_u32) << 9) | ((d &+ (a ^ b ^ c) &+ x[10] &+ 0x6ed9eba1_u32) >> 23)
    c = ((c &+ (d ^ a ^ b) &+ x[6] &+ 0x6ed9eba1_u32) << 11) | ((c &+ (d ^ a ^ b) &+ x[6] &+ 0x6ed9eba1_u32) >> 21)
    b = ((b &+ (c ^ d ^ a) &+ x[14] &+ 0x6ed9eba1_u32) << 15) | ((b &+ (c ^ d ^ a) &+ x[14] &+ 0x6ed9eba1_u32) >> 17)
    
    a = ((a &+ (b ^ c ^ d) &+ x[1] &+ 0x6ed9eba1_u32) << 3) | ((a &+ (b ^ c ^ d) &+ x[1] &+ 0x6ed9eba1_u32) >> 29)
    d = ((d &+ (a ^ b ^ c) &+ x[9] &+ 0x6ed9eba1_u32) << 9) | ((d &+ (a ^ b ^ c) &+ x[9] &+ 0x6ed9eba1_u32) >> 23)
    c = ((c &+ (d ^ a ^ b) &+ x[5] &+ 0x6ed9eba1_u32) << 11) | ((c &+ (d ^ a ^ b) &+ x[5] &+ 0x6ed9eba1_u32) >> 21)
    b = ((b &+ (c ^ d ^ a) &+ x[13] &+ 0x6ed9eba1_u32) << 15) | ((b &+ (c ^ d ^ a) &+ x[13] &+ 0x6ed9eba1_u32) >> 17)
    
    a = ((a &+ (b ^ c ^ d) &+ x[3] &+ 0x6ed9eba1_u32) << 3) | ((a &+ (b ^ c ^ d) &+ x[3] &+ 0x6ed9eba1_u32) >> 29)
    d = ((d &+ (a ^ b ^ c) &+ x[11] &+ 0x6ed9eba1_u32) << 9) | ((d &+ (a ^ b ^ c) &+ x[11] &+ 0x6ed9eba1_u32) >> 23)
    c = ((c &+ (d ^ a ^ b) &+ x[7] &+ 0x6ed9eba1_u32) << 11) | ((c &+ (d ^ a ^ b) &+ x[7] &+ 0x6ed9eba1_u32) >> 21)
    b = ((b &+ (c ^ d ^ a) &+ x[15] &+ 0x6ed9eba1_u32) << 15) | ((b &+ (c ^ d ^ a) &+ x[15] &+ 0x6ed9eba1_u32) >> 17)
    
    # Add back to state
    a = (a &+ aa) & 0xFFFFFFFF_u32
    b = (b &+ bb) & 0xFFFFFFFF_u32
    c = (c &+ cc) & 0xFFFFFFFF_u32
    d = (d &+ dd) & 0xFFFFFFFF_u32
  end
  
  # Convert state to bytes (little endian)
  result = Bytes.new(16)
  
  # a
  result[0] = (a & 0xFF).to_u8
  result[1] = ((a >> 8) & 0xFF).to_u8
  result[2] = ((a >> 16) & 0xFF).to_u8
  result[3] = ((a >> 24) & 0xFF).to_u8
  
  # b
  result[4] = (b & 0xFF).to_u8
  result[5] = ((b >> 8) & 0xFF).to_u8
  result[6] = ((b >> 16) & 0xFF).to_u8
  result[7] = ((b >> 24) & 0xFF).to_u8
  
  # c
  result[8] = (c & 0xFF).to_u8
  result[9] = ((c >> 8) & 0xFF).to_u8
  result[10] = ((c >> 16) & 0xFF).to_u8
  result[11] = ((c >> 24) & 0xFF).to_u8
  
  # d
  result[12] = (d & 0xFF).to_u8
  result[13] = ((d >> 8) & 0xFF).to_u8
  result[14] = ((d >> 16) & 0xFF).to_u8
  result[15] = ((d >> 24) & 0xFF).to_u8
  
  # Return hex string
  result.hexstring
end

if file_path.empty?
  puts "⚠️ Error: No input file specified!"
  puts "Usage: hash-sentinel -f FILE [-w WORDLIST]"
  exit 1
end

nt_hash_map = Hash(String, Array(String)).new { |hash, key| hash[key] = [] of String }

# Read NT hashes from input file
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

# If wordlist is provided, build hash-to-plaintext mapping
password_matches = Hash(String, String).new

# Only process wordlist if a path was actually provided
if !wordlist_path.empty?
  begin
    puts "📖 Reading wordlist and calculating hashes..."
    word_count = 0
    
    # Check if file exists before trying to read it
    if !File.exists?(wordlist_path)
      puts "❌ Error: Wordlist file '#{wordlist_path}' not found!"
      exit 1
    end

    # Process line by line to avoid loading entire file into memory
    begin
      word_count = 0
      File.each_line(wordlist_path) do |line|
        begin
          password = line.strip
          next if password.empty?
          
          hash = calculate_nt_hash(password)
          password_matches[hash] = password
          word_count += 1
        rescue ex
          puts "⚠️ Warning: Skipping password '#{line.strip}': #{ex.message}"
          next
        end
      end
      puts "✓ Processed #{word_count} passwords from wordlist"
    rescue ex
      puts "❌ Error processing wordlist: #{ex.message}"
      exit 1
    end
  rescue ex
    puts "❌ Error reading wordlist: #{ex.message}"
    exit 1
  end
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
    
    # Add plaintext password to header if found
    password_text = ""
    if !wordlist_path.empty? && password_matches.size > 0
      nt_hash = nt_hash_map.key_for(usernames)
      if password_matches.has_key?(nt_hash)
        plaintext = password_matches[nt_hash]
        password_text = " [Password: #{plaintext}]"
      end
    end
    
    puts "╔═ #{usernames.size} accounts with identical passwords#{domain_text}#{password_text} ══"
    
    # Display usernames without domains
    line = ""
    processed_usernames.each do |username|
      if line.empty?
        line = "║ • #{username}"
      else
        if line.size + username.size + 5 > 100
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