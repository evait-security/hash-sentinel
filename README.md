## 🔒 Hash Sentinel

> **Hash Sentinel** is a handy and efficient Crystal tool designed to quickly identify users in an Active Directory environment who share identical NT hashes (passwords). It’s a powerful addition to a penetration tester’s toolkit, especially useful during post-exploitation phases, domain takeovers, and password policy assessments.

---

## 📖 Introduction

When conducting penetration tests, especially after compromising a Windows domain environment, it’s crucial to analyze password usage across domain accounts. Identifying users with identical passwords helps assess password hygiene, detect shared administrative passwords, and pinpoint critical security issues.

After you've successfully taken control of an Active Directory domain (for example, by obtaining Domain Admin credentials), you typically extract the NTDS database dump. Here's a typical scenario to generate such a dump with Impacket's `secretsdump.py`:

```bash
secretsdump.py DOMAIN/Administrator:'Password123'@192.168.0.10 -outputfile full_domain_dump.txt -user-status
```

After obtaining the dump, you can filter out enabled users and exclude machine accounts with:

```bash
cat full_domain_dump.txt.ntds | grep 'status=Enabled' | cut -d " " -f 1 | grep -v '\$' > enabled_users_dump.ntds
```

Now, to detect users sharing the same password efficiently, **Hash Sentinel** helps you analyze this filtered data quickly and effortlessly.

---

## 🚀 Installation

Ensure Crystal is installed ([https://crystal-lang.org/install/](https://crystal-lang.org/install/)).

Clone this repository:

```bash
git clone https://github.com/your_username/hash-sentinel.git
cd hash-sentinel
shards install
```

---

## 🔧 Building from Source

Build the executable binary with the following command:

```bash
crystal build --release src/hash_sentinel.cr -o hash-sentinel
```

Now, the binary `hash-sentinel` will be created in your project directory.

---

## ▶️ Running the Binary

After building the binary, you can easily analyze your NT hash dumps. Run it using the following command structure:

```bash
./hash-sentinel -f enabled_users_dump.ntds
```

### Command Line Parameters

| Parameter | Description                                 | Example                        |
|-----------|---------------------------------------------|--------------------------------|
| `-f`      | Path to input file containing user hashes   | `-f enabled_users_dump.ntds`   |
| `-h`      | Display help information                    | `-h`                           |

---

## 📌 Usage Example

### 🔹 Input File Example (`enabled_users_dump.ntds`):

```
john.doe:1000:aad3b435b51404eeaad3b435b51404ee:88e4d9fabaecf3dec18dd80905521b29:::
jane.smith:1001:aad3b435b51404eeaad3b435b51404ee:e52cac67419a9a224a3b108f3fa6cb6d:::
mark.brown:1002:aad3b435b51404eeaad3b435b51404ee:88e4d9fabaecf3dec18dd80905521b29:::
```

### 🔹 Command:

```bash
./hash-sentinel -f enabled_users_dump.ntds
```

### 🔹 Output Example:

```
🔍 Analyzing NT hashes...

⚠️ Duplicate password found: john.doe, mark.brown
```

---

## 🛡️ Why Use Hash Sentinel?

- Quickly identifies weak password policies.
- Detects password reuse across user accounts.
- Facilitates security reporting and actionable recommendations.
- Simplifies large-scale password audits.

---

## 📚 Practical Workflow Example

A full practical example of a penetration testing workflow with `hash-sentinel`:

**Step 1:** Extract NTDS dump using Impacket (requires Domain Admin privileges):

```bash
secretsdump.py DOMAIN/Admin:'Passw0rd!'@10.10.10.100 -outputfile domain_dump.txt -user-status
```

**Step 2:** Extract only enabled user accounts (excluding machine accounts):

```bash
cat domain_dump.txt.ntds | grep 'status=Enabled' | cut -d " " -f 1 | grep -v '\$' > enabled_users_dump.ntds
```

**Step 3:** Run `hash-sentinel`:

```bash
./hash-sentinel -f enabled_users_dump.ntds
```

---

## 📝 License

MIT License

---

**Happy Hacking! 🚀**