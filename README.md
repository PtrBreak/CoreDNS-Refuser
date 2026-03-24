# **refuser v0.3.2 — CoreDNS Domain Refusal Plugin**

`refuser` is a high‑performance and extensible CoreDNS plugin designed to **quickly refuse (or allow) specific domain queries**.  
It is suitable for ad blocking, malicious domain filtering, enterprise DNS policies, and home network protection.

Refer to the CoreDNS documentation for instructions on enabling custom plugins.

---

## Features

- **Blacklist / Whitelist modes**  
  Supports both `blacklist` (default) and `whitelist` modes.

- **External domain list files**  
  Load large rule sets from external files.

- **Regular expression matching**  
  Optional regex rules using Go’s RE2 engine.

- **LRU rule cache**  
  High‑performance caching to avoid repeated rule evaluation.

- **Automatic rule reload**  
  Reload rule files periodically.

- **Hit decay mechanism**  
  Track frequently matched domains for debugging and analysis.

- **Verbose debug output**  
  Optional detailed logging for troubleshooting.

---

## Corefile Syntax

### Basic structure

```txt
refuser {
    mode blacklist|whitelist     # default: blacklist

    # Static rules inside Corefile (higher priority)
    listzone fqdn.name           # static rule
    exceptzone fqdn.name         # static exception

    listfile /path/to/rules.txt  # rule file
    exceptions /path/to/exc.txt  # exception file

    # --- Rule limits ---
    max_regex_rules limit        # max number of regex rules
    max_wildcard_rules limit     # max number of wildcard rules

    # --- Cache control ---
    cache_record_limit limit
    cache_limit_factor factor
    cache_fuse_cycles cycles
    decay_interval seconds
    delete_bucket_count count

    # --- General options ---
    reload seconds               # hot reload interval (0 = disabled)
    debug true|false             # verbose logging
}
```

---

## Rule File Format

```txt
bar                 # top‑level domain
foo.bar             # exact domain (includes subdomains)
WILDCARD:*foo.bar   # wildcard rule (no space allowed after "WILDCARD:")
REGEX:.*\.foo\..*   # regex rule (no space allowed after "REGEX:")
```

Supported rule types:

- Exact match  
- Wildcard match (`WILDCARD:` prefix required)  
- Regular expression (`REGEX:` prefix required, RE2 syntax)

If a line contains wildcard or regex characters **without** the required prefix,  
the line is treated as invalid and ignored.

---

## How It Works

`refuser` acts as a **front‑line filter** in the DNS request pipeline.  
When a rule matches, the plugin **does not forward the query to upstream servers**.  
Instead, it generates a refusal response locally.

Processing flow:

1. Receive DNS query  
2. Check rule cache (LRU)  
   - Hit → return REFUSED/NXDOMAIN immediately  
   - Hit allow → pass through  
3. Perform local rule matching  
   - Exact  
   - Wildcard  
   - Regex (optional)  
4. Decide allow/refuse based on mode  
5. On refusal → generate response locally (no upstream query)  
6. On no match → pass to next plugin (e.g., `forward`)  
7. Update decay counters and cache

This design ensures extremely low latency and high throughput.

---

## Debugging

Enable debug mode:

```txt
refuser {
    debug true
}
```

Example log:

```
[refuser] matched blacklist rule: ads.example.com → NXDOMAIN
```

---

## Performance Notes

- Suitable for large or frequently updated rule sets  
- Regex rules are slower; limit their number  
- Cache significantly improves performance  
- Recommended to place `refuser` at the top of each zone

---

## Version History

### **v0.3.2**
- Added: hit decay mechanism  
- Added: regex rule limit  
- Added: cache size limit  
- Added: automatic rule reload  
- Added: debug mode  
- Improved: matching performance  
- Improved: clearer error messages  
- Fixed: wildcard boundary issues  
- Fixed: duplicate rule loading  

---

## Example Corefile

```txt
. {
    refuser {
        mode blacklist
        listfile /path/to/rules.txt

        decay_interval 30
        max_regex_rules 32
        debug true
        reload 86400
        cache_record_limit 4096
    }

    forward . 192.168.1.1
}
```
