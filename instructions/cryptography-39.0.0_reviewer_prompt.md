### Review Priority

When reviewing CodeQL findings for this cryptography library, prioritize validation of:

#### Memory Safety & Type Validation
- **CWE-680**: Integer Overflow
- **CWE-754**: Improper Check for Unusual or Exceptional Conditions

### Key Validation Criteria

#### 1. Exploitability Assessment
- **Can attacker control buffer inputs?** Can untrusted data be passed to low-level operations?
- **What can be achieved?** Can mismatched buffer types corrupt data or bypass type safety?
- **Reachability?** Is the code in commonly-used cipher or cryptographic operations?
- **Impact scope?** Can this affect data integrity or cause memory corruption?

#### 2. Context Analysis
- **Trace data flow**: Cryptographic data input → buffer protocol operations → output handling
- **Type checking**: Where buffer mutability or type validation may be insufficient
- **Boundary validation**: Size checks and writable buffer constraints
- **FFI interactions**: Direct memory access through foreign function interfaces

#### 3. True Positive Indicators
- Immutable objects can be passed where writable buffers are expected
- Missing validation of buffer mutability before write operations
- Type-unsafe buffer conversions without proper constraints
- Affects common cipher update or encryption operations
- Direct memory writes without verifying buffer properties (e.g., readonly flags)
- Code accepts buffer protocol objects without enforcing write capability

#### 4. False Positive Indicators
- Buffer mutability is validated before write operations
- Proper type checks prevent misuse of immutable objects
- FFI bindings enforce writable buffer constraints
- Input from trusted sources only with guaranteed mutability

### Critical Focus Areas

- Cipher update and data processing operations
- Buffer protocol implementations and conversions
- FFI writable buffer validation
- Type safety in encryption/decryption operations
- We mostly care about openssl backend issues in update methods
- Check if require_writable parameters are absent or incorrect and how they affect the code

### Example

Can this snippet lead to memory issues:
```
>>> outbuf = b"\x00" * 32
>>> c = ciphers.Cipher(AES(b"\x00" * 32), modes.ECB()).encryptor()
>>> c.update_into(b"\x00" * 16, outbuf)
```

**You MUST use ALL iterations available to you**
