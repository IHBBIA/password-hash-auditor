import math
import re
import hashlib
import bcrypt
import getpass

COMMON_WEAK_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "admin",
    "welcome", "letmein", "iloveyou", "passw0rd", "admin123"
}

def calculate_entropy(password):
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 32

    if pool_size == 0:
        return 0.0
    return round(len(password) * math.log2(pool_size), 2)

def estimate_crack_time(entropy_bits):
    # Assumes an offline GPU cluster testing 10 billion (10^10) guesses/sec
    guesses = 2 ** entropy_bits
    seconds = guesses / 1e10

    if seconds < 1:
        return "Instant (< 1 second)"
    elif seconds < 60:
        return f"{round(seconds, 1)} seconds"
    elif seconds < 3600:
        return f"{round(seconds / 60, 1)} minutes"
    elif seconds < 86400:
        return f"{round(seconds / 3600, 1)} hours"
    elif seconds < 31536000:
        return f"{round(seconds / 86400, 1)} days"
    else:
        years = seconds / 31536000
        if years > 1e9:
            return "Billions of years"
        return f"{round(years, 1)} years"

def audit_password_policy(password):
    issues = []
    if len(password) < 12:
        issues.append("Length is under 12 characters (NIST/enterprise minimum).")
    if not re.search(r"[A-Z]", password):
        issues.append("Missing at least one uppercase letter (A-Z).")
    if not re.search(r"[a-z]", password):
        issues.append("Missing at least one lowercase letter (a-z).")
    if not re.search(r"[0-9]", password):
        issues.append("Missing at least one numeric digit (0-9).")
    if not re.search(r"[^a-zA-Z0-9]", password):
        issues.append("Missing at least one special symbol (!@#$%^&*).")
    if password.lower() in COMMON_WEAK_PASSWORDS:
        issues.append("CRITICAL: Matches a known breached/dictionary password.")
    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains 3 or more repeated consecutive characters.")

    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)

    return {
        "passed": len(issues) == 0,
        "issues": issues,
        "entropy_bits": entropy,
        "estimated_crack_time": crack_time
    }

def demonstrate_hashing(password):
    # Legacy fast hashes (Vulnerable to GPU rainbow/dictionary attacks)
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()

    # Modern slow salted hash (Resistant to brute-force)
    salt = bcrypt.gensalt(rounds=12)
    bcrypt_hash = bcrypt.hashpw(password.encode(), salt).decode()

    return md5_hash, sha256_hash, bcrypt_hash

if __name__ == "__main__":
    print("=" * 60)
    print("🔐 Enterprise Password Policy & Cryptographic Hash Auditor")
    print("=" * 60)

    # Uses getpass so passwords aren't echoed to terminal logs
    user_pwd = getpass.getpass("Enter a password to audit (input hidden): ")

    if not user_pwd:
        print("Error: Password cannot be empty.")
        exit(1)

    report = audit_password_policy(user_pwd)

    print("\n--- [1] Policy Compliance Report ---")
    if report["passed"]:
        print("✅ STATUS: COMPLIANT (Meets all enterprise complexity rules)")
    else:
        print("❌ STATUS: NON-COMPLIANT")
        for issue in report["issues"]:
            print(f"   - {issue}")

    print(f"\n--- [2] Entropy & Brute-Force Resistance ---")
    print(f"   - Bit Entropy:         {report['entropy_bits']} bits")
    print(f"   - Offline GPU Crack:   {report['estimated_crack_time']}")

    md5_h, sha256_h, bcrypt_h = demonstrate_hashing(user_pwd)
    print(f"\n--- [3] Cryptographic Storage Comparison ---")
    print(f"   - Unsalted MD5 (Legacy/Unsafe):     {md5_h}")
    print(f"   - Unsalted SHA-256 (Fast/Unsafe):   {sha256_h}")
    print(f"   - Salted bcrypt (Work Factor 12):   {bcrypt_h}")

    print(f"\n--- [4] Live Hash Verification Test ---")
    verify_pwd = getpass.getpass("Re-enter password to verify against bcrypt hash: ")
    is_valid = bcrypt.checkpw(verify_pwd.encode(), bcrypt_h.encode())
    print("✅ Match Confirmed!" if is_valid else "❌ Verification Failed: Passwords do not match.")
