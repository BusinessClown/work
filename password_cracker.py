#!/usr/bin/env python3
import hashlib, itertools, time, sys, os
# Check for required files
print(os.path.exists('passwords.txt'))
print(os.path.exists('dictionary.txt'))

def sha1(s):
    return hashlib.sha1(s.encode()).hexdigest()

def crack(password_file):
    # Load hashes
    hashes = {}
    with open(password_file) as f:
        for idx, line in enumerate(f, 1):
            parts = line.strip().split()
            hashes[parts[0] if len(parts) == 1 else parts[1]] = parts[0] if len(parts) == 2 else str(idx)
    
    cracked, attempts, start = {}, 0, time.time()
    
    total_hashes = len(hashes)
    def check(pwd):
        nonlocal attempts
        attempts += 1
        h = sha1(pwd)
        if h in hashes and h not in cracked:
            cracked[h] = pwd
            print(f"[+] UserID: {hashes[h]}, SHA-1-HASH {h}: {pwd}")
            del hashes[h]
            if 0 == len(hashes):print("[+] All passwords cracked!")
            return True
        return False
    
    # Attack 1: Digits 1-10
    for length in range(1, 11):
        if 0 == len(hashes): break
        for combo in itertools.product('0123456789', repeat=length):
            if check(''.join(combo)) and 0 == len(hashes): break
            if 0 == len(hashes): break
    
    # Attack 2-4: Dictionary (auto-detect, handle BOM)
    if os.path.exists('dictionary.txt'):
        with open('dictionary.txt', encoding='utf-8-sig') as f:
            words = [w.strip() for w in f if w.strip()]
        
        for word in words:
            if check(word.lower()) and 0 == len(hashes): break
            if 0 == len(hashes): break
        
        priority = sorted([w for w in words if len(w) <= 19], key=lambda x: (len(x), x))
        for w1, w2 in itertools.product(priority, repeat=2):
            combo = (w1 + w2).lower()
            if 1 <= len(combo) <= 80:
                if check(combo) and 0 == len(hashes): break
                if 0 == len(hashes): break
        
        for word in words:
            if 0 == len(hashes): break
            for digits in range(0, 10000):
                if check(word.lower() + str(digits))  and 0 == len(hashes): break
                if 0 == len(hashes): break
    
    # Results

    elapsed = time.time() - start
    print(f"\n{'='*60}")
    print(f"Cracked: {len(cracked)}/{total_hashes} ({100*len(cracked)/total_hashes:.0f}%)")
    print(f"Time: {elapsed:.1f}s | Attempts: {attempts:,}")
    print(f"{'='*60}")
    
    with open('cracked_passwords.txt', 'w') as f:
        f.write("User ID, SHA-1-HASH, PASSWORD\n")
        for h, pwd in cracked.items():
            f.write(f"{hashes[h]} {h} {pwd}\n")
    print("[+] Results saved to cracked_passwords.txt")

if __name__ == '__main__':
    crack(sys.argv[1] if len(sys.argv) > 1 else 'passwords.txt')
