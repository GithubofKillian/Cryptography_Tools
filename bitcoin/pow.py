#!/usr/bin/env python3

import argparse, hashlib, sys, datetime # do not use any other imports/libraries

# took 2 hours (please specify here how much time your solution required)

## Output of running `pow.py --difficulty 26`:
## [+] Solved in 27.864736 sec (0.8173 Mhash/sec)
## [+] Input: 4b696c6c69616e4a6f6e6e6561757800000000015b7e5a
## [+] Solution: 00000034dd754610666ef1052ede56eb8b155418284626d3556221b114d926de
## [+] Nonce: 22773338

# parse arguments
parser = argparse.ArgumentParser(description='Proof-of-work solver')
parser.add_argument('--difficulty', default=0, type=int, help='Number of leading zero bits')
args = parser.parse_args()

# start of the timer
start_time = datetime.datetime.now()

nb_zero_byte = args.difficulty // 8
nb_remaining_zero_bit = args.difficulty % 8

# nonce we change at each turn in the loop incrementally
nonce = 0
# number of hash to get the ration
nb_hashes = 0

identity = b'KillianJonneaux'

while True:
    # convert nonce int to byte
    nonce_bytes = nonce.to_bytes(8, 'big')
    data = identity + nonce_bytes
    # double hashing with SHA256
    first_hash = hashlib.sha256(data).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    nb_hashes += 1

    # checking if nb_zero_byte are 0 bytes
    if  all(b == 0 for b in second_hash[:nb_zero_byte]):
        # check if there is remaing bits 0 needed (not checked for --difficulty 26)
        if nb_remaining_zero_bit > 0: 
            next_byte = second_hash[nb_zero_byte]
            if next_byte >> (8 - nb_remaining_zero_bit) != 0:
                nonce += 1
                # skip the rest of the loop and go to the next one
                continue
        break # We find one of the solution
    else : # try with another nonce
        nonce += 1

end_time = datetime.datetime.now()
total_time = (end_time - start_time).total_seconds()

# print results
input_hex = (identity + nonce_bytes).hex()
solution_hash = hashlib.sha256(hashlib.sha256(identity + nonce_bytes).digest()).hexdigest()
hash_rate = (nb_hashes / total_time) / 10**6

print(f"[+] Solved in {total_time:.6f} sec ({hash_rate:.4f} Mhash/sec)")
print(f"[+] Input: {input_hex}")
print(f"[+] Solution: {solution_hash}")
print(f"[+] Nonce: {nonce}")


