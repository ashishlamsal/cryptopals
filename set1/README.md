# Set 1 : Basics

## Challenge 3 : Single-byte XOR cipher

When encrypting a string using single-byte XOR cipher we are actually **substituting** each plaintext character with another one. The problem with substitution ciphers is that they are susceptible of frequency analysis, meaning that it's possible to deduce the plaintext by the frequency distribution of the ciphertext. Assuming that the plaintext is English text, we can implement following:

Since the possible keys are a small number (255 ascii characters) we can do an exhaustive search, trying every possible key and scoring the obtained plaintexts to spot the most English-like. We use the character frequency as a way to score an English plaintext.


## Challenge 6 : Break repeating-key XOR

Given the plaintext **P=[p0, p1, .., pn]** the key K=[k0, k1, .., km] and assuming that the plaintext is much longer than the key m<n, the resulting ciphertext C=[c0, c1, .., cn] is computed as:


```
Ci = E(Pi) = (Pi ⊕ K(i%(m+1)))

p0-p1-p2-p3-p4-p5-p6-p7-p8-p9
k0-k1-k2-k0-k1-k2-k0-k1-k2-k0
-----------------------------
c0-c1-c2-c3-c4-c5-c6-c7-c8-c9
```

If we find the keylength *m* we can treat this problem to the single-byte XOR, since for every m characters we encrypt the plaintext with the same value. To find the keylengh it is suggested to try different keysize and pick the ones that will lead to a lower hamming distance between the blocks in the ciphertext.

## Challenge 7 : AES in ECB mode

![https://laconicwolf.com/wp-content/uploads/2018/05/cryptopals_challenge_7_002.png](https://laconicwolf.com/wp-content/uploads/2018/05/cryptopals_challenge_7_002.png)

## Challenge 8 : Detect AES in ECB mode

AES-ECB is detectible if the data encoded has two identical blocks. If the plaintext does not have two identical blocks, it is not possible to detect ECB mode. With that being said, we need to implement a duplicate checker.

The general strategy is as follows:

- Separate the ciphertext into chunks by taking blocks of 16 bytes
- Calculate the duplicates chunks in the ciphertext
- If duplicates are 1 or above, return True that ECB is used.

## References

- Wikipedia contributors. (2021, May 27). XOR cipher. Wikipedia. [https://en.wikipedia.org/wiki/XOR_cipher](https://en.wikipedia.org/wiki/XOR_cipher)
- Wikipedia contributors. (2021c, June 6). Block cipher mode of operation. Wikipedia. [https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)