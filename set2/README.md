# Set 2 : Block Crypto

## Challenge 10 : Implement CBC mode

```
Encryption
Ci = E(Ki, Pi ⊕ Ci−1)

Decryption
Pi = D(Ki, Ci) ⊕ Ci−1
```

![https://images3.programmersought.com/736/c1/c1e9aa41f47037b3d73a9b1f96de40c8.png](https://images3.programmersought.com/736/c1/c1e9aa41f47037b3d73a9b1f96de40c8.png)

## Challenge 12 : Byte-at-a-time ECB decryption (Simple)

We have to write the ECB oracle function in such a way that the ciphertext C gets computed by encrypting a string made up by appending a secret text S to the plaintext P passed to the oracle function. Both S and key K used for the encryption are secret.

```
C = oracle(P) = E(P|S, K)
```

What we get to know is C and P and we want to find S. We'll see that once we guess the blocksize, if ECB cipher mode is used, we can find S without recovering the key K.

For the sake of the explanation let `S = [s0,s1,s2,s3,s4,s5,s6,s7,s8,s9]`, keeping in mind that we don't know it's value and let the block size be `bsize=4`. Giving the oracle a plaintext crafted in such a way that its length is just one byte short of the block size `P0=[p0,p1,p2]` we end up with: `oracle(P0) = E(P0|S, K) = C0`

```
|p0 p1 p2 s0 |s1 s2 s3 s4 |s5  s6  s7  s8 |
|k1 k2 k3 k4 |k1 k2 k3 k4 |k1  k2  k3  k4 |
-------------------------------------------
|c0 c2 c3 c4 |c5 c6 c7 c8 |c9 c10 c11 c12 |
```

If we focus on the first block we see that `C0=[c0,c1,c2,c3]` is the result of encrypting `[p0,p1,p2,s0]`. Since we know `P0`, we can find `s0` by making repeated call to the oracle function trying all possible value of `s0` until we get a ciphertext whose first block corresponds to `C0`. In other words we are feeding the oracle a crafted plaintexts `TP0=[p0,p1,p2,x0]`for every possible value of `x0` until the first block `oracle(TP0)[0:4]=oracle(P0)[0:4]`, for which `x0=s0`. Once we find `x0` we managed to find the first byte `s0` of the secret text.

We can clear the whole first block by repeating the steps before and reducing each time the length of the plaintext by one byte. For example, to get the second byte `s1` we feed the oracle `P1=[p0,p1]`: `oracle(P1)=E(P1|S,K)=C1`

```
|p0 p1 s0 s1 |s2 s3 s4 s5 |s6  s7  s8  s9 |
|k1 k2 k3 k4 |k1 k2 k3 k4 |k1  k2  k3  k4 |
-------------------------------------------
|c0 c2 c3 c4 |c5 c6 c7 c8 |c9 c10 c11 c12 |
```

Since now we know `s0=x0` we are exactly in the same situation as before. We feed the oracle a crafted plaintext `TP1=[p0,p1,x0,x1]` trying every possible value for `x1` until the first block of `oracle(TP1)`and `oracle(C1)` are equal, then we have found `x1=s1`.

Once we're done with the first block we can move to the next ones, using the same strategy but instead of comparing the first block we look at the n-block. For example, with the second block we start again with `P0=[p0,p1,p2]`and `oracle(P0)=E(P0|S,K)=C0`

```
|p0 p1 p2 s0 |s1 s2 s3 s4 |s5  s6  s7 s8 |
|k1 k2 k3 k4 |k1 k2 k3 k4 |k1  k2  k3 k4 |
------------------------------------------
|c0 c2 c3 c4 |c5 c6 c7 c8 |c9 c10 c11 c12|
```

The difference is that this time we are interested in `s4`, since we have already recovered the first 4 bytes of `S` in `X=[x0,x1,x2,x3]`, so now we're looking at the second block. We try again every possible value for `x4` feeding the oracle function `TP=[P0|X|x4]` until we find `x4` for which the second block of `oracle(TP)` is equal to the second block of `oracle(P0)`

## Challenge 13 : ECB cut-and-paste

Cut and paste the ciphertexts in such a way that, once decrypted, we get the desired plaintext. The goal is to craft a ciphertext whose plaintext will have the role field set to `admin`. As a reminder, the encoded profile has this structure: `email=foo@bar.com&uid=10&role=user`

Since ECB is being used, every blocks is encrypted independently by the others and with the same, so we can shuffle around the blocks in the ciphertext and we will end up with a plaintext with the corresponding blocks moved around. If `C` is the original ciphertext with 4 blocks `cn: C=[c0,c1,c2,c3,c4]` and we move the blocks around `Cshuffle=[c2,c4,c1,c3]` the result of the decryption `Pshuffle=D(Cshuffle,K)` will be `Pshuffle=[p2,p4,p1,p3]`.

## Challenge 14 : Byte-at-a-time ECB decryption (Harder)

This exercise is similar to the number 12, with a slight difference that now the oracle function also prepend a random string of random values `R` to the plaintext. Keeping the same meaning for the others variables, the oracle can be described as:

```
C = oracle(P) = E(R|P|S, K)
```

We can reuse the same strategy and by noticing that if we make sure that the last block of the random text is completely filled, the problem is exactly the same, we just have to skip the initial blocks containing the random string `R`.

This is what we need:

- the number of bytes needed to fill the last block used by the random string `R`
- the number of blocks (after the "filling") used by `R`
- `blocksize` of the ciphertext

## Challenge 16 : CBC bitflipping attacks

Cipher Block Chaining (CBC) mode decryption has following properties : 

- by editing one ciphertext block, the corresponding plaintext block will be destroyed.
- the other effect of changing bits in one ciphertext block, is that the next block plaintext will be XORED against a different value, effectively flipping the plaintext bits.

The strategy used to complete this exercise is:

- Find out how long the random prefix is.
- Craft the attacker controlled plaintext in such a way that it will:
    - Fill completely one block with a known value, say "empty block"
    - Fill the adjacent block with the target value. In our case the target value is the string we're trying to inject, replacing the forbidden values that will otherwise be quoted out by encryption function.
- Encrypt the crafted plaintext
- Flip the right bits in the "empty block" ciphertext in such way that when decrypting the modified ciphertext we'll get the desired output in the "target block" plaintext.

*How do we know which bits we have to flip?*

We know the position of the bytes in the "target block" we want to change, so we have to change the corresponding bytes in the "empty block". The value of the bytes in the empty block that will lead to our desired result can be found using equation below, here `p1` is the position in the block where we want to change the value:

```
(D(CTargetBlock,K) ⊕ CEmptyBlock)[p1] = PTargetBlock[p1]
(D(CTargetBlock,K) ⊕ CEmptyBlock)[p1] ⊕ PTargetBlock[p1] ⊕ Tvalue = PTargetBlock[p1] ⊕ PTargetBlock[p1] ⊕ Tvalue
(D(CTargetBlock,K) ⊕ CEmptyBlock)[p1] ⊕ PTargetBlock[p1] ⊕ Tvalue = Tvalue
```

So to get the right value to substitute in the ciphertext we have to XOR the ciphertext byte in the empty block with the plaintext in the target block and XOR it again with the value we want to see in the plaintext.

## **References**

- Wikipedia contributors. (2021a, February 25). PKCS 7. Wikipedia. [https://en.wikipedia.org/wiki/PKCS_7](https://en.wikipedia.org/wiki/PKCS_7)
- Writeups. [http://unstable.xyz/pages/projects.html](http://unstable.xyz/pages/projects.html)

