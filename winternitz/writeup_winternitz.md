
# Winternitz - FCSC 2024 - writeup - GMO_Goat

![meme](meme_winternitz.jpeg)

Looking at the scheme used it is clear that we have a Winternitz-OTS but with a different encoding, so clearly this is the vulnerable part.

So all we have to do is find a 20-bytes plaintext that encode to a 40-element vector with each coordinates being bigger then the ones present in the encoding of the known message.

However we are working mod 257, so we are essentially trying to find a vector $v$ that is decodable, such that if we denote $e$ the 40-element vector corresponding to the encoding of "WINTERNITZ IS COMING" then we want :

$$\forall i \in \llbracket 0, 39 \rrbracket, e[i] \le v[i] \le 257 \space \space (E)$$

What I mean by decodable is that, because the matrix that is used in the encoding step isn't square, not every 40-element vector will have a corresponding 20-byte plaintext, so if we denote $M$ the matrix used in the encoding step :

$$ M = \begin{pmatrix}
   S_1 & S_1^2  & S_1^3  & \cdots  & S_1^{20}  \\
   S_2 & S_2^2  & S_2^3  & \cdots  & S_2^{20}  \\
   S_3 & S_3^2  & S_3^3  & \cdots  & S_3^{20}  \\
   \vdots & \vdots & \vdots & \ddots & \vdots \\
   S_{40} & S_{40}^2  & S_{40}^3  & \cdots  & S_{40}^{20}  \\
\end{pmatrix}
, S_i : \text{Support[i - 1]}
$$

We need to find $v$ such that $v \in \text{Im}(M^T)$
Meaning we want a reduced basis of $M^T$ that has coordinates that satisfies (E).
Thus we want a vector close to :

$$T = \cfrac{1}{2}\begin{pmatrix}
   e[0] \\
   e[1] \\
   e[] \\\
   \cdots \\
   e[39]
\end{pmatrix} + \cfrac{1}{2}
\begin{pmatrix}
   257 \\
   257 \\
   257 \\\
   \cdots \\
   257
\end{pmatrix}$$

All thats that is left is to plug this into a Babai solver, but don't forget we're working in $\mathbb Z / 257 \mathbb Z$ so the lattice will be :

$$\mathcal L = \begin{pmatrix}
   S_1 & S_2  & S_3  & \cdots  & S_{40}  \\
   S_1^2 & S_2^2 & S_3^2  & \cdots  & S_{40}^2  \\
   S_1^3 & S_2^3 & S_3^3  & \cdots  & S_{40}^3  \\
   \vdots & \vdots & \vdots & \ddots & \vdots \\
   S_1^{20} & S_2^{20}  & S_3^{20}  & \cdots  & S_{40}^{20}  \\
   257 & 0  & 0  & \cdots  & 0  \\
   0 & 257  & 0  & \cdots  & 0  \\
   0 & 0  & 257  & \cdots  & 0  \\
   \vdots & \vdots & \vdots & \ddots & \vdots \\
   0 & 0  & 0  & \cdots  & 257  \\
\end{pmatrix}

$$

So now $A = \text{Babai\_CVP}(\mathcal l, T)$ should do the trick however :

```python
A = Babai_CVP(B2, T)
print(A)
for i in range(40):
    if not A[i] < 257:
        print(i, "too big :", A[i])
    if not (A[i] >= e[i]):
        print(i, "too small :", A[i])
```

returns that one or two components are slightly off... manual tweaking and trial and error ended up working for me.

```python
# hand tweaking is dirty but works
Tv = [(k + 257 - 1) // 2 for k in e]
Tv[23] -= 3
Tv[38] -= 1
Tv[23] += 1
T = vector(ZZ, Tv)

A = Babai_CVP(B2, T)
print(A)
for i in range(40):
    if not A[i] < 257:
        print(i, "too big :", A[i])
    if not (A[i] >= e[i]):
        print(i, "too small :", A[i])
```

After that all I had to do was recover the plaintext :

```python
K = GF(257, proof=False)
def _decoding(w):
    m_enc = vector(K, list(w))
    return bytes([ int(k) % 256 for k in M.solve_right(m_enc)])
Mess = _decoding(A)
```

However, another annoying thing... since converting to byte is mod 256 and not mod 257, we have to have a decoded $v$ with no component being 256, again this is rare (but happened to me 🐐) so manual tweaking again...

```python
# hand tweaking is dirty but works
Tv = [(k + 257 - 1) // 2 for k in e]
Tv[23] -= 3
Tv[38] -= 1
Tv[23] += 1
T = vector(ZZ, Tv)

A = Babai_CVP(B2, T)
print(A)
for i in range(40):
    if not A[i] < 257:
        print(i, "too big :", A[i])
    if not (A[i] >= e[i]):
        print(i, "too small :", A[i])

de = _decoding_partial(A)
if 256 in de:
    print("unlucky !! ")
```

And with that we can construct a valid plaintext, and "build up" the given signature to another one :

```python
for i in range(40):
    for j in range(e[i]+1, A[i]+1):
        sig[i] = _H(sig[i], pk[0], i, j)
```

and with that we get the flag : ```FCSC{e2987e3e48e51343df63218484d5e760faf5cf15c9f01a8649a483a91c31ce11}```

Complete script : 

```python
from sage.all import *
from hashlib import sha256
from pwn import remote
from ast import literal_eval
message = b"WINTERNITZ IS COMING"

########################

conn = remote("challenges.france-cybersecurity-challenge.fr", 2153)
print(conn.recvline())
print(conn.recvuntil(b" = "))
sig = literal_eval(conn.recvline().strip().decode())
print(conn.recvuntil(b" = "))
pk = literal_eval(conn.recvline().strip().decode())
########################

sig = [bytes.fromhex(k) for k in sig]
pk = (bytes.fromhex(pk[0]), [bytes.fromhex(k) for k in pk[1]])

Support = [
              8,  17,  26,  32,  52,  53,  57,  58,
             59,  63,  64,  66,  67,  71,  73,  76,
             79,  81, 111, 115, 132, 135, 141, 144,
            151, 157, 170, 176, 191, 192, 200, 201,
            202, 207, 216, 224, 228, 237, 241, 252,
        ]
W = 257

def _encoding(msg):
    w = [0] * len(Support)
    for i in range(len(Support)):
        for j in range(len(msg)):
            # Constant coefficient is zero
            w[i] += msg[j] * Support[i] ** (j + 1)
        w[i] %= W
    return w

### encoding done : is NOT bijective ...
K = Zmod(W)
M = [[pow(Support[i], (j + 1), W) for j in range(20)] for i in range(len(Support))]
M = matrix(K, M)


print(M)

def _decoding(w):
    m_enc = vector(K, list(w))
    return bytes([ int(k) % 256 for k in M.solve_right(m_enc)])

def _decoding_partial(w):
    m_enc = vector(K, list(w))
    return [ int(k) for k in M.solve_right(m_enc)]

###############
def _byte_xor(b1, b2):
    assert len(b1) == len(b2), "Error: byte strings of different length."
    return bytes([x ^ y for x, y in zip(b1, b2)])
    
def _H(s, m, i, j):
    return sha256(
        _byte_xor(
            s,
            sha256(
                m + i.to_bytes(1, "big") + j.to_bytes(2, "big")
            ).digest()
        )
    ).digest()

e = _encoding(message)

from tqdm import tqdm
load("solver.sage")

def vec1(n):
    a = [0] * 40
    a[n] = 257
    return a

B2L = [vector(ZZ, list(l)) for l in M.transpose()]

for i in range(40):
    B2L.append(vector(ZZ, vec1(i)))
B2 = matrix(ZZ, B2L)

# hand tweaking is dirty but works
Tv = [(k + 257 - 1) // 2 for k in e]
Tv[23] -= 3
Tv[38] -= 1
Tv[23] += 1
T = vector(ZZ, Tv)

A = Babai_CVP(B2, T)
print(A)
for i in range(40):
    if not A[i] < 257:
        print(i, "too big :", A[i])
    if not (A[i] >= e[i]):
        print(i, "too small :", A[i])

de = _decoding_partial(A)
if 256 in de:
    print("unlucky !! ")

assert _encoding(_decoding(A)) == list(A) # wont work if we get 256 in decoding_partial
A = [int(k) for k in list(A)]

for i in range(40):
    for j in range(e[i]+1, A[i]+1):
        sig[i] = _H(sig[i], pk[0], i, j)

def verif(message, signature):
    if len(message) > 20:
        print("Error: message too long.")
        return None
    sig2 = signature.copy()
    mask_seed, PK = pk

    w = _encoding(message)
    for i in range(40):
        for j in range(w[i] + 1, 257):
            sig2[i] = _H(sig2[i], mask_seed, i, j)

    return all(s == pk for s, pk in zip(sig2, PK))

Mess = _decoding(A)
print(verif(Mess, sig))

print("MESSAGE :", Mess.hex())
conn.recvuntil(b">>> ")
conn.sendline(Mess.hex().encode())
conn.recvuntil(b">>> ")
conn.sendline(str([k.hex() for k in sig]).encode())
print("SIGNATURE :", str([k.hex() for k in sig]) )

conn.interactive()
```
