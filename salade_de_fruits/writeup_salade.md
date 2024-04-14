
# Salade de fruits - FCSC 2024 - Writeup - GMO_Goat

![meme](meme_salad.jpeg)

Problem statement :

```python
from itertools import count
from hashlib import sha256

for p in count(start = 1):
  for s in range(1, p + 1):
    for b in range(1, p + 1):
      if p ** 3 + s ** 3 == 94 * b ** 3:
        h = sha256(str(b).encode()).hexdigest()
        print(f"FCSC{{{h}}}")
        exit(1)
```

This is a classic problem of cubic equation, it turns out that every cubic equation (that is not degenerate) is isomorphic to an Elliptic Curve, sagemath has a conveniant function for that, so let's quickly look at the isomorphism (and its inverse function) :

```python
P = QQ["p, s, b"]
p, s, b = P.gens()

eq = p ** 3 - 94 * b ** 3 + s ** 3

f = EllipticCurve_from_cubic(eq)
print(f)
fi = f.inverse()
print(fi)
```

we get :

```
Scheme morphism:
  From: Projective Plane Curve over Rational Field defined by p^3 + s^3 - 94*b^3
  To:   Elliptic Curve defined by y^2 - 846*y = x^3 - 238572 over Rational Field
  Defn: Defined on coordinates by sending (p : s : b) to
        (-b : -3*p : -1/282*p - 1/282*s)
Scheme morphism:
  From: Elliptic Curve defined by y^2 - 846*y = x^3 - 238572 over Rational Field
  To:   Projective Plane Curve over Rational Field defined by p^3 + s^3 - 94*b^3
  Defn: Defined on coordinates by sending (x : y : z) to
        (-1/3*y : 1/3*y - 282*z : -x)
```

We want a solution with :

- $ 1 \le p$
- $ 1 \le s \le p$
- $ 1 \le b \le p$

We know its "easy" to find and iterate over points on an elliptic curve which by isomorphism will correspond to solutions of the equation, but we have to deal with the constraints...

Well, I just iterated from a generator of the curve until I found a solution with the constrains, not sure if it would work in the general case but it's always good to try your first idea and see what comes next, for me that was an immediate flag so I'm fine with my solution🐐,

And because we're working in the projective plane normalized in Z for elliptic curves, we have to bring back the solution from $\mathbb Q$ to $\mathbb Z$ which is done by multiplying $p_s$ and $s_s$ by their corresponding lcm.

```python
from sage.all import *
from itertools import count
from hashlib import sha256

P = QQ["p, s, b"]
p, s, b = P.gens()
eq = p ** 3 - 94 * b ** 3 + s ** 3

f = EllipticCurve_from_cubic(eq)
fi = f.inverse()

E = f.codomain()
G = E.gen(0)

for i in count(start = 1):
    ps, ss, bs = fi(i*G)
    if (ps > 0 and ss > 0 and bs > 0):
        y = lcm(ps.denom(), ss.denom())
        ps *= y
        ss *= y
        bs *= y

        h = sha256(str(bs).encode()).hexdigest()

        print(f"FCSC{{{h}}}")
        exit()
```

flag : ```FCSC{2c69e5056f2a80af36c0880a2395472e51b448730a1c5c06b2b0d8e0a3b466b6}```