#set document(title: "Documentatie AES si AES-GCM")
#set page(margin: 2.2cm)
#set text(size: 11pt)

= Documentatie AES si AES-GCM

== AES

AES este un cifru simetric pe blocuri. Blocul de intrare are mereu 128 de biti, adica 16 octeti. Cheia poate avea 128, 192 sau 256 de biti. In cod, `AESCipher.__init__` verifica lungimea cheii si calculeaza:

- `Nk = len(key) / 4`, numarul de cuvinte de 32 de biti din cheie.
- `Nr = Nk + 6`, numarul de runde: 10 pentru AES-128, 12 pentru AES-192, 14 pentru AES-256.

=== Reprezentarea starii

AES lucreaza intern cu o matrice `4 x 4` de octeti numita stare. In `block.py`, `Block.as_state` interpreteaza blocul in ordine pe coloane:

```text
state[r][c] = data[r + 4*c]
```

Aceasta este reprezentarea standard AES. `Block.from_state` face conversia inversa la finalul criptarii sau decriptarii.

=== Operatii in corpul finit GF(2^8)

AES trateaza fiecare octet ca pe un polinom cu coeficienti in `GF(2)`. De exemplu, bitii octetului sunt coeficientii polinomului:

```text
b7*x^7 + b6*x^6 + ... + b1*x + b0
```

Operatiile se fac in corpul finit:

```text
GF(2^8) = GF(2)[x] / (x^8 + x^4 + x^3 + x + 1)
```

Polinomul ireductibil AES este reprezentat hexadecimal prin `0x11B`. Deoarece rezultatul trebuie sa ramana un octet, orice termen `x^8` aparut la inmultire este redus modulo acest polinom.

Adunarea si scaderea in `GF(2^8)` sunt acelasi lucru: XOR pe biti. Motivul este ca in `GF(2)` avem `1 + 1 = 0`, deci nu exista transport ca in aritmetica intreaga.

==== xtime

Functia `xtime` din `gf256.py` inmulteste un octet cu `x`, adica cu valoarea `0x02`, in `GF(2^8)`.

```python
def xtime(value: int) -> int:
    value &= 0xFF
    result = value << 1
    if value & 0x80:
        result ^= 0x1B
    return result & 0xFF
```

Pasii sunt:

1. `value &= 0xFF` pastreaza numai cei 8 biti ai octetului.
2. `value << 1` inmulteste polinomul cu `x`.
3. Daca bitul cel mai semnificativ era `1`, dupa deplasare apare un termen `x^8`.
4. Din relatia `x^8 = x^4 + x^3 + x + 1 mod (x^8 + x^4 + x^3 + x + 1)`, reducerea se face prin XOR cu `00011011`, adica `0x1B`.
5. `& 0xFF` elimina orice bit peste dimensiunea unui octet.

Motivul pentru `xtime` este eficienta: inmultirea cu `2` apare des in `MixColumns`, iar orice inmultire cu un octet poate fi construita prin inmultiri repetate cu `x` si XOR.

==== Inmultirea generala gf_mul

`gf_mul(a, b)` din `gf256.py` implementeaza inmultirea a doi octeti in `GF(2^8)` prin metoda shift-and-add:

```python
for _ in range(8):
    if b & 1:
        result ^= a
    a = xtime(a)
    b >>= 1
```

Interpretarea este:

- Daca bitul curent din `b` este `1`, termenul curent `a` contribuie la rezultat si este adaugat prin XOR.
- `a = xtime(a)` muta termenul la urmatoarea putere a lui `x`.
- `b >>= 1` trece la urmatorul bit al multiplicatorului.

Astfel, `gf_mul(a, 3)` este echivalent cu `xtime(a) xor a`, iar constantele `9`, `11`, `13` si `14` folosite la decriptare sunt calculate prin aceeasi functie generala.

=== Structura criptarii AES

`AESCipher.encrypt_block` implementeaza exact structura AES:

```text
state = plaintext
AddRoundKey(state, round_key[0])

for round = 1 .. Nr-1:
    SubBytes(state)
    ShiftRows(state)
    MixColumns(state)
    AddRoundKey(state, round_key[round])

SubBytes(state)
ShiftRows(state)
AddRoundKey(state, round_key[Nr])
```

Ultima runda nu contine `MixColumns`. Aceasta este o proprietate a algoritmului AES, nu o optimizare locala.

==== KeyExpansion

Inainte de criptare, AES extinde cheia initiala intr-o lista de chei de runda. Codul este in `_expand_key`.

Pasii sunt:

1. Cheia este impartita in cuvinte de 4 octeti.
2. Pentru fiecare cuvant nou `w[i]`, se porneste de la copia lui `w[i-1]`.
3. Daca `i % Nk == 0`, se aplica:
   - `RotWord`: rotire la stanga cu un octet.
   - `SubWord`: aplicarea S-box pe fiecare octet.
   - XOR intre primul octet si constanta de runda `RCON`.
4. Pentru AES-256, daca `Nk > 6` si `i % Nk == 4`, se aplica suplimentar `SubWord`.
5. Cuvantul nou devine:

```text
w[i] = w[i-Nk] xor temp
```

Ratiunea este ca fiecare cheie de runda depinde neliniar de cheia initiala. `SubWord` introduce neliniaritate, `RotWord` muta pozitiile octetilor, iar `RCON` impiedica simetriile intre runde.

==== AddRoundKey

`_add_round_key` combina starea cu cheia rundei prin XOR:

```text
state[r][c] = state[r][c] xor round_key[c][r]
```

Aceasta este singura operatie AES care introduce material secret direct in stare. XOR este folosit deoarece adunarea in corpurile binare este XOR, iar operatia este propria inversa: aplicarea aceluiasi XOR a doua oara anuleaza cheia.

==== SubBytes

`_sub_bytes` inlocuieste fiecare octet al starii cu valoarea corespunzatoare din `S_BOX`. Inversul este `_inv_sub_bytes`, care foloseste `INV_S_BOX`.

Matematic, S-box-ul AES este construit prin:

1. invers multiplicativ in `GF(2^8)`, cu exceptia lui `0`, care ramane `0`;
2. transformare afina peste `GF(2)`.

Ratiunea este introducerea neliniaritatii. Fara `SubBytes`, toate celelalte transformari ar fi liniare sau afine si cifrul ar fi mult mai usor de atacat.

In implementare, valorile sunt precompute in tabele. Astfel, criptarea nu calculeaza inversul in corpul finit la fiecare octet, ci face doar indexare in `S_BOX`.

==== ShiftRows

`_shift_rows` roteste fiecare rand al starii spre stanga:

```text
randul 0: rotire cu 0 pozitii
randul 1: rotire cu 1 pozitie
randul 2: rotire cu 2 pozitii
randul 3: rotire cu 3 pozitii
```

Codul foloseste:

```python
state[r] = state[r][r:] + state[r][:r]
```

Inversul, `_inv_shift_rows`, roteste spre dreapta cu acelasi numar de pozitii. Ratiunea este difuzia intre coloane: dupa `ShiftRows`, octetii care erau in aceeasi coloana ajung in coloane diferite, iar `MixColumns` ii combina cu octeti din alte pozitii.

==== MixColumns

`_mix_columns` trateaza fiecare coloana ca pe un vector de 4 octeti si o inmulteste cu o matrice fixa peste `GF(2^8)`.

```text
b0 = 02*a0 xor 03*a1 xor 01*a2 xor 01*a3
b1 = 01*a0 xor 02*a1 xor 03*a2 xor 01*a3
b2 = 01*a0 xor 01*a1 xor 02*a2 xor 03*a3
b3 = 03*a0 xor 01*a1 xor 01*a2 xor 02*a3
```

In cod:

```python
state[0][c] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3
state[1][c] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3
state[2][c] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3)
state[3][c] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2)
```

Toate inmultirile sunt in `GF(2^8)`, deci `02*a` inseamna `xtime(a)`, iar `03*a` inseamna `xtime(a) xor a`.

Ratiunea este difuzia: modificarea unui singur octet din coloana influenteaza toti cei 4 octeti ai coloanei rezultate. Matricea este aleasa astfel incat transformarea sa fie inversabila.

==== Runda finala

Runda finala executa doar:

```text
SubBytes
ShiftRows
AddRoundKey
```

`MixColumns` este omis pentru a pastra structura standard AES si pentru a permite decriptarea cu transformari inverse clare. Securitatea este data de toate rundele impreuna, nu de prezenta `MixColumns` in ultima runda.

=== Structura decriptarii AES

`AESCipher.decrypt_block` aplica operatiile inverse in ordine inversa:

```text
state = ciphertext
AddRoundKey(state, round_key[Nr])

for round = Nr-1 .. 1:
    InvShiftRows(state)
    InvSubBytes(state)
    AddRoundKey(state, round_key[round])
    InvMixColumns(state)

InvShiftRows(state)
InvSubBytes(state)
AddRoundKey(state, round_key[0])
```

`_inv_mix_columns` foloseste matricea inversa:

```text
b0 = 0e*a0 xor 0b*a1 xor 0d*a2 xor 09*a3
b1 = 09*a0 xor 0e*a1 xor 0b*a2 xor 0d*a3
b2 = 0d*a0 xor 09*a1 xor 0e*a2 xor 0b*a3
b3 = 0b*a0 xor 0d*a1 xor 09*a2 xor 0e*a3
```

Constantele sunt tot elemente din `GF(2^8)`, iar implementarea foloseste `gf_mul` pentru a evita tabele separate.

== Implementarea AES in cod

Fluxul principal este concentrat in clasa `AESCipher`:

- Constructorul valideaza cheia, seteaza `nk`, `nr` si apeleaza `_expand_key`.
- `encrypt_block` transforma cei 16 octeti in stare, aplica rundele AES si reconstruieste blocul rezultat.
- `decrypt_block` face aceeasi conversie, dar aplica operatiile inverse.
- `S_BOX`, `INV_S_BOX` si `RCON` sunt constantele standard AES.
- `_mix_columns` si `_inv_mix_columns` folosesc `gf_mul` din `gf256.py`.

Separarea in `Block`, `gf256` si `AESCipher` face ca reprezentarea datelor, aritmetica in corp finit si logica rundelor AES sa fie usor de urmarit separat.

== AES-GCM

GCM, de la Galois/Counter Mode, combina doua componente:

- CTR mode pentru confidentialitate.
- GHASH pentru autentificarea datelor.

Rezultatul criptarii este perechea `(ciphertext, tag)`. Decriptarea este acceptata numai daca tag-ul recalculat se potriveste cu tag-ul primit.

=== Counter mode in general

Counter mode transforma AES dintr-un cifru pe blocuri intr-un generator de flux. In loc sa cripteze direct plaintext-ul, AES cripteaza blocuri de contor:

```text
S1 = AES_K(counter_1)
S2 = AES_K(counter_2)
...
C1 = P1 xor S1
C2 = P2 xor S2
...
```

Decriptarea este identica:

```text
P1 = C1 xor S1
P2 = C2 xor S2
```

Motivul este ca XOR cu acelasi flux se inverseaza singur. CTR nu necesita padding, deoarece ultimul bloc poate folosi doar primii octeti necesari din fluxul AES.

In GCM, contoarele sunt blocuri de 128 de biti. Functia `_inc32` incrementeaza numai ultimii 32 de biti:

```python
upper = counter >> 32
lower = ((counter & 0xFFFFFFFF) + 1) & 0xFFFFFFFF
return ((upper << 32) | lower) & _MASK_128
```

`_ctr_crypt` porneste de la `Y0`/`J0`, incrementeaza contorul inaintea fiecarui bloc si cripteaza `Y1`, `Y2`, etc. Acelasi cod este folosit pentru criptare si decriptare.

Conditia importanta de securitate este ca perechea `(key, IV)` sa nu fie refolosita pentru mesaje diferite. Refolosirea produce acelasi flux CTR si compromite confidentialitatea.

=== GHASH function

GHASH este functia de autentificare din GCM. Ea nu cripteaza datele, ci comprima AAD-ul si ciphertext-ul intr-o valoare de 128 de biti care intra in calculul tag-ului.

Mai intai se calculeaza subcheia hash:

```text
H = AES_K(0^128)
```

In cod:

```python
h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
```

GHASH lucreaza in `GF(2^128)`, nu in `GF(2^8)`. Polinomul de reducere pentru GCM este:

```text
x^128 + x^7 + x^2 + x + 1
```

Codul foloseste constanta:

```python
_REDUCTION_POLY = 0xE1000000000000000000000000000000
```

Functia `_gf_mul(x, y)` din `gcm.py` implementeaza inmultirea in `GF(2^128)` pe reprezentare big-endian:

```python
z = 0
v = y
for i in range(128):
    if (x >> (127 - i)) & 1:
        z ^= v
    if v & 1:
        v = (v >> 1) ^ _REDUCTION_POLY
    else:
        v >>= 1
```

Ratiunea este aceeasi ca la `GF(2^8)`: adunarea este XOR, iar inmultirea este inmultire de polinoame urmata de reducere modulo polinomul ireductibil. Diferenta este dimensiunea, 128 de biti, si conventia GCM de procesare a bitilor.

`_ghash(h, aad, ciphertext)` proceseaza:

1. toate blocurile AAD, completand ultimul bloc cu zero daca este incomplet;
2. toate blocurile ciphertext, completand ultimul bloc cu zero daca este incomplet;
3. un bloc final de lungimi:

```text
len(AAD in bits) || len(ciphertext in bits)
```

Formula iterativa este:

```text
Y_0 = 0
Y_i = (Y_{i-1} xor X_i) * H
GHASH = Y_n
```

In cod, `_iter_blocks` transforma datele in blocuri de 16 octeti si completeaza cu zero prin `ljust`. Blocul de lungimi este construit astfel:

```python
length_block = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
```

Blocul de lungimi este necesar pentru a separa fara ambiguitate cazuri in care concatenari diferite ar produce aceeasi succesiune de blocuri dupa padding.

=== Existence of Y0

GCM are nevoie de un bloc initial de contor, numit in standard `J0` si notat frecvent ca `Y0` in explicatii. In cod, variabila se numeste `j0`, iar comentariile de debug folosesc `Y0`.

Pentru IV de 96 de biti, cazul recomandat si cel mai eficient, se defineste:

```text
Y0 = IV || 0x00000001
```

In cod:

```python
if len(iv) == 12:
    return int.from_bytes(iv + b"\x00\x00\x00\x01", "big")
```

Motivul este ca un IV de 96 de biti lasa exact 32 de biti pentru contor. Primul bloc de date foloseste `Y1 = inc32(Y0)`, nu `Y0`.

Pentru IV-uri cu alta lungime, GCM comprima IV-ul prin GHASH:

```python
return cls._ghash(h, b"", iv)
```

Astfel orice IV, indiferent de lungime, este transformat intr-un bloc de 128 de biti compatibil cu CTR. `Y0` este folosit la calculul tag-ului prin `AES_K(Y0)`, iar blocurile de date folosesc contoarele incrementate.

=== Tag

Tag-ul GCM autentifica AAD-ul si ciphertext-ul. Dupa ce se calculeaza:

```text
S = GHASH_H(AAD, ciphertext)
```

tag-ul complet este:

```text
T = AES_K(Y0) xor S
```

Implementarea este in `_compute_tag`:

```python
s = cls._ghash(h, aad, ciphertext)
ek_j0 = int.from_bytes(aes.encrypt_block(j0.to_bytes(16, "big")), "big")
full_tag = (s ^ ek_j0).to_bytes(16, "big")
return full_tag[:tag_length]
```

`AES_K(Y0)` mascheaza rezultatul GHASH cu o valoare dependenta de cheie. `tag_length` permite trunchierea tag-ului intre 1 si 16 octeti, dar tag-urile mai scurte reduc siguranta autentificarii.

La decriptare, codul recalculeaza tag-ul asteptat si il compara cu `hmac.compare_digest`. Daca tag-ul nu este valid, se arunca:

```text
ValueError("Authentication failed: invalid GCM tag")
```

Semnificatia tag-ului este integritatea si autenticitatea: orice modificare in ciphertext, AAD, IV sau cheie duce la un tag diferit.

=== AAD

AAD inseamna Additional Authenticated Data. Aceste date nu sunt criptate, dar sunt autentificate.

Exemple de AAD:

- antete de protocol;
- nume de fisier;
- versiuni de format;
- metadate care trebuie sa ramana vizibile, dar protejate impotriva modificarii.

In implementare, AAD este primit ca parametru optional:

```python
encrypt_data(plaintext, iv, aad=b"", key=None)
decrypt_data(ciphertext, tag, iv, aad=b"", key=None)
```

AAD este introdus in GHASH inaintea ciphertext-ului. Daca AAD-ul folosit la decriptare difera de AAD-ul folosit la criptare, tag-ul recalculat nu mai corespunde si decriptarea esueaza.

=== Implementarea GCM in cod

Fluxul `encrypt_data` este:

1. obtine instanta AES prin `_resolve_aes`;
2. calculeaza `H = AES_K(0^128)`;
3. deriveaza `Y0`/`J0` din IV prin `_derive_j0`;
4. cripteaza plaintext-ul cu `_ctr_crypt`;
5. calculeaza tag-ul cu `_compute_tag`;
6. returneaza `(ciphertext, tag)`.

Fluxul `decrypt_data` este:

1. valideaza lungimea tag-ului;
2. obtine AES si recalculeaza `H`;
3. deriveaza acelasi `Y0` din IV;
4. aplica CTR pentru a obtine plaintext-ul;
5. recalculeaza tag-ul peste AAD si ciphertext;
6. compara tag-urile cu `hmac.compare_digest`;
7. returneaza plaintext-ul numai daca autentificarea reuseste.

Separarea pe functii face clara structura GCM:

- `_inc32`: avansarea contoarelor CTR.
- `_gf_mul`: inmultirea in `GF(2^128)`.
- `_ghash`: autentificarea AAD si ciphertext.
- `_derive_j0`: obtinerea blocului initial `Y0`.
- `_ctr_crypt`: criptarea/decriptarea in counter mode.
- `_compute_tag`: combinarea GHASH cu `AES_K(Y0)`.

== Verificare

Vectorii de test din `test_vectors` sunt folositi de `gui/test_vectors_runner.py`. Pentru AES se verifica atat criptarea, cat si decriptarea pentru chei de 128, 192 si 256 de biti. Pentru GCM se verifica obtinerea perechii ciphertext/tag si decriptarea autentificata.
