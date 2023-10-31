from Crypto.Hash import keccak
from ecdsa import ellipticcurve, numbertheory, SECP256k1
import secrets
from eth_abi import encode
from collections import defaultdict
import math

curve = SECP256k1.curve
p = curve.p()
n = SECP256k1.order
G = SECP256k1.generator

# Determine a second generator H based on G such that the relationship H = iG is unknown.
H_x = int.from_bytes(keccak.new(digest_bits=256).update(G.to_bytes()).digest(), "big") % p
H_y = 0
H = ellipticcurve.INFINITY
# Find the nearest valid x coordinate that maps to a point on the curve.
while True:
    # If we're able to derive an Y-coordinate with this then H must be on-curve.
    try:
        alpha = (pow(H_x, 3, p) + (curve.a() * H_x) + curve.b()) % p
        beta = numbertheory.square_root_mod_prime(alpha, p)
        H_y = p - beta
    except:
        pass
    H = ellipticcurve.PointJacobi(curve, H_x, H_y, 1)
    # Ensure generator candidate H has the same cyclic group order as G.
    if n*H == ellipticcurve.INFINITY and 1*H != ellipticcurve.INFINITY:
        break
    # Or keep looking...
    H_x = (H_x + 1) % p
H_v = 28 if (H_y & 1) else 27

# Precalculate -aH points.
iaH = []
for i in range(8):
    a = 2**i
    aH = a*H
    iaH.append(-ellipticcurve.Point(curve, aH.x(), aH.y(), n))

# For initializing immutables (calculating those values here is cheaper).
config = encode(['uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256','uint256'], [G.x(), G.y(), H.x(), H.y(), H_v, n, iaH[0].x(), iaH[0].y(), iaH[1].x(), iaH[1].y(), iaH[2].x(), iaH[2].y(), iaH[3].x(), iaH[3].y(), iaH[4].x(), iaH[4].y(), iaH[5].x(), iaH[5].y(), iaH[6].x(), iaH[6].y(), iaH[7].x(), iaH[7].y()])
print(f"Constructor config: 0x{config.hex()}\n")


# Generates the contract call necessary to make a deposit.
def deposit(to, amount):
    blindingFactor = secrets.randbelow(n) + 1
    # C = xG + aH
    C = blindingFactor*G + amount*H
    # Print instructions.
    print(f"Send transaction from {to}")
    print(f"""ConfidentialTransactionValues.deposit{{ value: {int(amount)} }}({{
        C_x = {C.x()},
        C_y = {C.y()},
        blindingFactor = {blindingFactor}
    }})\n""")
    return (C, blindingFactor, amount)


# Generates the contract call necessary to make a withdrawal.
def withdraw(owner, utxo):
    (C, blindingFactor, amount) = utxo
    # Print instructions.
    print(f"Send transaction from {owner}")
    print(f"""ConfidentialTransactionValues.withdraw({{
        C_x = {C.x()},
        C_y = {C.y()},
        blindingFactor = {blindingFactor},
        amount = {int(amount)}
    }})\n""")


# Generates the contract call necessary to make a transfer.
def transfer(owner, utxosIn, receivers, amounts):
    # Sum blindingFactors.
    blindingFactorsInSum = (sum(utxo[1] for utxo in utxosIn) % n)
    # Generate new commitments.
    utxosOut = []
    rangeProofs = []
    blindingFactorsOutSum = 0
    for i, receiver in enumerate(receivers):
        # Determine blinding factor.
        blindingFactor = secrets.randbelow(n) + 1
        # Last blinding factor needs to be determined deterministically for sum(xIn) == sum(xOut).
        if len(receivers) == i + 1:
            blindingFactor = (n - blindingFactorsOutSum) + blindingFactorsInSum
            if blindingFactor > n:
                blindingFactor = blindingFactorsInSum - blindingFactorsOutSum
        blindingFactorsOutSum = (blindingFactorsOutSum + blindingFactor) % n
        # C = xG + aH
        C = blindingFactor*G + amounts[i]*H
        utxosOut.append((C, blindingFactor, amounts[i]))
        # Generate Range Proof.
        if len(receivers) > 1:
            rangeProofs.append(proofRange(C, blindingFactor, amounts[i]))
    # Sanity checks and print instructions.
    assert blindingFactorsInSum == blindingFactorsOutSum
    assert (sum(utxo[2] for utxo in utxosIn) % n) == sum(amounts)
    print(f"Send transaction from {owner}")
    print(f"""ConfidentialTransactionValues.transfer({{
        Cin_x = [{', '.join('"'+str(utxo[0].x())+'"' for utxo in utxosIn)}],
        Cin_y = [{', '.join('"'+str(utxo[0].y())+'"' for utxo in utxosIn)}],
        receivers = [{', '.join('"'+address+'"' for address in receivers)}],
        Cout_x = [{', '.join('"'+str(utxo[0].x())+'"' for utxo in utxosOut)}],
        Cout_y = [{', '.join('"'+str(utxo[0].y())+'"' for utxo in utxosOut)}],
        Cout_proofs = [{', '.join('"0x'+rangeProof.hex()+'"' for rangeProof in rangeProofs)}]
    }})\n""")
    return utxosOut

# Creates a Range Proof for the given Commitment.
def proofRange(C, blindingFactor, amount):
    # Determine integer mantissa and exponent for amount.
    exponent = 0
    if amount > 0:
        while amount != int(amount):
            amount *= 10
            exponent -= 1
        while amount % 10 == 0 and amount != 0:
            amount /= 10
            exponent += 1
    assert amount < 2**8
    # Summing the blinding factors of sub-commitments should result in the
    # target Commitment's blindingFactor / 10**exponent.
    targetBlindingFactor = blindingFactor * pow(10**exponent, -1, n)
    # Split mantissa into sub-commitments.
    rings = []
    subBlindingFactorsSum = 0
    subCommitmentsSum = ellipticcurve.INFINITY
    for i in range(7, -1, -1):
        subAmount = 2**i
        if amount >= subAmount:
            amount -= subAmount
        else:
            subAmount = 0
        # Determine blinding factor.
        subBlindingFactor = secrets.randbelow(n) + 1
        # Last blinding factor needs to be determined deterministically.
        if i == 0:
            subBlindingFactor = (n - subBlindingFactorsSum) + targetBlindingFactor
            if subBlindingFactor > n:
                subBlindingFactor = targetBlindingFactor - subBlindingFactorsSum
        subBlindingFactorsSum = (subBlindingFactorsSum + subBlindingFactor) % n
        # C = xG + aH
        Ci = subBlindingFactor*G + subAmount*H
        rings.insert(0, [
            (Ci, subBlindingFactor if subAmount == 0 else 0),
            (Ci + iaH[i], subBlindingFactor if subAmount != 0 else 0)
        ])
        subCommitmentsSum += Ci
    assert ((10**exponent)*subBlindingFactorsSum % n) == blindingFactor
    assert ((10**exponent)*subCommitmentsSum) == C
    # Generate Ring Signature.
    (e0, x, y, s) = signature = sign(C, rings)
    return encode(["(uint256[],uint256[],uint256,uint256,uint256[][])"], [(x, y, exponent, e0, s)])

# Signs a commitment with a structure of rings of 8 sub-commitments:
#
# [ [ (C1, bf) (C1 - 1*H, 0) ], [ (C2, 0) (C2 - 2*H, bf) ], ..., [ (C128, 0) (C128 - 128*H, bf) ] ]
# ^ ^                        ^  ^                        ^       ^                              ^ ^
# ^ ^-------- Ring 0 --------^  ^-------- Ring 1 --------^       ^----------- Ring 7 -----------^ ^
# ^                                                                                               ^
# ^--------------------------------------- Borromean Rings ---------------------------------------^
#
# The "private key" used to sign is the blinding factor (bf). When the sub-commitment can be used
# for signing as-is that means it encodes a 0-value. Otherwise a power-of-two is encoded as an amount
# which can only be signed for, when subtracting that power from the sub-commitment first.
#
# Returns: (e0, x[], y[], s[][])
#
# Where x and y are the coordinates of the first commitment in each ring (the mantissa sub-commitments).
#
def sign(C, rings):
    # Determine x and y of each sub-commitment and create message with commitment.
    x = [ring[0][0].x() for ring in rings]
    y = [ring[0][0].y() for ring in rings]
    M = hash([C.x(), C.y(), x, y], ["uint256", "uint256", "uint256[]", "uint256[]"])

    # Create Chameleon Hashes for each signer.
    k = defaultdict(int)
    e = defaultdict(lambda: defaultdict(int))
    signer_idx = defaultdict(int)
    for i, ring in enumerate(rings):
        # Random scalar for Chameleon Hash (later replaced by e & s).
        k[i] = secrets.randbelow(n) + 1

        for j, (Ci, bf) in enumerate(ring):
            # Set Chameleon Hash as e of signer.
            if bf != 0:
                # e = hash(m, address(kG * r^(-1)))
                R = (k[i] * G) * numbertheory.inverse_mod(Ci.x(), n)
                address = '0x' + keccak.new(digest_bits=256).update(R.to_bytes()).digest()[-20:].hex()
                e[i][j + 1] = hash([M, address, i, j], ["uint256", "address", "uint8", "uint8"])
                # Remember signer's index in current ring.
                signer_idx[i] = j

    # Determine e for each sub-commitment after signer.
    s = defaultdict(lambda: defaultdict(int))
    for i, ring in enumerate(rings):
        for j in range(signer_idx[i] + 1, len(ring)):
            (Ci, _) = ring[j]
            # Random scalar s for non-signers.
            s[i][j] = secrets.randbelow(n) + 1
            # e' = hash(m, address((eP - sG) * r^(-1)))
            R = (e[i][j]*Ci + (-(s[i][j] * G))) * numbertheory.inverse_mod(Ci.x(), n)
            address = '0x' + keccak.new(digest_bits=256).update(R.to_bytes()).digest()[-20:].hex()
            e[i][j + 1] = hash([M, address, i, j], ["uint256", "address", "uint8", "uint8"])

    # Gather the last e value for each ring (e[i][-1]).
    ring_ends = [e[i][max(e[i].keys())] for i in e]
    # And determine e0 based on each ring's last sub-commitment.
    e0 = hash([ring_ends], ["uint256[]"])

    # Starting from e0, determine e for each sub-commitment before the signer.
    for i, ring in enumerate(rings):
        e[i][0] = e0
        for j in range(signer_idx[i]):
            (Ci, _) = ring[j]
            # Random scalar s for non-signers.
            s[i][j] = secrets.randbelow(n) + 1
            # e' = hash(m, address((eP - sG) * r^(-1)))
            R = (e[i][j]*Ci + (-(s[i][j] * G))) * numbertheory.inverse_mod(Ci.x(), n)
            address = '0x' + keccak.new(digest_bits=256).update(R.to_bytes()).digest()[-20:].hex()
            e[i][j + 1] = hash([M, address, i, j], ["uint256", "address", "uint8", "uint8"])

    # Finally, calculate s for each Chameleon Hash to replace k with.
    for i, ring in enumerate(rings):
        j = signer_idx[i]
        (Ci, bf) = ring[j]
        s[i][j] = (e[i][j]*bf - k[i]) % n
        # Sanity-check: Hash with s & e should be the same as hash with k.
        R_ = (e[i][j]*Ci + (-(s[i][j] * G))) * numbertheory.inverse_mod(Ci.x(), n)
        address_ = '0x' + keccak.new(digest_bits=256).update(R_.to_bytes()).digest()[-20:].hex()
        e_ = hash([M, address_, i, j], ["uint256", "address", "uint8", "uint8"])
        assert e[i][j + 1] == e_

    return (e0, x, y, [ [s[i][j] for j in sorted(s[i])] for i in sorted(s) ])

def hash(data, encoding):
    return int.from_bytes(keccak.new(digest_bits=256).update(encode(encoding, data)).digest(), 'big') % n

# ---------------------- Playground ----------------------------------

alice = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
bob = "0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2"
eve = "0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2"

print("Alice makes a deposit")
utxo1 = deposit(alice, 1.42e18)

print("Alice sends it to Bob and Eve")
utxos2 = transfer(alice, [utxo1], [bob, eve], [1e18, 0.42e18])

print("Bob makes a withdrawal")
withdraw(bob, utxos2[0])