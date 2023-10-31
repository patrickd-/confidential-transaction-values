 
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.18;

import "Secp256k1.sol";

contract ConfidentialTransactionValues {
    // Cyclic group parameters: C = xG + aH (mod n)
    uint256 immutable SECP256K1_G_x;
    uint256 immutable SECP256K1_G_y;
    uint256 immutable SECP256K1_H_x;
    uint256 immutable SECP256K1_H_y;
    uint256 immutable SECP256K1_H_v;
    uint256 immutable SECP256K1_n;
    // Range proof parameters.
    uint256 constant PROOF_bits = 8;
    uint256 constant PROOF_max_exponent = 24;
    uint256 constant PROOF_max_outputs = 10;
    // Pre-computed -aH Points.
    uint256 immutable i1H_x; uint256 immutable i1H_y;
    uint256 immutable i2H_x; uint256 immutable i2H_y;
    uint256 immutable i4H_x; uint256 immutable i4H_y;
    uint256 immutable i8H_x; uint256 immutable i8H_y;
    uint256 immutable i16H_x; uint256 immutable i16H_y;
    uint256 immutable i32H_x; uint256 immutable i32H_y;
    uint256 immutable i64H_x; uint256 immutable i64H_y;
    uint256 immutable i128H_x; uint256 immutable i128H_y;

    // Initializes immutables.
    constructor(bytes memory config) {
        (SECP256K1_G_x, SECP256K1_G_y, SECP256K1_H_x, SECP256K1_H_y, SECP256K1_H_v, SECP256K1_n, i1H_x, i1H_y, i2H_x, i2H_y, i4H_x, i4H_y, i8H_x, i8H_y, i16H_x, i16H_y, i32H_x, i32H_y, i64H_x, i64H_y, i128H_x, i128H_y) = abi.decode(config, (uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256));
    }

    // Managing unspent commitments (replaces token balances).
    mapping(address owner => mapping(bytes commitment => bool spendable)) internal unspentCommitments;
    function unspend(address receiver, uint256 C_x, uint256 C_y) internal {
        bytes memory commitment = abi.encode(C_x, C_y);
        require(!unspentCommitments[receiver][commitment], "Already an unspent commitment");
        unspentCommitments[receiver][commitment] = true;
    }
    function spend(address owner, uint256 C_x, uint256 C_y) internal {
        bytes memory commitment = abi.encode(C_x, C_y);
        require(unspentCommitments[owner][commitment], "Not an unspent commitment");
        unspentCommitments[owner][commitment] = false;
    }

    event Deposit(uint256 C_x, uint256 C_y, uint256 x, uint256 a);
    event Withdrawal(uint256 C_x, uint256 C_y, uint256 x, uint256 a);
    event Transfer(uint256[] Cin_x, uint256[] Cin_y, address[] receivers, uint256[] Cout_x, uint256[] Cout_y);

    /**
     * Depositing ETH
     *
     * The depositor needs to reveal the commitment amount to make sure that it is equal
     * to the actual ETH being deposited. The commitment's amount may be larger than the
     * maximum amount supported by the range proofs. It may be split by transfer() into
     * separate supported commitments, which also hides the amounts from that point on.
     */
    function deposit(uint256 C_x, uint256 C_y, uint256 blindingFactor) payable external {
        validateCommitment(C_x, C_y, blindingFactor, msg.value);
        unspend(msg.sender, C_x, C_y);
        emit Deposit(C_x, C_y, blindingFactor, msg.value);
    }

    /**
     * Withdrawing ETH
     *
     * When withdrawing, the owner of an unspent commitment needs to reveal the amount
     * so it can be validated before sending them that amount from the contract.
     */
    function withdraw(uint256 C_x, uint256 C_y, uint256 blindingFactor, uint256 amount) external {
        validateCommitment(C_x, C_y, blindingFactor, amount);
        spend(msg.sender, C_x, C_y);
        // Send ether.
        (bool success,) = msg.sender.call{ value: amount }("");
        if (!success) revert("Failed sending eth");
        emit Withdrawal(C_x, C_y, blindingFactor, amount);
    }

    /**
     * Internally transfers ETH balance
     *
     * While it'll be visible that receiver addresses own commitments, the actual amount
     * contained within the commitment will not be visible until it is withdrawn.
     */
    function transfer(
        uint256[] calldata Cin_x, uint256[] calldata Cin_y,   // The unspent commitments the sender wants to consume.
        address[] calldata receivers,                         // The receivers of the new commitments created.
        uint256[] calldata Cout_x, uint256[] calldata Cout_y, // The new commitments to store as unspent.
        bytes[] calldata Cout_proofs                          // The new commitment's range proofs.
    ) external {
        // Although unlikely to be possible, prevent amount-overflows via many outputs.
        require(Cout_x.length <= PROOF_max_outputs, "Too many outputs");

        // Validate that Input Sums are equal to Output Sums.
        require(Secp256k1.makeSumsAndCompare(Cin_x, Cin_y, Cout_x, Cout_y), "Inputs not equal to outputs");

        // Spend input commitments.
        for (uint256 i; i < Cin_x.length; i++) {
            spend(msg.sender, Cin_x[i], Cin_y[i]);
        }

        // Store output commitments for receivers.
        for (uint256 i; i < Cout_x.length; i++) {
            unspend(receivers[i], Cout_x[i], Cout_y[i]);
            // Only when more than one outputs are created, a range proof for each is required.
            // Otherwise we can assume the is range is valid based on the already proven inputs.
            if (Cout_x.length > 1) validateRangeProof(Cout_x[i], Cout_y[i], Cout_proofs[i]);
        }
        emit Transfer(Cin_x, Cin_y, receivers, Cout_x, Cout_y);
    }

    /**
     * Requires that the commitment holds for
     *   C = xG + aH
     *
     * (Mis-)Uses ecrecover as a widget to calculate xG + aH cheaply.
     */
    function validateCommitment(uint256 C_x, uint256 C_y, uint256 x, uint256 a) public view {
        // C0 = address(hash(C))
        address C0_address = address(uint160(uint256(keccak256(abi.encode(C_x, C_y)))));
        // C1 = address(hash(raH - (-x)rG) / r) = address(hash(aH - (-x)G))
        address C1_address = ecrecover(                                   // address(hash(sH - hG) / r)
            bytes32(mulmod(SECP256K1_n - x, SECP256K1_H_x, SECP256K1_n)), // h (normally a hash, instead -x*r)
            uint8(SECP256K1_H_v),                                         // v (to recover H's y-coordinate)
            bytes32(SECP256K1_H_x),                                       // r (H's x-coordinate)
            bytes32(mulmod(a, SECP256K1_H_x, SECP256K1_n))                // s (normally signature, instead a*r)
        );
        require(C0_address == C1_address, "Invalid commitment");
    }

    struct RangeProof {
        uint256[] Ci_x; uint256[] Ci_y; // Sub-commitments that sum up to commitment being validated...
        uint256 exponent;               // ...when multiplied with base-10 exponent.
        uint256 e0;                     // Borromean Ring Sig initialization vector.
        uint256[][] s;                  // Ring member's semi-random components.
    }

    /**
     * Validates a Range Proof for the specified commitment.
     */
    function validateRangeProof(uint256 C_x, uint256 C_y, bytes calldata rangeProof) public view {
        RangeProof memory proof = abi.decode(rangeProof, (RangeProof));
        uint256[8] memory iaH_x = [i1H_x, i2H_x, i4H_x, i8H_x, i16H_x, i32H_x, i64H_x, i128H_x];
        uint256[8] memory iaH_y = [i1H_y, i2H_y, i4H_y, i8H_y, i16H_y, i32H_y, i64H_y, i128H_y];
        require(proof.exponent <= PROOF_max_exponent, "Exponent is too large");
        require((proof.Ci_x.length == PROOF_bits) && (proof.Ci_y.length == PROOF_bits) && (proof.s.length == PROOF_bits), "Invalid proof bit-size");

        // Signed Message M = H(Commitment, Sub-commitments)
        uint256 M = uint256(keccak256(abi.encode(C_x, C_y, proof.Ci_x, proof.Ci_y))) % SECP256K1_n;

        // Validate the Ring Signature.
        // For each Bit there is a Ring i with two components (Ci, Ci - aH).
        uint256[] memory e = new uint256[](PROOF_bits);
        for (uint8 i; i < PROOF_bits; i++) {
            // Calculate in-between e based on e0 and the first Ring Member Ci.
            e[i] = next_e(proof.Ci_x[i], proof.Ci_y[i], proof.s[i][0], i, 0, proof.e0, M);
            // Calculate second Ring Member Ci-aH from first Member Ci.
            (uint256 Ci2_x, uint256 Ci2_y) = Secp256k1.affineAdd(proof.Ci_x[i], proof.Ci_y[i], iaH_x[i], iaH_y[i]);
            // Calculate final e based on e1 and the second Ring Member C2i = Ci-aH.
            e[i] = next_e(Ci2_x, Ci2_y, proof.s[i][1], i, 1, e[i], M);
        }
        // Each Ring's last e value builds e0 (e'0 = H(e, e, ...))
        require(proof.e0 == (uint256(keccak256(abi.encode(e))) % SECP256K1_n), "Invalid ring signature");

        // Now check whether the sub-commitments actually add up to the commitment being validated.
        (uint256 Ci_sum_x, uint256 Ci_sum_y) = Secp256k1.sumAffinePoints(proof.Ci_x, proof.Ci_y);
        uint8 Ci_sum_v = (Ci_sum_y & 1 == 1) ? 28 : 27; // Determine v based on y-coordinate's even/odd-ness.
        // (Mis-)Use ecrecover as a widget to calculate C_sum * 10**exponent.
        // C0 = address(hash(C))
        address C0_address = address(uint160(uint256(keccak256(abi.encode(C_x, C_y)))));
        // C1 = address(hash(((r * 10^exponent) * C_sum - 0G) / r))
        address C1_address = ecrecover(bytes32(0), Ci_sum_v, bytes32(Ci_sum_x), bytes32(mulmod(Ci_sum_x, 10**proof.exponent, SECP256K1_n)));
        require(C0_address == C1_address, "Invalid range proof for commitment");
    }
    function next_e(uint256 x, uint256 y, uint256 s, uint8 i, uint8 j, uint256 e, uint256 M) internal view returns (uint256) {
        // Determine v (parity) based on y-coordinate's even/odd-nes.
        uint8 v = (y & 1 == 1) ? 28 : 27;
        // (Mis-)Use ecrecover as a widget to calculate (eP - sG) * r^(-1)
        // e = hash(m, address(hash((eP - sG) * r^(-1))))
        address R = ecrecover(bytes32(s), v, bytes32(x), bytes32(e));
        require(R != address(0x0));
        return uint256(keccak256(abi.encode(M, R, i, j))) % SECP256K1_n;
    }

}
