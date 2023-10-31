 // SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "https://github.com/chronicleprotocol/scribe/blob/main/src/libs/LibSecp256k1.sol";

library Secp256k1 {
    using LibSecp256k1 for LibSecp256k1.JacobianPoint;

    uint256 public constant p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // Sums two lists of affine points (using jacobi addition) and compares them without affine conversion.
    function makeSumsAndCompare(
        uint256[] calldata A_x, uint256[] calldata A_y,
        uint256[] calldata B_x, uint256[] calldata B_y
    ) public pure returns (bool) {
        if (A_x.length == 1 && B_x.length == 1) {
            return (A_x[0] == B_x[0] && A_y[0] == B_y[0]);
        }
        (uint256 A_sum_x, uint256 A_sum_y, uint256 A_sum_z) = jacobiSumAffinePoints(A_x, A_y);
        (uint256 B_sum_x, uint256 B_sum_y, uint256 B_sum_z) = jacobiSumAffinePoints(B_x, B_y);
        // eqJacobian() from https://github.com/nucypher/numerology/blob/master/contracts/Numerology.sol
        unchecked {
            if(B_sum_z == 0) {
                return A_sum_z == 0;
            } else if(A_sum_z == 0) {
                return false;
            }
            uint256 A_sum_z_squared = mulmod(A_sum_z, A_sum_z, p);
            uint256 B_sum_z_squared = mulmod(B_sum_z, B_sum_z, p);
            if (mulmod(B_sum_x, A_sum_z_squared, p) != mulmod(A_sum_x, B_sum_z_squared, p)) {
            return false;
            }
            uint256 A_sum_z_cubed = mulmod(A_sum_z_squared, A_sum_z, p);
            uint256 B_sum_z_cubed = mulmod(B_sum_z_squared, B_sum_z, p);
            return mulmod(B_sum_y, A_sum_z_cubed, p) == mulmod(A_sum_y, B_sum_z_cubed, p);
        }
    }

    // Sums a list of affine points and returns the affine sum point.
    function sumAffinePoints(
        uint256[] calldata x,
        uint256[] calldata y
    ) public pure returns (uint256, uint256) {
        (uint256 sum_x, uint256 sum_y, uint256 sum_z) = jacobiSumAffinePoints(x, y);
        return toAffine(sum_x, sum_y, sum_z);
    }

    // Adds to affine points and returns the affine result.
    function affineAdd(uint256 A_x, uint256 A_y, uint256 B_x, uint256 B_y) public pure returns (uint256, uint256) {
        // addAffineJacobian() from https://github.com/nucypher/numerology/blob/master/contracts/Numerology.sol
        unchecked {
            uint256 a   = A_x;
            uint256 c   = A_y;
            uint256 t0  = B_x;
            uint256 t1  = B_y;
            if ((a == t0) && (c == t1)) {
                uint256 z = 1;
                uint256 x = a;
                uint256 _2y = mulmod(2, c, p);
                uint256 _4yy = mulmod(_2y, _2y, p);
                uint256 s = mulmod(_4yy, x, p);
                uint256 m = mulmod(3, mulmod(x, x, p), p);
                uint256 t = addmod(mulmod(m, m, p), mulmod(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d, s, p),p);
                uint256 D_y = addmod(mulmod(m, addmod(s, p - t, p), p), mulmod(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17, mulmod(_4yy, _4yy, p), p), p);
                uint256 D_z = mulmod(_2y, z, p);
                return toAffine(t, D_y, D_z);
            }
            uint256 d = addmod(t1, p-c, p);
            uint256 b = addmod(t0, p-a, p);
            uint256 e = mulmod(b, b, p);
            uint256 f = mulmod(e, b, p);
            uint256 g = mulmod(a, e, p);
            uint256 C_x = addmod(mulmod(d, d, p), p-addmod(mulmod(2, g, p), f, p), p);
            uint256 C_y = addmod(mulmod(d, addmod(g, p-C_x, p), p), p-mulmod(c, f, p), p);
            return toAffine(C_x, C_y, b);
        }
    }

    // Sums a list of affine points and returns the jacobi sum point.
    function jacobiSumAffinePoints(
        uint256[] calldata x,
        uint256[] calldata y
    ) public pure returns (uint256, uint256, uint256) {
        LibSecp256k1.JacobianPoint memory P_sum = LibSecp256k1.JacobianPoint(x[0], y[0], 1);
        for (uint256 idx = 1; idx < x.length; idx++) {
            P_sum.addAffinePoint(LibSecp256k1.Point(x[idx], y[idx]));
        }
        return (P_sum.x, P_sum.y, P_sum.z);
    }

    // toAffine() from https://github.com/chronicleprotocol/scribe/blob/main/src/libs/LibSecp256k1.sol
    function toAffine(uint256 x, uint256 y, uint256 z)
        public
        pure
        returns (uint256, uint256)
    {
        uint256 zInv = _invMod(z);
        uint256 zInv_square = mulmod(zInv, zInv, p);
        uint256 affine_x = mulmod(x, zInv_square, p);
        uint256 affine_y = mulmod(y, mulmod(zInv, zInv_square, p), p);
        return (affine_x, affine_y);
    }
    // Precalculation of z^(-1) saves 98% of gas.
    function toAffine(uint256 x, uint256 y, uint256 z, uint256 zInv)
        public
        pure
        returns (uint256, uint256)
    {
        require(mulmod(z, zInv, p) == 1);
        uint256 zInv_square = mulmod(zInv, zInv, p);
        uint256 affine_x = mulmod(x, zInv_square, p);
        uint256 affine_y = mulmod(y, mulmod(zInv, zInv_square, p), p);
        return (affine_x, affine_y);
    }
    // _invMod() from https://github.com/chronicleprotocol/scribe/blob/main/src/libs/LibSecp256k1.sol
    function _invMod(uint256 x) private pure returns (uint256) {
        uint256 t;
        uint256 q;
        uint256 newT = 1;
        uint256 r = p;
        assembly ("memory-safe") {
            for {} x {} {
                q := div(r, x)
                let tmp := t
                t := newT
                newT := addmod(tmp, sub(p, mulmod(q, newT, p)), p)
                tmp := r
                r := x
                x := sub(tmp, mul(q, x))
            }
        }
        return t;
    }
}
