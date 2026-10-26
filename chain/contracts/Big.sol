// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Big
/// @notice 1024-bit modular arithmetic on the EVM, built on the modexp precompile (address 0x05).
/// The EVM has no big-integer multiplication, but squaring modulo p is one cheap precompile call, and
///     4ab = (a+b)^2 - (a-b)^2   (mod p)
/// gives multiplication from two squarings plus add/sub; division by 4 is exact after adding a multiple of p.
/// Numbers are 4 little-endian 256-bit limbs (a[0] = least significant).
library Big {
    function fromBytes(bytes memory b) internal pure returns (uint256[4] memory r) {
        require(b.length == 128, "len");
        for (uint256 i = 0; i < 4; i++) {
            uint256 w;
            assembly { w := mload(add(add(b, 32), mul(i, 32))) }
            r[3 - i] = w;
        }
    }

    function toBytes(uint256[4] memory a) internal pure returns (bytes memory b) {
        b = new bytes(128);
        for (uint256 i = 0; i < 4; i++) {
            uint256 w = a[3 - i];
            assembly { mstore(add(add(b, 32), mul(i, 32)), w) }
        }
    }

    function cmp(uint256[4] memory a, uint256[4] memory b) internal pure returns (int256) {
        for (uint256 i = 4; i > 0; i--) {
            if (a[i - 1] > b[i - 1]) return 1;
            if (a[i - 1] < b[i - 1]) return -1;
        }
        return 0;
    }

    function add(uint256[4] memory a, uint256[4] memory b) internal pure returns (uint256[4] memory r, bool carry) {
        unchecked {
            for (uint256 i = 0; i < 4; i++) {
                uint256 s = a[i] + b[i];
                bool c1 = s < a[i];
                uint256 s2 = s + (carry ? 1 : 0);
                bool c2 = s2 < s;
                r[i] = s2;
                carry = c1 || c2;
            }
        }
    }

    /// @dev requires a >= b
    function sub(uint256[4] memory a, uint256[4] memory b) internal pure returns (uint256[4] memory r) {
        unchecked {
            bool borrow;
            for (uint256 i = 0; i < 4; i++) {
                uint256 d = a[i] - b[i];
                bool b1 = a[i] < b[i];
                uint256 d2 = d - (borrow ? 1 : 0);
                bool b2 = d < (borrow ? 1 : 0);
                r[i] = d2;
                borrow = b1 || b2;
            }
        }
    }

    function addmod_(uint256[4] memory a, uint256[4] memory b, uint256[4] memory p) internal pure returns (uint256[4] memory r) {
        bool carry;
        (r, carry) = add(a, b);
        if (carry || cmp(r, p) >= 0) r = sub(r, p);      // wraps correctly mod 2^1024 when carry is set
    }

    function submod_(uint256[4] memory a, uint256[4] memory b, uint256[4] memory p) internal pure returns (uint256[4] memory) {
        if (cmp(a, b) >= 0) return sub(a, b);
        return sub(p, sub(b, a));
    }

    /// @dev out = base^exp mod mod  via the precompile; all byte strings big-endian.
    function modexp(bytes memory base, bytes memory exp, bytes memory mod_) internal view returns (bytes memory out) {
        bytes memory input = abi.encodePacked(base.length, exp.length, mod_.length, base, exp, mod_);
        out = new bytes(mod_.length);
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x05, add(input, 32), mload(input), add(out, 32), mload(out))
        }
        require(ok, "modexp");
    }

    function square(uint256[4] memory a, bytes memory pBytes) internal view returns (uint256[4] memory) {
        return fromBytes(modexp(toBytes(a), abi.encodePacked(uint256(2)), pBytes));
    }

    /// @dev (v + j*p) / 4 where j in 0..3 makes the sum divisible by 4 (p is odd, so this is v * 4^-1 mod p)
    function div4(uint256[4] memory v, uint256[4] memory p) internal pure returns (uint256[4] memory out) {
        uint256 r = v[0] & 3;
        uint256 j = ((4 - r) % 4) * ((p[0] & 3) == 1 ? 1 : 3) % 4;
        uint256[5] memory t;
        unchecked {
            for (uint256 i = 0; i < 4; i++) t[i] = v[i];
            for (uint256 k = 0; k < j; k++) {
                bool carry;
                for (uint256 i = 0; i < 4; i++) {
                    uint256 s = t[i] + p[i];
                    bool c1 = s < t[i];
                    uint256 s2 = s + (carry ? 1 : 0);
                    bool c2 = s2 < s;
                    t[i] = s2;
                    carry = c1 || c2;
                }
                if (carry) t[4] += 1;
            }
            for (uint256 i = 0; i < 4; i++) out[i] = (t[i] >> 2) | (t[i + 1] << 254);
        }
    }

    /// @notice a*b mod p for a, b < p
    function mulmod_(uint256[4] memory a, uint256[4] memory b, uint256[4] memory p, bytes memory pBytes)
        internal view returns (uint256[4] memory)
    {
        uint256[4] memory s2 = square(addmod_(a, b, p), pBytes);
        uint256[4] memory d2 = square(submod_(a, b, p), pBytes);
        return div4(submod_(s2, d2, p), p);
    }
}

/// @notice Thin wrapper so the library can be unit-tested against Python big integers.
contract BigTest {
    function mul(bytes calldata a, bytes calldata b, bytes calldata p) external view returns (bytes memory) {
        return Big.toBytes(Big.mulmod_(Big.fromBytes(a), Big.fromBytes(b), Big.fromBytes(p), p));
    }
}
