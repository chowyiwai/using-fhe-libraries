#include "params.h"
#include <palisade.h>

using namespace lbcrypto;

map<int, BGVrnsParam> BGVrnsParam::ParamSets = {

    // BgvRnsParam(p, n, sigma, securityLevel, multDepth)
    {1, BGVrnsParam(PlaintextModulus(536903681), 65536, 3.2, HEStd_128_classic, 3)}, // taken from palisade `depth-bgvrns.cpp`
    {2, BGVrnsParam(PlaintextModulus(536903681), 32768, 3.2, HEStd_128_classic, 3)},
    {3, BGVrnsParam(PlaintextModulus(536903681), 16384, 3.2, HEStd_128_classic, 3)},
    {4, BGVrnsParam(PlaintextModulus(536903681), 16384, 3.2, HEStd_128_classic, 1)},
    {5, BGVrnsParam(PlaintextModulus(536903681), 16384, 3.2, HEStd_128_classic, 0)}, // expected to fail
    {6, BGVrnsParam(PlaintextModulus(207748), 8192, 3.2, HEStd_128_classic, 1)}
};

map<int, BGVParam> BGVParam::ParamSets = {

    // BgvParam(p, m, relinWindow, stdDev, q)
    // BgvParam(p, m, numOfBits, relinWindow, stdDev)
    {1, BGVParam(PlaintextModulus(207755), 131072, 1, 2, BigInteger("1073872897"))}, // expected to fail
    {2, BGVParam(PlaintextModulus(207755), 131072, 1, 2, BigInteger("1074266113"))}, // expected to fail
    {3, BGVParam(PlaintextModulus(207749), 256, 60, 1, 4)},
    {4, BGVParam(PlaintextModulus(207749), 128, 60, 1, 4)},
    {5, BGVParam(PlaintextModulus(207749), 64, 60, 1, 4)},
    {6, BGVParam(PlaintextModulus(207749), 8192, 70, 1, 4)},
    {7, BGVParam(PlaintextModulus(207749), 16384, 80, 1, 4)},
    {8, BGVParam(PlaintextModulus(207749), 65536, 100, 1, 4)},
    {9, BGVParam(PlaintextModulus(207749), 65536, 90, 1, 4)},
    {10, BGVParam(PlaintextModulus(207749), 65536, 80, 1, 4)}
};

map<int, CKKSParam> CKKSParam::ParamSets = {

    // CkksParam(m, numPrimes, scaleExp, relinWindow, batchSize)
    // CKKSParam(multDepth, scaleFactorBits, batchSize, securityLevel, n)
    {1, CKKSParam(131072, 1, 57, 10, 5)}, // expected to fail (because multDepth/numPrimes is too low)
    {2, CKKSParam(5, 50, 8, HEStd_128_classic, 0)},
    {3, CKKSParam(2097152, 1, 47, 10, 5)}, // expected to fail (because multDepth/numPrimes is too low)
    {4, CKKSParam(2097152, 6, 47, 10, 5)},
    {5, CKKSParam(2097152, 5, 47, 10, 5)},
    {6, CKKSParam(2097152, 3, 47, 10, 5)},
    {7, CKKSParam(2097152, 2, 47, 10, 5)},
    {8, CKKSParam(256, 2, 52, 10, 5)},
    {9, CKKSParam(256, 2, 58, 10, 5)},
    {10, CKKSParam(8192, 4, 40, 10, 5)},
    {11, CKKSParam(16384, 4, 40, 10, 5)},
    {12, CKKSParam(32768, 4, 40, 10, 5)}
};

