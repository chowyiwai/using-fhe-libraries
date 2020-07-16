#include "params.h"
#include <palisade.h>

using namespace lbcrypto;

map<int, BgvRnsParam> BgvRnsParam::ParamSets = {

    // BgvRnsParam(p, n, sigma, securityLevel, multDepth)
    {1, BgvRnsParam(PlaintextModulus(536903681), 65536, 3.2, HEStd_128_classic, 3)}, // taken from palisade `depth-bgvrns.cpp`
    {2, BgvRnsParam(PlaintextModulus(536903681), 32768, 3.2, HEStd_128_classic, 3)},
    {3, BgvRnsParam(PlaintextModulus(536903681), 16384, 3.2, HEStd_128_classic, 3)},
    {4, BgvRnsParam(PlaintextModulus(536903681), 16384, 3.2, HEStd_128_classic, 1)},
    {5, BgvRnsParam(PlaintextModulus(536903681), 16384, 3.2, HEStd_128_classic, 0)}, // expected to fail
    {6, BgvRnsParam(PlaintextModulus(207748), 8192, 3.2, HEStd_128_classic, 1)}
};

map<int, BgvParam> BgvParam::ParamSets = {

    // BgvParam(p, m, relinWindow, stdDev, q)
    // BgvParam(p, m, numOfBits, numOfTowers, relinWindow, stdDev)
    //{1, BgvParam(PlaintextModulus(207755), 131072, 1, 2, BigInteger("1073872897"))}, // expected to fail
    //{2, BgvParam(PlaintextModulus(207755), 131072, 1, 2, BigInteger("1074266113"))}, // expected to fail
    //{3, BgvParam(PlaintextModulus(207749), 256, 60, 1, 1, 4)},
    //{4, BgvParam(PlaintextModulus(207749), 128, 60, 1, 1, 4)},
    {5, BgvParam(PlaintextModulus(207749), 64, 60, 1, 1, 4)},
    {6, BgvParam(PlaintextModulus(207749), 8192, 70, 1, 1, 4)},
    {7, BgvParam(PlaintextModulus(207749), 16384, 80, 1, 1, 4)},
    {8, BgvParam(PlaintextModulus(207749), 65536, 100, 1, 1, 4)},
    {9, BgvParam(PlaintextModulus(207749), 65536, 90, 1, 1, 4)},
    {10, BgvParam(PlaintextModulus(207749), 65536, 80, 1, 1, 4)}
};

