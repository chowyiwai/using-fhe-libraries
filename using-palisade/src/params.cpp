#include "params.h"
#include <palisade.h>

using namespace lbcrypto;

map<int, BGVrnsParam> BGVrnsParam::ParamSets = {

    // Parameters in square brackets are optional to provide
    // BGVrnsParam(p, n, multDepth, [securityLevel], [sigma], [maxDepth], [mode], [ksTech])
    {1, BGVrnsParam(PlaintextModulus(207748), 8192, 1)},
    {2, BGVrnsParam(PlaintextModulus(207748), 16384, 1)},
    {3, BGVrnsParam(PlaintextModulus(207748), 32768, 1)},
    {4, BGVrnsParam(PlaintextModulus(207748), 65536, 1)},
    {5, BGVrnsParam(PlaintextModulus(207748), 131072, 1)},
    {6, BGVrnsParam(PlaintextModulus(207748), 262144, 1)},
    {7, BGVrnsParam(PlaintextModulus(536903681), 8192, 1)},
    {8, BGVrnsParam(PlaintextModulus(536903681), 16384, 1)},
    {9, BGVrnsParam(PlaintextModulus(536903681), 32768, 1)},
    {10, BGVrnsParam(PlaintextModulus(536903681), 65536, 1)} // taken from palisade `depth-bgvrns.cpp`

};

map<int, BGVParam> BGVParam::ParamSets = {

    // BGVParam(p, m, numOfBits, [relinWindow], [stdDev], [mode])
    {1, BGVParam(PlaintextModulus(207749), 32, 60)},
    {2, BGVParam(PlaintextModulus(6558547), 32, 60)},
    {3, BGVParam(PlaintextModulus(207749), 64, 60)},
    {4, BGVParam(PlaintextModulus(6558547), 64, 60)},
    {5, BGVParam(PlaintextModulus(207749), 128, 60)},
    {6, BGVParam(PlaintextModulus(6558547), 128, 60)},
    {7, BGVParam(PlaintextModulus(207749), 256, 60)},
    {8, BGVParam(PlaintextModulus(6558547), 256, 60)},
    {9, BGVParam(PlaintextModulus(207749), 512, 60)},
    {10, BGVParam(PlaintextModulus(6558547), 512, 60)},
    {11, BGVParam(PlaintextModulus(207749), 1024, 60)},
    {12, BGVParam(PlaintextModulus(6558547), 1024, 60)},
    {13, BGVParam(PlaintextModulus(207749), 4096, 70)},
    {14, BGVParam(PlaintextModulus(6558547), 4096, 70)},
    {15, BGVParam(PlaintextModulus(207749), 8192, 80)},
    {16, BGVParam(PlaintextModulus(6558547), 8192, 80)},
    {17, BGVParam(PlaintextModulus(207749), 32768, 80)},
    {18, BGVParam(PlaintextModulus(6558547), 32768, 80)},
    {19, BGVParam(PlaintextModulus(207749), 32768, 90)},
    {20, BGVParam(PlaintextModulus(6558547), 32768, 90)},
    {21, BGVParam(PlaintextModulus(207749), 32768, 100)},
    {22, BGVParam(PlaintextModulus(6558547), 32768, 100)},
    {23, BGVParam(PlaintextModulus(207749), 32768, 150)},
    {24, BGVParam(PlaintextModulus(6558547), 32768, 150)},
    {25, BGVParam(PlaintextModulus(207749), 65536, 30)},
    {26, BGVParam(PlaintextModulus(6558547), 65536, 30)},
    {27, BGVParam(PlaintextModulus(207749), 65536, 80)},
    {28, BGVParam(PlaintextModulus(6558547), 65536, 80)},
    {27, BGVParam(PlaintextModulus(207749), 65536, 100)},
    {28, BGVParam(PlaintextModulus(6558547), 65536, 100)},
    {29, BGVParam(PlaintextModulus(6558547), 32, 150)}
};

map<int, CKKSParam> CKKSParam::ParamSets = {

    // CKKSParam(multDepth, scaleFactorBits, n, [securityLevel], [batchSize], [rsTech])
    {1, CKKSParam(1, 10, 8192)},
    {2, CKKSParam(1, 20, 8192)},
    {3, CKKSParam(1, 30, 8192)},
    {4, CKKSParam(1, 40, 8192)},
    {5, CKKSParam(1, 10, 16384)},
    {6, CKKSParam(1, 20, 16384)},
    {7, CKKSParam(1, 30, 16384)},
    {8, CKKSParam(1, 40, 16384)},
    {9, CKKSParam(1, 10, 32768)},
    {10, CKKSParam(1, 20, 32768)},
    {11, CKKSParam(1, 30, 32768)},
    {12, CKKSParam(1, 40, 32768)},
    {13, CKKSParam(1, 10, 65536)},
    {14, CKKSParam(1, 20, 65536)},
    {15, CKKSParam(1, 30, 65536)},
    {16, CKKSParam(1, 40, 65536)},
    {17, CKKSParam(1, 47, 8192)},
    {18, CKKSParam(1, 47, 16384)},
    {19, CKKSParam(1, 47, 32768)},
    {20, CKKSParam(1, 47, 65536)},
    {21, CKKSParam(1, 59, 16384)},
    {22, CKKSParam(1, 59, 32768)},
    {23, CKKSParam(1, 59, 65536)}
};

