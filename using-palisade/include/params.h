#ifndef PARAMS_H
#define PARAMS_H
#include <palisade.h>
#include <cryptocontextgen.h>

using namespace lbcrypto;
using namespace std;

template <class Element>
class Param {

    public:
        Param() {};
        ~Param() {};
        CryptoContext<Element> generateCryptoContext() const;

};

#endif // PARAMS_H

/** Represents parameters for BGVrns scheme */
class BGVrnsParam: Param<DCRTPoly> {

    public:
        static map<int, BGVrnsParam> ParamSets;

        BGVrnsParam(PlaintextModulus p,  int64_t n, int multDepth, SecurityLevel securityLevel = HEStd_128_classic,
                    double sigma = 3.19, int maxDepth = 1, MODE mode = OPTIMIZED, KeySwitchTechnique ksTech = HYBRID)
            : p(p), n(n), multDepth(multDepth), securityLevel(securityLevel), sigma(sigma), maxDepth(maxDepth), mode(mode), ksTech(ksTech) {}

        CryptoContext<DCRTPoly> generateCryptoContext() const {
            CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(multDepth, p, securityLevel,
                                                                                                sigma, maxDepth, mode,
                                                                                                ksTech, n);
            return cc;
        }

    private:
        PlaintextModulus p; // plaintext modulus
        int64_t n; // dimension
        int multDepth;

        SecurityLevel securityLevel;
        double sigma;
        int maxDepth; // maximum depth before relinearisation
        MODE mode;
        KeySwitchTechnique ksTech;
};

/** Represents parameters for BGV scheme */
class BGVParam: Param<Poly> {

    public:
        static map<int, BGVParam> ParamSets;

        BGVParam(PlaintextModulus p, int64_t m, int64_t numOfBits, int64_t relinWindow = 1, float stdDev = 4, MODE mode = RLWE)
            : p(p), m(m), numOfBits(numOfBits), relinWindow(relinWindow), stdDev(stdDev), mode(mode) {}

        CryptoContext<Poly> generateCryptoContext() const {
            auto params = generateParams();
            CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(params, p, relinWindow, stdDev, mode);
            return cc;
        }

    private:
        PlaintextModulus p; // plaintext modulus
        int64_t m; // order; n = m / 2;
        int64_t numOfBits;

        int64_t relinWindow;
        float stdDev;
        MODE mode;

        shared_ptr<ILParams> generateParams() const {
            return ElemParamFactory::GenElemParams<ILParams>(m, numOfBits);
        }
};

/** Represents parameters for CKKS scheme */
class CKKSParam: Param<DCRTPoly> {

    public:
        static map<int, CKKSParam> ParamSets;

        CKKSParam(int64_t multDepth, int64_t scaleFactorBits, int64_t n, SecurityLevel securityLevel = HEStd_128_classic, int batchSize = 8,
                  RescalingTechnique rsTech = EXACTRESCALE)
            :  multDepth(multDepth), scaleFactorBits(scaleFactorBits), n(n), securityLevel(securityLevel), batchSize(batchSize), rsTech(rsTech) {}

        CryptoContext<DCRTPoly> generateCryptoContext() const {
            return CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(multDepth, scaleFactorBits, batchSize, securityLevel, n, rsTech);
        }

    private:
        int64_t multDepth;
        int64_t scaleFactorBits; // equal to `dcrtbits` (the number of bits of the ciphertext modulus) and equal to the plaintext modulus
        int64_t n; // dimension; if specified as 0, the library will choose it based on the security level

        SecurityLevel securityLevel;
        int64_t batchSize;
        RescalingTechnique rsTech;

};

