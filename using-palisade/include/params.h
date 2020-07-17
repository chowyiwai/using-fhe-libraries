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

//// Represents parameters for BGVrns scheme
class BGVrnsParam: Param<DCRTPoly> {

    public:
        static map<int, BGVrnsParam> ParamSets;

        BGVrnsParam(PlaintextModulus p,  int64_t n, double sigma, SecurityLevel securityLevel, int multDepth)
            : p(p), n(n), sigma(sigma), securityLevel(securityLevel), multDepth(multDepth) {}

        CryptoContext<DCRTPoly> generateCryptoContext() const {
            CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(multDepth, p, securityLevel, sigma, maxDepth, mode, ksTech, n);
            return cc;
        }

    private:
        PlaintextModulus p; // plaintext modulus
        int64_t n; // dimension
        double sigma;
        SecurityLevel securityLevel;
        int multDepth;
        int maxDepth = 1; // maximum depth before relinearisation
        MODE mode = RLWE;
        KeySwitchTechnique ksTech = BV;

};

//// Represents parameters for BGV scheme
class BGVParam: Param<Poly> {

    public:
        static map<int, BGVParam> ParamSets;

        BGVParam(PlaintextModulus p, int64_t m, int64_t numOfBits, int numOfTowers, int64_t relinWindow, float stdDev)
            : p(p), m(m), numOfBits(numOfBits), numOfTowers(numOfTowers), relinWindow(relinWindow), stdDev(stdDev) {}

        // overloaded constructor
        BGVParam(PlaintextModulus p, int64_t m, int64_t relinWindow, float stdDev, BigInteger q)
            : p(p), m(m), relinWindow(relinWindow), stdDev(stdDev), q(q) {
                qSpecified = true;
        }

        CryptoContext<Poly> generateCryptoContext() const {
            auto params = generateParams();
            CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(params, p, relinWindow, stdDev, mode);
            return cc;
        }

    private:
        PlaintextModulus p; // plaintext modulus
        int64_t m; // order; n = m / 2;
        int64_t numOfBits;
        int numOfTowers;
        int64_t relinWindow;
        float stdDev;
        BigInteger q; // ciphertext modulus
        bool qSpecified = false; // represents whether a value for q was passed in
        MODE mode = RLWE;

        shared_ptr<ILParams> generateParams() const {
            if (qSpecified) {
                return make_shared<ILParams>(m, q);
            }

            return ElemParamFactory::GenElemParams<ILParams>(m, numOfBits, numOfTowers);
        }
};

//// Represents parameters for CKKS scheme
class CKKSParam: Param<DCRTPoly> {

    public:
        static map<int, CKKSParam> ParamSets;

        CKKSParam(int64_t m, int64_t numPrimes, int64_t scaleExp, int64_t relinWindow, int64_t batchSize)
            : m(m), numPrimes(numPrimes), scaleExp(scaleExp), relinWindow(relinWindow), batchSize(batchSize) {}

        // overloaded constructor
        CKKSParam(int64_t multDepth, int64_t scaleFactorBits, int64_t batchSize, SecurityLevel securityLevel, int64_t n)
            : multDepth(multDepth), scaleExp(scaleFactorBits), batchSize(batchSize), securityLevel(securityLevel), n(n) {
                securityLevelSpecified = true;
        }

        CryptoContext<DCRTPoly> generateCryptoContext() const {
            if (securityLevelSpecified) {
                return CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(multDepth, scaleExp, batchSize, securityLevel, n, rsTech);
            }

            return GenCryptoContextCKKS<DCRTPoly>(m, numPrimes, scaleExp, relinWindow, batchSize, mode, ksTech, rsTech);
        }

    private:
        int64_t m; // cyclOrder
        int64_t numPrimes; // number of primes that make up the ciphertext modulus and equal to multiplicative depth + 1
        int64_t scaleExp; // equal to `dcrtbits` (the number of bits of the ciphertext modulus) and equal to the plaintext modulus
        int64_t relinWindow;
        int64_t batchSize;
        MODE mode = RLWE;
        KeySwitchTechnique ksTech = BV;
        RescalingTechnique rsTech = APPROXRESCALE;

        int64_t multDepth;
        SecurityLevel securityLevel;
        bool securityLevelSpecified = false;
        int64_t n; // dimension; if specified as 0, the library will choose it based on the security level

};

