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
class BgvRnsParam: Param<DCRTPoly> {

    public:
        static map<int, BgvRnsParam> ParamSets;

        BgvRnsParam(PlaintextModulus p,  usint n, double sigma, SecurityLevel securityLevel, int multDepth)
            : p(p), n(n), sigma(sigma), securityLevel(securityLevel), multDepth(multDepth) {}

        CryptoContext<DCRTPoly> generateCryptoContext() const {
            CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(multDepth, p, securityLevel, sigma, maxDepth, mode, ksTech, n);
            return cc;
        }

    private:
        PlaintextModulus p; // plaintext modulus
        usint n; // dimension
        double sigma;
        SecurityLevel securityLevel;
        int multDepth;
        int maxDepth = 1; // maximum depth before relinearisation
        MODE mode = RLWE;
        KeySwitchTechnique ksTech = BV;

};

class BgvParam: Param<Poly> {

    public:
        static map<int, BgvParam> ParamSets;

        BgvParam(PlaintextModulus p, uint64_t m, uint64_t numOfBits, int numOfTowers, usint relinWindow, float stdDev)
            : p(p), m(m), numOfBits(numOfBits), numOfTowers(numOfTowers), relinWindow(relinWindow), stdDev(stdDev) {}

        // overloaded constructor
        BgvParam(PlaintextModulus p, uint64_t m, usint relinWindow, float stdDev, BigInteger q)
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
        uint64_t m; // order; n = m / 2;
        uint64_t numOfBits;
        int numOfTowers;
        usint relinWindow;
        float stdDev;
        BigInteger q; // ciphertext modulus
        bool qSpecified = false; // represents whether a value for q was passed in
        MODE mode = RLWE;

        shared_ptr<ILParams> generateParams() const {
            if (qSpecified) {
                return make_shared<ILParams>(m, q);
            } else {
                return ElemParamFactory::GenElemParams<ILParams>(m, numOfBits, numOfTowers);
            }
        }
};
