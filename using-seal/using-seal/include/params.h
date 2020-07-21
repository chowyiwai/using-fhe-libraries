#ifndef PARAMS_H
#define PARAMS_H

#include <seal/seal.h>

using namespace std;
using namespace seal;

class Param {

public:
    Param() {};
    ~Param() {};
    shared_ptr<SEALContext> generateContext();

};

#endif // PARAMS_H

class CKKSParam: public Param {

public:
    static map<int, CKKSParam> ParamSets;

    CKKSParam(size_t poly_modulus_degree, vector<int> coeff_modulus_size_chain, double scale = 0)
        : poly_modulus_degree(poly_modulus_degree), coeff_modulus_size_chain(coeff_modulus_size_chain), scale(scale) {}

    shared_ptr<SEALContext> generateContext() {
        EncryptionParameters parms(scheme_type::CKKS);

        auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, coeff_modulus_size_chain);

        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(coeff_modulus);

        auto context = SEALContext::Create(parms);

        return context;
    }

    double getScale() {
        return scale;
    }

private:
    size_t poly_modulus_degree; // order
    vector<int> coeff_modulus_size_chain; // chain of integers representing the sizes of prime numbers, whose products give the ciphertext modulus
    double scale;
};
