#include "../include/params.h"

using namespace std;

map<int, CKKSParam> CKKSParam::ParamSets = {

    // CKKSParam(poly_modulus_degree, coeff_modulus_size_chain)
    {1, CKKSParam(8192, { 60, 40, 40, 60 }, pow(2.0, 40))} // taken from SEAL's `../examples/4_ckks_basics.cpp`

};