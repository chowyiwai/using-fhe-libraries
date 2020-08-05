#include "../include/params.h"

using namespace std;

map<int, CKKSParam> CKKSParam::ParamSets = {

    // CKKSParam(poly_modulus_degree, coeff_modulus_size_chain, scale)
    {1, CKKSParam(8192, { 60, 40, 40, 60 }, pow(2.0, 40))}, // taken from SEAL's `../examples/4_ckks_basics.cpp` // max bit count = 218
    {2, CKKSParam(16384, { 60, 40, 40, 40, 60 }, pow(2.0, 40))}, // max bit count = 438
    {3, CKKSParam(32768, { 60, 40, 40, 40, 40, 60 }, pow(2.0, 40))}, // max bit count = 881
    {4, CKKSParam(4096, { 35, 30, 35 }, pow(2.0, 30))}, // max bit count = 109
    {5, CKKSParam(2048, { 18, 18, 18 }, pow(2.0, 16))}, // max bit count = 54
    {6, CKKSParam(1024, { 20 }, pow(2.0, 5))}, // max bit count = 27
    {7, CKKSParam(8192, { 40, 40, 40, 60 }, pow(2.0, 40))},
    {8, CKKSParam(16384, { 40, 40, 40, 60 }, pow(2.0, 40))},
    {9, CKKSParam(32768, { 40, 40, 40, 60 }, pow(2.0, 40))},
    {12, CKKSParam(4096, { 54, 55 }, pow(2.0, 22))},
    {13, CKKSParam(4096, { 53, 56 }, pow(2.0, 22))},
    {14, CKKSParam(4096, { 52, 57 }, pow(2.0, 22))},
    {15, CKKSParam(4096, { 51, 58 }, pow(2.0, 22))},
    {16, CKKSParam(4096, { 50, 59 }, pow(2.0, 22))},
    {17, CKKSParam(8192, { 40, 60 }, pow(2.0, 18))},
    {18, CKKSParam(4096, { 24, 25, 60 }, pow(2.0, 22))},
    {19, CKKSParam(4096, { 9, 40, 60 }, pow(2.0, 9))}
};