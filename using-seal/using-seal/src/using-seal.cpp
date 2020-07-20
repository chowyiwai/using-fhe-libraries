// using-seal.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "include/paramsrunner.h"

using namespace std;
using namespace seal;

void runCKKS(double x1, double y1, double x2, double y2) {
    EncryptionParameters parms(scheme_type::CKKS);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    double scale = pow(2.0, 40);

    auto context = SEALContext::Create(parms);

    ParamsRunner<double, CKKSEncoder> paramsRunner;
    paramsRunner.runDistComp(x1, y1, x2, y2, context, scale);
}

int main()
{
    
    // The coordinates of the national stadium are
    // Latitude: 1.3044172525405884 or 1304.4172525405884 x 10^{-3}
    // Longitude: 103.87432861328125 or 103874.32861328125 x 10^{-3}
    // The coordinates of DSO are
    // Latitude: 1.290164 or 1290.164 x 10^{-3}
    // Longitude: 103.789106 or 103789.106 x 10^{-3}
    double stadiumXCoordDouble = 1.304;
    double stadiumYCoordDouble = 103.874;
    double dsoXCoordDouble = 1.290;
    double dsoYCoordDouble = 103.789;

    runCKKS(stadiumXCoordDouble, stadiumYCoordDouble, dsoXCoordDouble, dsoYCoordDouble);

}