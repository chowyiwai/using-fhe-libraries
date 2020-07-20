// using-seal.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <seal/seal.h>
#include <examples.h>

using namespace std;
using namespace seal;

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


    EncryptionParameters parms(scheme_type::CKKS);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    double scale = pow(2.0, 40);

    auto context = SEALContext::Create(parms);

    print_parameters(context);

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    vector<double> x1Coord = { stadiumXCoordDouble };
    vector<double> y1Coord = { stadiumYCoordDouble };
    vector<double> x2Coord = { dsoXCoordDouble };
    vector<double> y2Coord = { dsoYCoordDouble };

    Plaintext x1Plaintext;
    Plaintext y1Plaintext;
    Plaintext x2Plaintext;
    Plaintext y2Plaintext;

    encoder.encode(x1Coord, scale, x1Plaintext);
    encoder.encode(y1Coord, scale, y1Plaintext);
    encoder.encode(x2Coord, scale, x2Plaintext);
    encoder.encode(y2Coord, scale, y2Plaintext);

    Ciphertext x1Ciphertext;
    Ciphertext y1Ciphertext;
    Ciphertext x2Ciphertext;
    Ciphertext y2Ciphertext;

    encryptor.encrypt(x1Plaintext, x1Ciphertext);
    encryptor.encrypt(y1Plaintext, y1Ciphertext);
    encryptor.encrypt(x2Plaintext, x2Ciphertext);
    encryptor.encrypt(y2Plaintext, y2Ciphertext);

    Ciphertext xDiff;
    evaluator.sub(x1Ciphertext, x2Ciphertext, xDiff);

    Plaintext xDiffPlaintext;
    decryptor.decrypt(xDiff, xDiffPlaintext);

    vector<double> xDiffVector;
    encoder.decode(xDiffPlaintext, xDiffVector);

    cout << "xDiff: ";
    print_vector(xDiffVector, 1, 9);

    //cout << "Noise budget in xDiff: " << decryptor.invariant_noise_budget(xDiff) << endl;

    Ciphertext yDiff;
    evaluator.sub(y1Ciphertext, y2Ciphertext, yDiff);

    Plaintext yDiffPlaintext;
    decryptor.decrypt(yDiff, yDiffPlaintext);

    vector<double> yDiffVector;
    encoder.decode(yDiffPlaintext, yDiffVector);

    cout << "yDiff: ";
    print_vector(yDiffVector, 1, 9);

    //cout << "Noise budget in yDiff: " << decryptor.invariant_noise_budget(yDiff) << endl;

    Ciphertext xDiffSq;
    evaluator.square(xDiff, xDiffSq);

    Plaintext xDiffSqPlaintext;
    decryptor.decrypt(xDiffSq, xDiffSqPlaintext);

    vector<double> xDiffSqVector;
    encoder.decode(xDiffSqPlaintext, xDiffSqVector);

    cout << "xDiffSq: ";
    print_vector(xDiffSqVector, 1, 9);
    
    //cout << "Noise budget in xDiffSq: " << decryptor.invariant_noise_budget(xDiffSq) << endl;

    Ciphertext yDiffSq;
    evaluator.square(yDiff, yDiffSq);

    Plaintext yDiffSqPlaintext;
    decryptor.decrypt(yDiffSq, yDiffSqPlaintext);

    vector<double> yDiffSqVector;
    encoder.decode(yDiffSqPlaintext, yDiffSqVector);

    cout << "yDiffSq: ";
    print_vector(yDiffSqVector, 1, 9);

    //cout << "Noise budget in yDiffSq: " << decryptor.invariant_noise_budget(yDiffSq) << endl;

    Ciphertext distSq;
    evaluator.add(xDiffSq, yDiffSq, distSq);

    //cout << "Noise budget in distSq: " << decryptor.invariant_noise_budget(distSq) << endl;

    Plaintext distSqPlaintext;
    decryptor.decrypt(distSq, distSqPlaintext);

    vector<double> distSqVector;
    encoder.decode(distSqPlaintext, distSqVector);

    print_vector(distSqVector, 1, 9);

}