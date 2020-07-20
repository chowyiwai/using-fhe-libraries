#ifndef PARAMSRUNNER_H
#define PARAMSRUNNER_H

#include "distancecomputer.h"
#include <cmath>

using namespace std;
using namespace seal;

/** @brief Represents the main runner of various computations
 * given coordinates and parameters (in the form of SEALContext)
 */
template <typename T, class EncoderType>
class ParamsRunner {
public:
    ParamsRunner() {};
    ~ParamsRunner() {};

    void runDistComp(T x1, T y1, T x2, T y2, shared_ptr<SEALContext> context, T scale = 0);

protected:
    void print_all_parameters(shared_ptr<SEALContext> context);
    Plaintext encodePlaintext(vector<T> data, T scale, EncoderType* encoder);
    Ciphertext encryptPlaintext(Plaintext plaintext, Encryptor* encryptor);
    vector<T> decrypt(Ciphertext ciphertext, Decryptor* decryptor, EncoderType* encoder, string varName);
    bool checkDecryption(vector<T> original, vector<T> decrypted, T epsilon = 0);
};

#endif // PARAMSRUNNER_H

template <typename T, class EncoderType>
void ParamsRunner<T, EncoderType>::print_all_parameters(shared_ptr<SEALContext> context) {
    print_parameters(context); // Method by SEAL that prints ...

    auto& context_data = *context->key_context_data();

    // Print modulus chain while calculating value of q, then print q
    BigUInt q(context_data.total_coeff_modulus_bit_count(), "1"); // initialise q with the size of the coeff_modulus and a value of 1

    auto coeff_modulus = context_data.parms().coeff_modulus();

    cout << "Modulus Chain: (";
    for (int i = 0; i < coeff_modulus.size(); i++) {
        auto value = coeff_modulus[i].value();
        q *= value;
        cout << value;
        if (i == coeff_modulus.size() - 1) {
            cout << ")" << endl;
        }
        else {
            cout << ", ";
        }
    }

    cout << "q = " << q.to_dec_string() << endl;
}

template <typename T, class EncoderType>
Plaintext ParamsRunner<T, EncoderType>::encodePlaintext(vector<T> data, T scale, EncoderType* encoder) {
    Plaintext plaintext;
    encoder->encode(data, scale, plaintext);
    return plaintext;
}

template <typename T, class EncoderType>
Ciphertext ParamsRunner<T, EncoderType>::encryptPlaintext(Plaintext plaintext, Encryptor* encryptor) {
    Ciphertext ciphertext;
    encryptor->encrypt(plaintext, ciphertext);
    return ciphertext;
}

template <typename T, class EncoderType> 
vector<T> ParamsRunner<T, EncoderType>::decrypt(Ciphertext ciphertext, Decryptor* decryptor, EncoderType* encoder, string varName) {
    Plaintext decrypted;
    decryptor->decrypt(ciphertext, decrypted);

    vector<T> decryptedVector;
    encoder->decode(decrypted, decryptedVector);

    cout << "Decrypted " << varName << ": ";
    print_vector(decryptedVector, 1, 9);

    return decryptedVector;
}

template <typename T, class EncoderType>
bool ParamsRunner<T, EncoderType>::checkDecryption(vector<T> original, vector<T> decrypted, T epsilon) {
    // Compare only the first element
    bool isEqual = abs(original[0] - decrypted[0]) < epsilon;
    if (isEqual) {
        cout << "original[0] = " << original[0] << endl;
        cout << "decrypted[0] = " << decrypted[0] << endl;
        bool same = original[0] == decrypted[0];
        cout << "same: " << same << endl;
        cout << "Failed" << endl;
        return false;
    }
    else {
        cout << "Successful" << endl;
        return true;
    }
}


template <typename T, class EncoderType>
void ParamsRunner<T, EncoderType>::runDistComp(T x1, T y1, T x2, T y2, shared_ptr<SEALContext> context, T scale) {
    print_all_parameters(context);
    
    vector<T> x1Coord = { x1 };
    vector<T> y1Coord = { y1 };
    vector<T> x2Coord = { x2 };
    vector<T> y2Coord = { y2 };
    
    // Encode coordinates into plaintexts
    cout << "Encoding coordinates into plaintexts..." << endl;
    EncoderType encoder(context);
    Plaintext x1Plaintext = encodePlaintext(x1Coord, scale, &encoder);
    Plaintext y1Plaintext = encodePlaintext(y1Coord, scale, &encoder);
    Plaintext x2Plaintext = encodePlaintext(x2Coord, scale, &encoder);
    Plaintext y2Plaintext = encodePlaintext(y2Coord, scale, &encoder);

    cout << "Running key generation..." << endl;
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();

    cout << "Encrypting plaintexts..." << endl;
    Encryptor encryptor(context, public_key);
    Ciphertext x1Ciphertext = encryptPlaintext(x1Plaintext, &encryptor);
    Ciphertext y1Ciphertext = encryptPlaintext(y1Plaintext, &encryptor);
    Ciphertext x2Ciphertext = encryptPlaintext(x2Plaintext, &encryptor);
    Ciphertext y2Ciphertext = encryptPlaintext(y2Plaintext, &encryptor);

    cout << "Decrypting ciphertexts..." << endl;
    Decryptor decryptor(context, secret_key);
    decrypt(x1Ciphertext, &decryptor, &encoder, "x1");
    decrypt(y1Ciphertext, &decryptor, &encoder, "y1");
    decrypt(x2Ciphertext, &decryptor, &encoder, "x2");
    decrypt(y2Ciphertext, &decryptor, &encoder, "y2");

    Evaluator evaluator(context);
    DistanceComputer<T, EncoderType> distanceComputer(&evaluator, &decryptor, &encoder);

    // Compute square of distance
    vector<T> distSq = distanceComputer.computeDistanceSquared(x1, y1, x2, y2);
    print_vector(distSq, 1, 9);

    // Homomorphically compute square of distance
    Ciphertext distSqCiphertext = distanceComputer.computeDistanceSquared(x1Ciphertext, y1Ciphertext, x2Ciphertext, y2Ciphertext);
    vector<T> decrypted = decrypt(distSqCiphertext, &decryptor, &encoder, "Distance Squared");
    checkDecryption(distSq, decrypted);
 }