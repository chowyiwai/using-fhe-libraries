#ifndef DISTANCECOMPUTER_H
#define DISTANCECOMPUTER_H

#include <vector>
#include <seal/seal.h>
#include <examples.h>

using namespace std;
using namespace seal;

/** @brief Represents a distance computer that
 * supports both homomorphic and non-homomorphic computations
 */
template <typename T, class EncoderType>
class DistanceComputer {

public:
    DistanceComputer(Evaluator* evaluator, Decryptor* decryptor, EncoderType* encoder) 
        : evaluator(evaluator), decryptor(decryptor), encoder(encoder) {};
    virtual ~DistanceComputer() {};

    vector<T> computeDistanceSquared(T x1, T y1, T x2, T y2) {
        cout << "Evaluating square of distance between (" << x1 << ", " << y1
            << ") and (" << x2 << ", " << y1 << ")" << endl;
        T xDiff = abs(x1 - x2);
        T yDiff = abs(y1 - y2);
        T xDiffSquared = pow(xDiff, 2);
        T yDiffSquared = pow(yDiff, 2);
        T distanceSquared = xDiffSquared + yDiffSquared;
        cout << "Square of distance = " << distanceSquared << endl;
        vector<T> distanceSquaredVector = { distanceSquared };
        return distanceSquaredVector;
    }

    virtual Ciphertext computeDistanceSquared(Ciphertext x1, Ciphertext y1,
        Ciphertext x2, Ciphertext y2);

private:
    Evaluator* evaluator;
    Decryptor* decryptor;
    EncoderType* encoder;

    // To check intermediate computation steps
    vector<T> decrypt(Ciphertext ciphertext);
};

#endif // DISTANCECOMPUTER_H

template <typename T, class EncoderType>
Ciphertext DistanceComputer<T, EncoderType>::computeDistanceSquared(Ciphertext x1, Ciphertext y1, Ciphertext x2,
    Ciphertext y2) {

    cout << "Homomorphically evaluating square of distance..." << endl;

    cout << "Computing xDiff..." << endl;
    Ciphertext xDiff;
    evaluator->sub(x1, x2, xDiff);

    vector<double> xDiffVector = decrypt(xDiff);
    cout << "Decrypted xDiff:";
    print_vector(xDiffVector, 1, 9);

    cout << "Computing yDiff..." << endl;
    Ciphertext yDiff;
    evaluator->sub(y1, y2, yDiff);

    vector<double> yDiffVector = decrypt(yDiff);
    cout << "Decrypted yDiff: ";
    print_vector(yDiffVector, 1, 9);

    cout << "Computing xDiffSq..." << endl;
    Ciphertext xDiffSq;
    evaluator->square(xDiff, xDiffSq);

    vector<double> xDiffSqVector = decrypt(xDiffSq);
    cout << "xDiffSq: ";
    print_vector(xDiffSqVector, 1, 9);

    cout << "Computing yDiffSq..." << endl;
    Ciphertext yDiffSq;
    evaluator->square(yDiff, yDiffSq);

    vector<double> yDiffSqVector = decrypt(yDiffSq);
    cout << "yDiffSq: ";
    print_vector(yDiffSqVector, 1, 9);

    Ciphertext distSq;
    evaluator->add(xDiffSq, yDiffSq, distSq);

    return distSq;
}

template <typename T, class EncoderType>
vector<T> DistanceComputer<T, EncoderType>::decrypt(Ciphertext ciphertext) {
    Plaintext decrypted;
    decryptor->decrypt(ciphertext, decrypted);

    vector<T> decryptedVector;
    encoder->decode(decrypted, decryptedVector);

    return decryptedVector;
}


