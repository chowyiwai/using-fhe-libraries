#ifndef DISTANCECOMPUTER_H
#define DISTANCECOMPUTER_H

#include <vector>
#include <palisade.h>

using namespace std;
using namespace lbcrypto;
using std::vector;

/** @brief Represents a distance computer that
 * supports both homomorphic and non-homomorphic computations
 */
template <class Element, typename T>
class DistanceComputer {

    public:
        DistanceComputer() {};
        virtual ~DistanceComputer() {};

        vector<T> computeDistanceSquared(T x1, T y1, T x2, T y2) {
            cout << "Evaluating square of distance between (" << x1 << ", " << y1
                << ") and (" << x2 << ", " << y1 << ")" <<  endl;
            T xDiff = abs(x1 - x2);
            T yDiff = abs(y1 - y2);
            T xDiffSquared = pow(xDiff, 2);
            T yDiffSquared = pow(yDiff, 2);
            T distanceSquared = xDiffSquared + yDiffSquared;
            cout << "Square of distance = " << distanceSquared << endl;
            vector<T> distanceSquaredVector{distanceSquared};
            return distanceSquaredVector;
        }

        virtual Ciphertext<Element> computeDistanceSquared(Ciphertext<Element> x1, Ciphertext<Element> y1,
                                                           Ciphertext<Element> x2, Ciphertext<Element> y2,
                                                           CryptoContext<Element> cc, LPPrivateKey<Element> secretKey,
                                                           bool supportsComposedMult);

    private:
        // To check intermediate computation steps
        Plaintext decrypt(Ciphertext<Element> ciphertext, CryptoContext<Element> cryptoContext, LPPrivateKey<Element> secretKey);
};

#endif // DISTANCECOMPUTER_H

template <class Element, typename T>
Ciphertext<Element> DistanceComputer<Element, T>::computeDistanceSquared(Ciphertext<Element> x1, Ciphertext<Element> y1,
                                                                         Ciphertext<Element> x2, Ciphertext<Element> y2,
                                                                         CryptoContext<Element> cc, LPPrivateKey<Element> secretKey,
                                                                         bool supportsComposedMult) {
    cout << "Homomorphically evaluating square of distance..." << endl;

    cout << "Computing xDiff..." << endl;
    auto xDiff = cc->EvalSub(x1, x2);

    Plaintext xDiffDecrypt = decrypt(xDiff, cc, secretKey);
    cout << "Decrypted " << "xDiff: " << xDiffDecrypt << endl;

    cout << "Computing yDiff..." << endl;
    auto yDiff = cc->EvalSub(y1, y2);

    Plaintext yDiffDecrypt = decrypt(yDiff, cc, secretKey);
    cout << "Decrypted " << "yDiff: " << yDiffDecrypt << endl;

    Ciphertext<Element> xDiffSq;
    Ciphertext<Element> yDiffSq;
    if (supportsComposedMult) {
        cout << "Computing xDiffSq..." << endl;
        xDiffSq = cc->ComposedEvalMult(xDiff, xDiff);
        cout << "Computing yDiffSq..." << endl;
        yDiffSq = cc->ComposedEvalMult(yDiff, yDiff);
    } else {
        cout << "Computing xDiffSq..." << endl;
        xDiffSq = cc->EvalMult(xDiff, xDiff);
        cout << "Computing yDiffSq..." << endl;
        yDiffSq = cc->EvalMult(yDiff, yDiff);
    }

    Plaintext xDiffSqDecrypt = decrypt(xDiffSq, cc, secretKey);
    cout << "Decrypted " << "xDiffSq: " << xDiffSqDecrypt << endl;

    Plaintext yDiffSqDecrypt = decrypt(yDiffSq, cc, secretKey);
    cout << "Decrypted " << "yDiffSq: " << yDiffSqDecrypt << endl;

    cout << "Computing total sum..." << endl;
    auto sum = cc->EvalAdd(xDiffSq, yDiffSq);
    return sum;
}

template <class Element, typename T>
Plaintext DistanceComputer<Element, T>::decrypt(Ciphertext<Element> ciphertext, CryptoContext<Element> cc, LPPrivateKey<Element> secretKey) {
    Plaintext decrypted;
    cc->Decrypt(secretKey, ciphertext, &decrypted);
    decrypted->SetLength(1);
    return decrypted;
}


