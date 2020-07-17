#ifndef PARAMSRUNNER_H
#define PARAMSRUNNER_H

#include <palisade.h>
#include "distancecomputer.h"
#include "vector.h"
#include <cmath>

using namespace std;
using namespace lbcrypto;

/** @brief Represents the main runner of various computations
 * given coordinates and parameter sets (in the form of CryptoContext objects)
 */
template <class Element, typename T>
class ParamsRunner {
    public:
        ParamsRunner() {};
        ~ParamsRunner() {};

        void runDistComp(T x1, T y1, T x2, T y2, CryptoContext<Element> cryptoContext);
        void runMultCheck(T x, CryptoContext<Element> cryptoContext);

    protected:
        virtual Plaintext encodePlaintext(vector<T> coord, CryptoContext<Element> cc, string plaintextName);
        void printParameters(CryptoContext<Element> cryptoContext);
        virtual void printCoordinates(T x, T y, string xName, string yName);
        LPKeyPair<Element> generateKeys(CryptoContext<Element> cryptoContext);
        bool decryptAndCheck(Ciphertext<Element> ct, Plaintext pt, LPPrivateKey<Element> secretKey, CryptoContext<Element> cryptoContext, string plaintextName);
        virtual bool checkDecryption(Plaintext original, Plaintext decrypted);
};

#endif // PARAMSRUNNER_H

template<class Element, typename T>
Plaintext ParamsRunner<Element, T>::encodePlaintext(vector<T> coord, CryptoContext<Element> cc, string plaintextName) {
    vector<int64_t>* typeCastedCoord;
    typeCastedCoord = (vector<int64_t>*) &coord;
    Plaintext plaintext = cc->MakeCoefPackedPlaintext(*typeCastedCoord);
    cout << plaintextName << " Plaintext: " << plaintext << endl;
    return plaintext;
}

template<class Element, typename T>
void ParamsRunner<Element, T>::printParameters(CryptoContext<Element> cryptoContext) {

    // Get parameter set
    int64_t p = cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    int64_t n = cryptoContext->GetCryptoParameters()
                        ->GetElementParams()
                        ->GetCyclotomicOrder() / 2;
    auto q = cryptoContext->GetCryptoParameters()
                        ->GetElementParams()
                        ->GetModulus();

    cout << "p (plaintext modulus) = "
        << p
        << endl;
    cout << "n (dimension) =  "
        << n
        << endl;
    cout << "q (size of field) = "
        << q
        << endl;
    cout << "log2(q) = "
        << log2(q.ConvertToDouble())
        << endl;
}

template <class Element, typename T>
LPKeyPair<Element> ParamsRunner<Element, T>::generateKeys(CryptoContext<Element> cryptoContext) {

    LPKeyPair<Element> keyPair;
    keyPair = cryptoContext->KeyGen();

    if (!keyPair.good()) {
        cout << "Key generation failed!" << endl;
        exit(1);
    }

    return keyPair;
}

template<class Element, typename T>
void ParamsRunner<Element, T>::runDistComp(T x1, T y1, T x2, T y2, CryptoContext<Element> cryptoContext) {

    printParameters(cryptoContext);

    printCoordinates(x1, y1, "x1", "y1");
    printCoordinates(x2, y2, "x2", "y2");

    vector<T> x1Coord{x1};
    vector<T> y1Coord{y1};
    vector<T> x2Coord{x2};
    vector<T> y2Coord{y2};

    // Enable encryption and SHE
    cryptoContext->Enable(ENCRYPTION);
    cryptoContext->Enable(SHE);

    // Encode coordinates into plaintexts
    cout << "Encoding coordinates into plaintexts..." << endl;
    Plaintext x1Plaintext = encodePlaintext(x1Coord, cryptoContext, "x1");
    Plaintext y1Plaintext = encodePlaintext(y1Coord, cryptoContext, "y1");
    Plaintext x2Plaintext = encodePlaintext(x2Coord, cryptoContext, "x2");
    Plaintext y2Plaintext = encodePlaintext(y2Coord, cryptoContext, "y2");

    cout << "Running key generation..." << endl;
    LPKeyPair<Element> keyPair = generateKeys(cryptoContext);

    cout << "Encrypting plaintexts..." << endl;
    LPPublicKey<Element> publicKey = keyPair.publicKey;
    Ciphertext<Element> x1Ciphertext = cryptoContext->Encrypt(publicKey, x1Plaintext);
    Ciphertext<Element> y1Ciphertext = cryptoContext->Encrypt(publicKey, y1Plaintext);
    Ciphertext<Element> x2Ciphertext = cryptoContext->Encrypt(publicKey, x2Plaintext);
    Ciphertext<Element> y2Ciphertext = cryptoContext->Encrypt(publicKey, y2Plaintext);

    cout << "Decrypting ciphertexts..." << endl;
    LPPrivateKey<Element> secretKey = keyPair.secretKey;
    decryptAndCheck(x1Ciphertext, x1Plaintext, secretKey, cryptoContext, "x1");
    decryptAndCheck(y1Ciphertext, y1Plaintext, secretKey, cryptoContext, "y1");
    decryptAndCheck(x2Ciphertext, x2Plaintext, secretKey, cryptoContext, "x2");
    decryptAndCheck(y2Ciphertext, y2Plaintext, secretKey, cryptoContext, "y2");

    DistanceComputer<Element, T> distanceComputer;

    // Compute square of distance
    vector<T> distSq = distanceComputer.computeDistanceSquared(x1, y1, x2, y2);
    Plaintext distSqPlaintext = encodePlaintext(distSq, cryptoContext, "Distance Squared");

    // Homomorphically compute square of distance
    cout << "EvalMultKeyGen(secretKey)..." << endl;
    cryptoContext->EvalMultKeyGen(secretKey);
    Ciphertext<Element> distanceCiphertext = distanceComputer.computeDistanceSquared(x1Ciphertext, y1Ciphertext, x2Ciphertext, y2Ciphertext, cryptoContext, secretKey);
    decryptAndCheck(distanceCiphertext, distSqPlaintext, secretKey, cryptoContext, "Distance Squared");
}

template<class Element, typename T>
void ParamsRunner<Element, T>::runMultCheck(T seed, CryptoContext<Element> cryptoContext) {

    printParameters(cryptoContext);

    cout << "x = " << seed << endl;
    vector<T> x{seed};

    // Enable encryption and SHE
    cryptoContext->Enable(ENCRYPTION);
    cryptoContext->Enable(SHE);

    // Encode x into plaintext
    cout << "Encoding x into plaintext..." << endl;
    Plaintext xPlaintext = encodePlaintext(x, cryptoContext, "x");

    cout << "Running key generation..." << endl;
    LPKeyPair<Element> keyPair = generateKeys(cryptoContext);

    cout << "Encrypting plaintext..." << endl;
    LPPublicKey<Element> publicKey = keyPair.publicKey;
    Ciphertext<Element> xCiphertext = cryptoContext->Encrypt(publicKey, xPlaintext);

    cout << "Decrypting ciphertext..." << endl;
    LPPrivateKey<Element> secretKey = keyPair.secretKey;
    decryptAndCheck(xCiphertext, xPlaintext, secretKey, cryptoContext, "x");

    Ciphertext<Element> resultCiphertext = xCiphertext;
    vector<T> actualResult = x;
    int counter = 0;

    cryptoContext->EvalMultKeyGen(secretKey);

    bool correct = true;
    while (correct) {
        resultCiphertext = cryptoContext->EvalMult(resultCiphertext, xCiphertext);
        actualResult = actualResult * x;
        Plaintext actualResultPlaintext = encodePlaintext(actualResult, cryptoContext, "Actual Result");
        correct = decryptAndCheck(resultCiphertext, actualResultPlaintext, secretKey, cryptoContext, "Result");
        counter = counter + 1;
    }

    cout << "CORRECT FOR " << counter << " MULTIPLICATION(S)" << endl;
}

template<class Element, typename T>
void ParamsRunner<Element, T>::printCoordinates(T x, T y, string xName, string yName) {
    cout << "(" << xName << ", " << yName << ") coordinates are: ";
    cout << "(" << x << ", " << y << ")" << endl;
}

template<class Element, typename T>
bool ParamsRunner<Element, T>::checkDecryption(Plaintext original, Plaintext decrypted) {
    if (*original != *decrypted) {
        cout << "Failed" << endl;
        return false;
    } else {
        cout << "Successful" << endl;
        return true;
    }
}

template<class Element, typename T>
bool ParamsRunner<Element, T>::decryptAndCheck(Ciphertext<Element> ct, Plaintext pt, LPPrivateKey<Element> sk, CryptoContext<Element> cc, string plaintextName) {

    Plaintext decrypt;
    cc->Decrypt(sk, ct, &decrypt);
    decrypt->SetLength(pt->GetLength());

    cout << "Decrypted " << plaintextName << ": " << decrypt << endl;

    return checkDecryption(pt, decrypt);
}

template<class Element>
class CKKSParamsRunner: public ParamsRunner<Element, complex<double>> {

    virtual Plaintext encodePlaintext(vector<complex<double>> coord, CryptoContext<Element> cc, string plaintextName) {
        Plaintext plaintext;
        plaintext = cc->MakeCKKSPackedPlaintext(coord);
        cout << plaintextName << " Plaintext: " << plaintext << endl;
        return plaintext;
    }

    virtual void printCoordinates(complex<double> x, complex<double> y, string xName, string yName) {
        cout << "(" << xName << ", " << yName << ") coordinates are: ";
        printf("(%f + %fi, ", real(x), imag(x));
        printf("%f + %fi) \n", real(y), imag(y));
    }

    virtual bool checkDecryption(Plaintext original, Plaintext decrypted) {
        cout << "Please check correctness manually for CKKS" << endl;
        return false;
    }

};

