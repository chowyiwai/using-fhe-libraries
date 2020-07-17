#ifndef PARAMSRUNNER_H
#define PARAMSRUNNER_H

#include <palisade.h>
#include "distancecomputer.h"

using namespace std;
using namespace lbcrypto;

template <class Element, typename T>
class ParamsRunner {
    public:
        ParamsRunner() {};
        ~ParamsRunner() {};

        void run(T x1, T y1, T x2, T y2, CryptoContext<Element> cryptoContext);

    protected:
        virtual Plaintext encodePlaintext(vector<T> coord, CryptoContext<Element> cc, string plaintextName);
        void printParameters(CryptoContext<Element> cryptoContext);
        virtual void printCoordinates(T x, T y, string xName, string yName);
        LPKeyPair<Element> generateKeys(CryptoContext<Element> cryptoContext);
        void decryptAndCheck(Ciphertext<Element> ct, Plaintext pt, LPPrivateKey<Element> secretKey, CryptoContext<Element> cryptoContext, string plaintextName);
        virtual void checkDecryption(Plaintext original, Plaintext decrypted);
};
#endif // PARAMSRUNNER_H

template<class Element, typename T>
Plaintext ParamsRunner<Element, T>::encodePlaintext(vector<T> coord, CryptoContext<Element> cc, string plaintextName) {
    cout << "in normal one" << endl;
    vector<int64_t>* typeCastedCoord;
    typeCastedCoord = (vector<int64_t>*) &coord;
    Plaintext plaintext = cc->MakeCoefPackedPlaintext(*typeCastedCoord);
    cout << plaintextName << " Plaintext: " << plaintext << endl;
    return plaintext;
}

template<class Element, typename T>
void ParamsRunner<Element, T>::printParameters(CryptoContext<Element> cryptoContext) {

    // GET PARAMETER SET
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
void ParamsRunner<Element, T>::run(T x1, T y1, T x2, T y2, CryptoContext<Element> cryptoContext) {

    // PRINT PARAMETER SET
    printParameters(cryptoContext);

    // PRINT ORIGINAL COORDINATES
    printCoordinates(x1, y1, "x1", "y1");
    printCoordinates(x2, y2, "x2", "y2");

    vector<T> x1Coord{x1};
    vector<T> y1Coord{y1};
    vector<T> x2Coord{x2};
    vector<T> y2Coord{y2};

    // ENABLE ENCRYPTION AND SHE
    cryptoContext->Enable(ENCRYPTION);
    cryptoContext->Enable(SHE);

    // ENCODE COORDINATES INTO PLAINTEXTS
    cout << "Encoding coordinates into plaintexts..." << endl;
    Plaintext x1Plaintext = encodePlaintext(x1Coord, cryptoContext, "x1");
    Plaintext y1Plaintext = encodePlaintext(y1Coord, cryptoContext, "y1");
    Plaintext x2Plaintext = encodePlaintext(x2Coord, cryptoContext, "x2");
    Plaintext y2Plaintext = encodePlaintext(y2Coord, cryptoContext, "y2");

    // GENERATE KEYS
    cout << "Running key generation..." << endl;
    LPKeyPair<Element> keyPair = generateKeys(cryptoContext);

    // ENCRYPT PLAINTEXTS
    cout << "Encrypting plaintexts..." << endl;
    LPPublicKey<Element> publicKey = keyPair.publicKey;
    Ciphertext<Element> x1Ciphertext = cryptoContext->Encrypt(publicKey, x1Plaintext);
    Ciphertext<Element> y1Ciphertext = cryptoContext->Encrypt(publicKey, y1Plaintext);
    Ciphertext<Element> x2Ciphertext = cryptoContext->Encrypt(publicKey, x2Plaintext);
    Ciphertext<Element> y2Ciphertext = cryptoContext->Encrypt(publicKey, y2Plaintext);

    // DECRYPT PLAINTEXTS
    cout << "Decrypting ciphertexts..." << endl;
    LPPrivateKey<Element> secretKey = keyPair.secretKey;
    decryptAndCheck(x1Ciphertext, x1Plaintext, secretKey, cryptoContext, "x1");
    decryptAndCheck(y1Ciphertext, y1Plaintext, secretKey, cryptoContext, "y1");
    decryptAndCheck(x2Ciphertext, x2Plaintext, secretKey, cryptoContext, "x2");
    decryptAndCheck(y2Ciphertext, y2Plaintext, secretKey, cryptoContext, "y2");

    DistanceComputer<Element, T> distanceComputer;

    // COMPUTE SQUARE OF DISTANCE
    vector<T> distSq = distanceComputer.computeDistanceSquared(x1, y1, x2, y2);
    Plaintext distSqPlaintext = encodePlaintext(distSq, cryptoContext, "Distance Squared");

    // HOMOMORPHICALLY COMPUTE SQUARE OF DISTANCE
    cout << "EvalMultKeyGen(secretKey)" << endl;
    cryptoContext->EvalMultKeyGen(secretKey);
    cout << "EvalMultKeyGen(secretKey) COMPLETE" << endl;
    Ciphertext<Element> distanceCiphertext = distanceComputer.computeDistanceSquared(x1Ciphertext, y1Ciphertext, x2Ciphertext, y2Ciphertext, cryptoContext, secretKey);
    decryptAndCheck(distanceCiphertext, distSqPlaintext, secretKey, cryptoContext, "Distance Squared");
}

template<class Element, typename T>
void ParamsRunner<Element, T>::printCoordinates(T x, T y, string xName, string yName) {
    cout << "(" << xName << ", " << yName << ") coordinates are: ";
    printf("(%" PRId64 ", ", x);
    printf("%" PRId64 ")\n", y);
}

template<class Element, typename T>
void ParamsRunner<Element, T>::checkDecryption(Plaintext original, Plaintext decrypted) {
    if (*original != *decrypted) {
        cout << "Failed" << endl;
    } else {
        cout << "Successful" << endl;
    }
}

template<class Element, typename T>
void ParamsRunner<Element, T>::decryptAndCheck(Ciphertext<Element> ct, Plaintext pt, LPPrivateKey<Element> sk, CryptoContext<Element> cc, string plaintextName) {

    Plaintext decrypt;
    cc->Decrypt(sk, ct, &decrypt);

    decrypt->SetLength(pt->GetLength());

    cout << "Decrypted " << plaintextName << ": " << decrypt << endl;

    checkDecryption(pt, decrypt);
}

template<class Element>
class CKKSParamsRunner: public ParamsRunner<Element, complex<double>> {

    virtual Plaintext encodePlaintext(vector<complex<double>> coord, CryptoContext<Element> cc, string plaintextName) {
        cout << "in ckks one" << endl;
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

    virtual void checkDecryption(Plaintext original, Plaintext decrypted) {
        cout << "Please check correctness manually for CKKS" << endl;
    }

};

