#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <pke\palisade.h>
#include <pke\cryptocontextgen.h>
#include <typeinfo>
#include <core\palisadecore.h>
#include <math.h>

using namespace std;
using namespace lbcrypto;

template <class Element>
void printParameters(CryptoContext<Element> cryptoContext) {

    // GET PARAMETER SET
    usint p = cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    usint n = cryptoContext->GetCryptoParameters()
                        ->GetElementParams()
                        ->GetCyclotomicOrder() / 2;
    auto q = cryptoContext->GetCryptoParameters()
                        ->GetElementParams()
                        ->GetModulus();

    cout << "p (plaintext modulus) = "
        << p
        << endl;
    cout << "n (ring dimension?) =  "
        << n
        << endl;
    cout << "q (size of field) = "
        << q
        << endl;
}

template <class Element>
LPKeyPair<Element> generateKeys(CryptoContext<Element> cryptoContext) {

    LPKeyPair<Element> keyPair;
    keyPair = cryptoContext->KeyGen();

    if (!keyPair.good()) {
        cout << "Key generation failed!" << endl;
        exit(1);
    }

    return keyPair;
}

template <typename T>
void printCoordinates(T x, T y, string xName, string yName, bool isCKKS) {
    cout << "(" << xName << ", " << yName << ") coordinates are: ";
    if (isCKKS) {
        printf("(%f + %fi, ", real(x), imag(x));
        printf("%f + %fi) \n", real(y), imag(y));
    } else {
        printf("(%" PRId64 ", ", x);
        printf("%" PRId64 ")\n", y);
    }
}

template <class Element, typename T>
Plaintext encodeAndPrintPlaintext(vector<T> coord, CryptoContext<Element> cc, string plaintextName, bool isCKKS) {
    Plaintext plaintext;
    if (isCKKS) {
        vector<complex<double>>* castedCoord;
        castedCoord = (vector<complex<double>>*) &coord;
        plaintext = cc->MakeCKKSPackedPlaintext(*castedCoord);
    } else {
        vector<int64_t>* castedCoord;
        castedCoord = (vector<int64_t>*) &coord;
        plaintext = cc->MakeCoefPackedPlaintext(*castedCoord);
    }
    cout << plaintextName << " Plaintext: " << plaintext << endl;
    return plaintext;
}

template <class Element>
Plaintext encodeCKKSAndPrintPlaintext(vector<complex<double>> coord, CryptoContext<Element> cc, string plaintextName) {
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(coord);
    cout << plaintextName << " Plaintext: " << plaintext << endl;
    return plaintext;
}

void checkDecryption(Plaintext original, Plaintext decrypted) {
    if (*original != *decrypted) {
        cout << "Failed" << endl;
    } else {
        cout << "Successful" << endl;
    }
}

template <class Element>
void decryptCiphertextAndCheck(Ciphertext<Element> ct, Plaintext pt, LPPrivateKey<Element> sk, CryptoContext<Element> cc, string plaintextName) {

    Plaintext decrypt;
    cc->Decrypt(sk, ct, &decrypt);

    // SET LENGTHS OF DECRYPTED PLAINTEXTS BACK TO ORIGINAL LENGTH FOR COMPARISON PURPOSES

    decrypt->SetLength(pt->GetLength());

    // PRINT DECRYPTED CIPHERTEXT
    cout << "Decrypted " << plaintextName << ": " << decrypt << endl;

    // CHECK IF DECRYPTION IS CORRECT
    checkDecryption(pt, decrypt);
}

template <typename T>
T computeDistanceSquared(T x1, T y1, T x2, T y2) {
    cout << "Evaluating actual square of distance..." << endl;
    auto xDiff = abs(x1 - x2);
    auto yDiff = abs(y1 - y2);
    auto yDiffSquared = pow(yDiff, 2);
    auto distanceSquared = pow(xDiff, 2) + pow(yDiff, 2);
    cout << "Square of distance = " << distanceSquared << endl;
    return distanceSquared;
}

template <class Element>
Ciphertext<Element> computeDistanceSquared(Ciphertext<Element> x1, Ciphertext<Element> y1,
                                        Ciphertext<Element> x2, Ciphertext<Element> y2,
                                        CryptoContext<Element> cc, LPPrivateKey<Element> secretKey) {
    cout << "Homomorphically evaluating square of distance..." << endl;

    cout << "Computing xDiff..." << endl;
    auto xDiff = cc->EvalSub(x1, x2);
    Plaintext xDiffDecrypt;
    cc->Decrypt(secretKey, xDiff, &xDiffDecrypt);
    xDiffDecrypt->SetLength(1);
    cout << "Decrypted " << "xDiff: " << xDiffDecrypt << endl;

    cout << "Computing yDiff..." << endl;
    auto yDiff = cc->EvalSub(y1, y2);
    Plaintext yDiffDecrypt;
    cc->Decrypt(secretKey, yDiff, &yDiffDecrypt);
    yDiffDecrypt->SetLength(1);
    cout << "Decrypted " << "yDiff: " << yDiffDecrypt << endl;

    cout << "Computing xDiffSq..." << endl;
    auto xDiffSq = cc->EvalMult(xDiff, xDiff);
    Plaintext xDiffSqDecrypt;
    cc->Decrypt(secretKey, xDiffSq, &xDiffSqDecrypt);
    xDiffSqDecrypt->SetLength(1);
    cout << "Decrypted " << "xDiffSq: " << xDiffSqDecrypt << endl;

    cout << "Computing yDiffSq..." << endl;
    auto yDiffSq = cc->EvalMult(yDiff, yDiff);
    Plaintext yDiffSqDecrypt;
    cc->Decrypt(secretKey, yDiffSq, &yDiffSqDecrypt);
    yDiffSqDecrypt->SetLength(1);
    cout << "Decrypted " << "yDiffSq: " << yDiffSqDecrypt << endl;

    cout << "Computing total sum..." << endl;
    auto sum = cc->EvalAdd(xDiffSq, yDiffSq);
    return sum;
}

template <class Element, typename T>
void run(T x1, T y1, T x2, T y2, CryptoContext<Element> cryptoContext, bool isCKKS) {

    // PRINT PARAMETER SET
    printParameters(cryptoContext);

    // PRINT ORIGINAL COORDINATES
    printCoordinates(x1, y1, "x1", "y1", isCKKS);
    printCoordinates(x2, y2, "x2", "y2", isCKKS);

    vector<T> x1Coord{x1};
    vector<T> y1Coord{y1};
    vector<T> x2Coord{x2};
    vector<T> y2Coord{y2};

    // ENABLE ENCRYPTION AND SHE
    cryptoContext->Enable(ENCRYPTION);
    cryptoContext->Enable(SHE);

    // ENCODE COORDINATES INTO PLAINTEXTS
    cout << "Encoding coordinates into plaintexts..." << endl;
    Plaintext x1Plaintext = encodeAndPrintPlaintext(x1Coord, cryptoContext, "x1", isCKKS);
    Plaintext y1Plaintext = encodeAndPrintPlaintext(y1Coord, cryptoContext, "y1", isCKKS);
    Plaintext x2Plaintext = encodeAndPrintPlaintext(x2Coord, cryptoContext, "x2", isCKKS);
    Plaintext y2Plaintext = encodeAndPrintPlaintext(y2Coord, cryptoContext, "y2", isCKKS);

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
    decryptCiphertextAndCheck(x1Ciphertext, x1Plaintext, secretKey, cryptoContext, "x1");
    decryptCiphertextAndCheck(y1Ciphertext, y1Plaintext, secretKey, cryptoContext, "y1");
    decryptCiphertextAndCheck(x2Ciphertext, x2Plaintext, secretKey, cryptoContext, "x2");
    decryptCiphertextAndCheck(y2Ciphertext, y2Plaintext, secretKey, cryptoContext, "y2");

    // COMPUTE SQUARE OF DISTANCE
    T dSquare = computeDistanceSquared(x1, y1, x2, y2);
    vector<T> distance{dSquare};
    Plaintext distancePlaintext = encodeAndPrintPlaintext(distance, cryptoContext, "Distance", isCKKS);

    // HOMOMORPHICALLY COMPUTE SQUARE OF DISTANCE
    cout << "EvalMultKeyGen(secretKey)" << endl;
    cryptoContext->EvalMultKeyGen(secretKey);
    cout << "EvalMultKeyGen(secretKey) done " << endl;
    Ciphertext<Element> distanceCiphertext = computeDistanceSquared(x1Ciphertext, y1Ciphertext, x2Ciphertext, y2Ciphertext, cryptoContext, secretKey);
    decryptCiphertextAndCheck(distanceCiphertext, distancePlaintext, secretKey, cryptoContext, "Distance");
}

void runBGVrns1(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (1) BGVrns using parameters from PALISADE example in `depth-bgvrns.cpp` ||" << endl;
    usint plaintextModulus = 536903681;
    double sigma = 3.2;
    SecurityLevel securityLevel = HEStd_128_classic;

    CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(3, plaintextModulus, securityLevel, sigma, 1, RLWE, BV, 65536);

    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGVrns2(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (2) BGVrns ||" << endl;
    usint plaintextModulus = 536903681; // 736213581
    double sigma = 3.2;
    SecurityLevel securityLevel = HEStd_128_classic;

    CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(3, plaintextModulus, securityLevel, sigma, 1, RLWE, BV, 32768);
    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGVrns3(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (3) BGVrns ||" << endl;
    usint plaintextModulus = 536903681;
    double sigma = 3.2;
    SecurityLevel securityLevel = HEStd_128_classic;

    CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(3, plaintextModulus, securityLevel, sigma, 1, RLWE, BV);
    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGVrns4(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (4) BGVrns ||" << endl;
    usint plaintextModulus = 536903681;
    double sigma = 3.2;
    SecurityLevel securityLevel = HEStd_128_classic;

    CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(1, plaintextModulus, securityLevel, sigma, 1, RLWE, BV);
    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGVrns5(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (5) BGVrns ||" << endl;
    usint plaintextModulus = 536903681;
    double sigma = 3.2;
    SecurityLevel securityLevel = HEStd_128_classic;

    CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(0, plaintextModulus, securityLevel, sigma, 1, RLWE, BV);
    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGVrns7(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (7) BGVrns ||" << endl;
    usint plaintextModulus = 207748;
    double sigma = 3.2;
    SecurityLevel securityLevel = HEStd_128_classic;

    CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(1, plaintextModulus, securityLevel, sigma, 1, RLWE, BV, 8192);
    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

template <typename IntType>
IntType GetCoprime(const IntType &n, uint64_t minValue, int counter) {
    IntType one(1);
    int c = 1;
    for (IntType i = IntType(1); i < n; i = i + IntType(1)) {
        if (GreatestCommonDivisor(i, n) == one && i >= minValue){
            if (c <= counter) {
                c++;
                continue;
            }
            return i;
        }
    }
}

void runBGV1(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (1) BGV ||" << endl;
    uint64_t order = 131072;
    uint64_t numOfBits = 30;
    auto ciphertextModulus = BigInteger("1073872897");

    auto maxCoord = max({x1, y1, x2, y2});
    PlaintextModulus plaintextModulus(207755);

    auto params = std::make_shared<ILParams>(order, ciphertextModulus);

    usint relinWindow = 1;
    float sigma = 2;

    CryptoContext<Poly> cryptoContext = CryptoContextFactory<Poly>::genCryptoContextBGV(params, plaintextModulus, relinWindow, sigma, RLWE, 1);

    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGV2(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (2) BGV ||" << endl;
    uint64_t order = 131072;
    uint64_t numOfBits = 30;
    auto ciphertextModulus = NextPrime<NativeInteger>(FirstPrime<NativeInteger>(numOfBits, order), order);
    auto maxCoord = max({x1, y1, x2, y2});
    PlaintextModulus plaintextModulus(GetCoprime(ciphertextModulus, 2 * maxCoord + 1, 6).ConvertToInt());

    auto params = std::make_shared<ILParams>(order, ciphertextModulus);

    usint relinWindow = 1;
    float sigma = 2;

    CryptoContext<Poly> cryptoContext = CryptoContextFactory<Poly>::genCryptoContextBGV(params, plaintextModulus, relinWindow, sigma);

    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGV8(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (8) BGV ||" << endl;
    uint64_t order = 256;
    uint64_t numOfBits = 60;
    auto maxCoord = max({x1, y1, x2, y2});
    PlaintextModulus plaintextModulus(207749);

    int numOfTowers = 1;

    shared_ptr<ILParams> p =
      ElemParamFactory::GenElemParams<ILParams>(order, numOfBits, numOfTowers);

    CryptoContext<Poly> cryptoContext =
      CryptoContextFactory<Poly>::genCryptoContextBGV(p, plaintextModulus, 1, 4, RLWE);
    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGV9(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (9) BGV ||" << endl;
    uint64_t order = 128;
    uint64_t numOfBits = 60;
    auto maxCoord = max({x1, y1, x2, y2});
    PlaintextModulus plaintextModulus(207749);

    int numOfTowers = 1;

    shared_ptr<ILParams> p =
      ElemParamFactory::GenElemParams<ILParams>(order, numOfBits, numOfTowers);

    CryptoContext<Poly> cryptoContext =
      CryptoContextFactory<Poly>::genCryptoContextBGV(p, plaintextModulus, 1, 4, RLWE);
    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGV10(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (10) BGV ||" << endl;
    uint64_t order = 64;
    uint64_t numOfBits = 60;
    auto maxCoord = max({x1, y1, x2, y2});
    PlaintextModulus plaintextModulus(207749);

    int numOfTowers = 1;

    shared_ptr<ILParams> p =
      ElemParamFactory::GenElemParams<ILParams>(order, numOfBits, numOfTowers);

    CryptoContext<Poly> cryptoContext =
      CryptoContextFactory<Poly>::genCryptoContextBGV(p, plaintextModulus, 1, 4, RLWE);
    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGV11(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (11) BGV ||" << endl;
    uint64_t order = 8192;
    uint64_t numOfBits = 70;
    auto maxCoord = max({x1, y1, x2, y2});
    PlaintextModulus plaintextModulus(207749);

    int numOfTowers = 1;

    shared_ptr<ILParams> p =
      ElemParamFactory::GenElemParams<ILParams>(order, numOfBits, numOfTowers);

    CryptoContext<Poly> cryptoContext =
      CryptoContextFactory<Poly>::genCryptoContextBGV(p, plaintextModulus, 1, 4, RLWE);
    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGV12(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (12) BGV ||" << endl;
    uint64_t order = 16384;
    uint64_t numOfBits = 80;
    auto maxCoord = max({x1, y1, x2, y2});
    PlaintextModulus plaintextModulus(207749);

    int numOfTowers = 1;

    shared_ptr<ILParams> p =
      ElemParamFactory::GenElemParams<ILParams>(order, numOfBits, numOfTowers);

    CryptoContext<Poly> cryptoContext =
      CryptoContextFactory<Poly>::genCryptoContextBGV(p, plaintextModulus, 1, 4, RLWE);
    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGV13(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (13) BGV ||" << endl;
    uint64_t order = 65536;
    uint64_t numOfBits = 100;
    auto maxCoord = max({x1, y1, x2, y2});
    PlaintextModulus plaintextModulus(207749);

    int numOfTowers = 1;

    shared_ptr<ILParams> p =
      ElemParamFactory::GenElemParams<ILParams>(order, numOfBits, numOfTowers);

    CryptoContext<Poly> cryptoContext =
      CryptoContextFactory<Poly>::genCryptoContextBGV(p, plaintextModulus, 1, 4, RLWE);
    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGV14(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (14) BGV ||" << endl;
    uint64_t order = 65536;
    uint64_t numOfBits = 90;
    auto maxCoord = max({x1, y1, x2, y2});
    PlaintextModulus plaintextModulus(207749);

    int numOfTowers = 1;

    shared_ptr<ILParams> p =
      ElemParamFactory::GenElemParams<ILParams>(order, numOfBits, numOfTowers);

    CryptoContext<Poly> cryptoContext =
      CryptoContextFactory<Poly>::genCryptoContextBGV(p, plaintextModulus, 1, 4, RLWE);
    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGV15(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (15) BGV ||" << endl;
    uint64_t order = 65536;
    uint64_t numOfBits = 80;
    auto maxCoord = max({x1, y1, x2, y2});
    PlaintextModulus plaintextModulus(207749);

    int numOfTowers = 1;

    shared_ptr<ILParams> p =
      ElemParamFactory::GenElemParams<ILParams>(order, numOfBits, numOfTowers);

    CryptoContext<Poly> cryptoContext =
      CryptoContextFactory<Poly>::genCryptoContextBGV(p, plaintextModulus, 1, 4, RLWE);
    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runCKKS1(complex<double> x1, complex<double> y1, complex<double> x2, complex<double> y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (1) CKKS ||" << endl;

    usint cyclOrder = 131072;
    usint numPrimes = 1;
    usint scaleExp = 57;
    usint relinWindow = 10;
    usint batchSize = 5;

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContextCKKS<DCRTPoly>(cyclOrder, numPrimes, scaleExp, relinWindow, batchSize, RLWE, BV, APPROXRESCALE);

    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runCKKS2(complex<double> x1, complex<double> y1, complex<double> x2, complex<double> y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (2) CKKS ||" << endl;

    uint32_t multDepth = 5;
    uint32_t scaleFactorBits = 50;
    uint32_t batchSize = 8;
    SecurityLevel securityLevel = HEStd_128_classic;
    // 0 means the library will choose it based on securityLevel
    uint32_t ringDimension = 0;
    CryptoContext<DCRTPoly> cryptoContext =
    CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
      multDepth, scaleFactorBits, batchSize, securityLevel, ringDimension,
      APPROXRESCALE);

    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runCKKS3(complex<double> x1, complex<double> y1, complex<double> x2, complex<double> y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (3) CKKS ||" << endl;

    usint cyclOrder = 2097152;
    usint numPrimes = 1;
    usint scaleExp = 47;
    usint relinWindow = 10;
    usint batchSize = 5;

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContextCKKS<DCRTPoly>(cyclOrder, numPrimes, scaleExp, relinWindow, batchSize, RLWE, BV, APPROXRESCALE);

    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runCKKS7(complex<double> x1, complex<double> y1, complex<double> x2, complex<double> y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (7) CKKS ||" << endl;

    usint cyclOrder = 2097152;
    usint numPrimes = 2;
    usint scaleExp = 47;
    usint relinWindow = 10;
    usint batchSize = 5;

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContextCKKS<DCRTPoly>(cyclOrder, numPrimes, scaleExp, relinWindow, batchSize, RLWE, BV, APPROXRESCALE);

    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runCKKS8(complex<double> x1, complex<double> y1, complex<double> x2, complex<double> y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (8) CKKS ||" << endl;

    usint cyclOrder = 256;
    usint numPrimes = 2;
    usint scaleExp = 52;
    usint relinWindow = 10;
    usint batchSize = 5;

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContextCKKS<DCRTPoly>(cyclOrder, numPrimes, scaleExp, relinWindow, batchSize, RLWE, BV, APPROXRESCALE);

    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runBGVrns(int64_t x1, int64_t y1, int64_t x2, int64_t y2) {
    runBGVrns1(x1, y1, x2, y2, false);
    runBGVrns2(x1, y1, x2, y2, false);
    runBGVrns3(x1, y1, x2, y2, false);
    runBGVrns4(x1, y1, x2, y2, false);
    runBGVrns5(x1, y1, x2, y2, false);
    // case 6 causes error
    runBGVrns7(x1, y1, x2, y2, false);
    // case 8 causes error
}

void runBGV(int64_t x1, int64_t y1, int64_t x2, int64_t y2) {
    //runBGV1(x1, y1, x2, y2, false);
    //runBGV2(x1, y1, x2, y2, false);
    //runBGV8(x1, y1, x2, y2, false);
    //runBGV9(x1, y1, x2, y2, false);
    //runBGV10(x1, y1, x2, y2, false);
    //runBGV11(x1, y1, x2, y2, false);
    //runBGV12(x1, y1, x2, y2, false);
    //runBGV13(x1, y1, x2, y2, false);
    //runBGV14(x1, y1, x2, y2, false);
    runBGV15(x1, y1, x2, y2, false);
}


void runCKKS(complex<double> x1, complex<double> y1, complex<double> x2, complex<double> y2) {
    //runCKKS1(x1, y1, x2, y2, true);
    //runCKKS2(x1, y1, x2, y2, true);
    //runCKKS3(x1, y1, x2, y2, true);
    //runCKKS7(x1, y1, x2, y2, true);
    runCKKS8(x1, y1, x2, y2, true);
}

int main()
{

    // The coordinates of the national stadium are
    // Latitude: 1.3044172525405884 or 1304.4172525405884 x 10^{-3}
    // Longitude: 103.87432861328125 or 103874.32861328125 x 10^{-3}
    // We take the part before the decimal point for each
    int64_t stadiumXCoord = 1304;
    int64_t stadiumYCoord = 103874;

    // The coordinates of DSO are
    // Latitude: 1.290164 or 1290.164 x 10^{-3}
    // Longitude: 103.789106 or 103789.106 x 10^{-3}
    int64_t dsoXCoord = 1290;
    int64_t dsoYCoord = 103789;

    //runBGVrns(stadiumXCoord, stadiumYCoord, dsoXCoord, dsoYCoord);
    runBGV(stadiumXCoord, stadiumYCoord, dsoXCoord, dsoYCoord);

    complex<double> stadiumXCoordDouble = 1.304;
    complex<double> stadiumYCoordDouble = 103.874;
    complex<double> dsoXCoordDouble = 1.290;
    complex<double> dsoYCoordDouble = 103.789;

    //runCKKS(stadiumXCoordDouble, stadiumYCoordDouble, dsoXCoordDouble, dsoYCoordDouble);

    return 0;
}
