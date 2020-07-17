#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <pke\palisade.h>
#include <pke\cryptocontextgen.h>
#include <typeinfo>
#include <core\palisadecore.h>
#include <math.h>

#include "params.h"
#include "paramsrunner.h"

using namespace std;
using namespace lbcrypto;
/*
void runCKKS1(complex<double> x1, complex<double> y1, complex<double> x2, complex<double> y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (1) CKKS ||" << endl;

    int64_t cyclOrder = 131072;
    int64_t numPrimes = 1;
    int64_t scaleExp = 57;
    int64_t relinWindow = 10;
    int64_t batchSize = 5;

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

    int64_t cyclOrder = 2097152;
    int64_t numPrimes = 1;
    int64_t scaleExp = 47;
    int64_t relinWindow = 10;
    int64_t batchSize = 5;

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContextCKKS<DCRTPoly>(cyclOrder, numPrimes, scaleExp, relinWindow, batchSize, RLWE, BV, APPROXRESCALE);

    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runCKKS7(complex<double> x1, complex<double> y1, complex<double> x2, complex<double> y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (7) CKKS ||" << endl;

    int64_t cyclOrder = 2097152;
    int64_t numPrimes = 2;
    int64_t scaleExp = 47;
    int64_t relinWindow = 10;
    int64_t batchSize = 5;

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContextCKKS<DCRTPoly>(cyclOrder, numPrimes, scaleExp, relinWindow, batchSize, RLWE, BV, APPROXRESCALE);

    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runCKKS8(complex<double> x1, complex<double> y1, complex<double> x2, complex<double> y2, bool isCKKS) {
    double start = currentDateTime();

    cout << "|| Generating CryptoContext for (8) CKKS ||" << endl;

    int64_t cyclOrder = 256;
    int64_t numPrimes = 2;
    int64_t scaleExp = 52;
    int64_t relinWindow = 10;
    int64_t batchSize = 5;

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContextCKKS<DCRTPoly>(cyclOrder, numPrimes, scaleExp, relinWindow, batchSize, RLWE, BV, APPROXRESCALE);

    run(x1, y1, x2, y2, cryptoContext, isCKKS);

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "\n" <<  endl;
}

void runCKKS(complex<double> x1, complex<double> y1, complex<double> x2, complex<double> y2) {
    //runCKKS1(x1, y1, x2, y2, true);
    //runCKKS2(x1, y1, x2, y2, true);
    //runCKKS3(x1, y1, x2, y2, true);
    //runCKKS7(x1, y1, x2, y2, true);
    runCKKS8(x1, y1, x2, y2, true);
}
*/

void printHeader(string schemeName, string setNumber) {
    string title = "| Running " + schemeName + " " + setNumber + " parameter set... |";
    string border(title.length(), '-');
    cout << border << endl;
    cout << title << endl;
    cout << border << "\n" << endl;
}

template<class ParamType, class Element, typename T>
void run(T x1, T y1, T x2, T y2, map<int, ParamType> paramSet, string schemeName,
         ParamsRunner<Element, T> *paramsRunner) {

    typename map<int, ParamType>::iterator iter;

    for (iter = paramSet.begin(); iter != paramSet.end(); iter++) {
        auto key = iter->first;
        auto value = iter->second;

        printHeader(schemeName, to_string(key));
        double start = currentDateTime();

        auto cryptoContext = value.generateCryptoContext();

        CKKSParamsRunner<Element>* ckksParamsRunner = dynamic_cast<CKKSParamsRunner<Element>*>(paramsRunner);

        if (ckksParamsRunner != nullptr) {
            ckksParamsRunner->run(x1, y1, x2, y2, cryptoContext);
        } else {
            paramsRunner->run(x1, y1, x2, y2, cryptoContext);

        }

        double finish = currentDateTime();
        double diff = finish - start;
        cout << "Total time taken: " << diff << "\n" <<  endl;
    }
}

void runBGVrns(int64_t x1, int64_t y1, int64_t x2, int64_t y2) {
    string schemeName = "BGVrns";
    ParamsRunner<DCRTPoly, int64_t> paramsRunner;
    run<BGVrnsParam, DCRTPoly, int64_t>(x1, y1, x2, y2, BGVrnsParam::ParamSets, schemeName, &paramsRunner);
}

void runBGV(int64_t x1, int64_t y1, int64_t x2, int64_t y2) {
    string schemeName = "BGV";
    ParamsRunner<Poly, int64_t> paramsRunner;
    run<BGVParam, Poly, int64_t>(x1, y1, x2, y2, BGVParam::ParamSets, schemeName, &paramsRunner);
}

void runCKKS(complex<double> x1, complex<double> y1, complex<double> x2, complex<double> y2) {
    string schemeName = "CKKS";
    CKKSParamsRunner<DCRTPoly> ckksParamsRunner;
    run<CKKSParam, DCRTPoly, complex<double>>(x1, y1, x2, y2, CKKSParam::ParamSets, schemeName, &ckksParamsRunner);
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
    //runBGV(stadiumXCoord, stadiumYCoord, dsoXCoord, dsoYCoord);

    complex<double> stadiumXCoordDouble = 1.304;
    complex<double> stadiumYCoordDouble = 103.874;
    complex<double> dsoXCoordDouble = 1.290;
    complex<double> dsoYCoordDouble = 103.789;

    runCKKS(stadiumXCoordDouble, stadiumYCoordDouble, dsoXCoordDouble, dsoYCoordDouble);

    return 0;
}
