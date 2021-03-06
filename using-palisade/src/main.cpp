#include "params.h"
#include "paramsrunner.h"

using namespace std;
using namespace lbcrypto;

void printHeader(string schemeName, string setNumber) {
    string title = "| Running " + schemeName + " " + setNumber + " parameter set... |";
    string border(title.length(), '-');
    cout << border << endl;
    cout << title << endl;
    cout << border << "\n" << endl;
}

/** Runs distance computation on a single parameter set
 *  @param value is the parameter set
 */
template<class ParamType, class Element, typename T>
double runDistComp(T x1, T y1, T x2, T y2, ParamType value,
         ParamsRunner<Element, T> *paramsRunner) {

    double start = currentDateTime();
    CryptoContext<Element> cryptoContext = value.generateCryptoContext();

    CKKSParamsRunner<Element>* ckksParamsRunner = dynamic_cast<CKKSParamsRunner<Element>*>(paramsRunner);

    bool supportsComposedMult = false;
    if (is_same<ParamType, BGVrnsParam>::value) {
        supportsComposedMult = true; // only BGVrns supports ComposedEvalMult
    }

    if (ckksParamsRunner != nullptr) {
        ckksParamsRunner->runDistComp(x1, y1, x2, y2, cryptoContext, supportsComposedMult);
    } else {
        paramsRunner->runDistComp(x1, y1, x2, y2, cryptoContext, supportsComposedMult);
    }

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "ms \n" <<  endl;
    return diff;
}

/** Computes the average time for running distance computation for one parameter set */
template <class ParamType, class Element, typename T>
double computeDistCompAvgTime(T x1, T y1, T x2, T y2, ParamType value,
                      ParamsRunner<Element, T> *paramsRunner, int sampleNum) {
    double totalTime = 0;

    streambuf *old = cout.rdbuf(0); // change cout's stream buffer to remove all the print statements when running


    for (int i = 0; i < sampleNum; i++) {
        auto diff = runDistComp(x1, y1, x2, y2, value, paramsRunner);
        totalTime += diff;
    }

    cout.rdbuf(old);
    double avgTime = totalTime / sampleNum;
    return avgTime;
}

/** @brief Runs distance computation for all given parameter sets multiple times
 *  and prints the average time taken for it to run.
 *
 *  @param sampleNum Number of times each parameter set is run
 */
template<class ParamType, class Element, typename T>
void runDistCompTimeCheck(T x1, T y1, T x2, T y2, map<int, ParamType> paramSets, string schemeName,
                    ParamsRunner<Element, T> *paramsRunner, int sampleNum) {
    typename map<int, ParamType>::iterator iter;

    cout << "Running each " << schemeName << " parameter set " << sampleNum << " times" << endl;

    for (iter = paramSets.begin(); iter != paramSets.end(); iter++) {
        auto key = iter->first;
        auto value = iter->second;

        printHeader(schemeName, to_string(key));
        double avgTime = computeDistCompAvgTime<ParamType, Element, T>(x1, y1, x2, y2, value, paramsRunner, sampleNum);
        cout << "Average Time Taken: " << avgTime << "ms \n" <<  endl;
    }
}

/** @brief Runs distance computation on all given parameter sets */

template<class ParamType, class Element, typename T>
void runDistComp(T x1, T y1, T x2, T y2, map<int, ParamType> paramSets, string schemeName,
         ParamsRunner<Element, T> *paramsRunner) {

    typename map<int, ParamType>::iterator iter;

    for (iter = paramSets.begin(); iter != paramSets.end(); iter++) {
        auto key = iter->first;
        auto value = iter->second;

        printHeader(schemeName, to_string(key));
        runDistComp(x1, y1, x2, y2, value, paramsRunner);
    }
}

void runDistCompBGVrns(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isTimeCheck, int sampleNum = 0) {
    string schemeName = "BGVrns";
    ParamsRunner<DCRTPoly, int64_t> paramsRunner;
    if (isTimeCheck) {
        runDistCompTimeCheck<BGVrnsParam, DCRTPoly, int64_t>(x1, y1, x2, y2, BGVrnsParam::ParamSets,
                                                             schemeName, &paramsRunner, sampleNum);
    } else {
        runDistComp<BGVrnsParam, DCRTPoly, int64_t>(x1, y1, x2, y2, BGVrnsParam::ParamSets, schemeName, &paramsRunner);
    }
}

void runDistCompBGV(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isTimeCheck, int sampleNum = 0) {
    string schemeName = "BGV";
    ParamsRunner<Poly, int64_t> paramsRunner;
    if (isTimeCheck) {
        runDistCompTimeCheck<BGVParam, Poly, int64_t>(x1, y1, x2, y2, BGVParam::ParamSets,
                                                      schemeName, &paramsRunner, sampleNum);
    } else {
        runDistComp<BGVParam, Poly, int64_t>(x1, y1, x2, y2, BGVParam::ParamSets, schemeName, &paramsRunner);
    }
}

void runDistCompCKKS(complex<double> x1, complex<double> y1, complex<double> x2, complex<double> y2, bool isTimeCheck, int sampleNum = 0) {
    string schemeName = "CKKS";
    CKKSParamsRunner<DCRTPoly> ckksParamsRunner;
    if (isTimeCheck) {
        runDistCompTimeCheck<CKKSParam, DCRTPoly, complex<double>>(x1, y1, x2, y2, CKKSParam::ParamSets,
                                                                   schemeName, &ckksParamsRunner, sampleNum);
    } else {
        runDistComp<CKKSParam, DCRTPoly, complex<double>>(x1, y1, x2, y2, CKKSParam::ParamSets, schemeName, &ckksParamsRunner);
    }
}

/** Runs check on number of multiplications that can be performed for a single parameter set
 *  before incorrect results are returned.
 */
template<class ParamType, class Element, typename T>
void runMultCheck(T seed, ParamType value, ParamsRunner<Element, T> *paramsRunner) {

    double start = currentDateTime();
    auto cryptoContext = value.generateCryptoContext();

    CKKSParamsRunner<Element>* ckksParamsRunner = dynamic_cast<CKKSParamsRunner<Element>*>(paramsRunner);

    if (ckksParamsRunner != nullptr) {
        ckksParamsRunner->runMultCheck(seed, cryptoContext);
    } else {
        paramsRunner->runMultCheck(seed, cryptoContext);
    }

    double finish = currentDateTime();
    double diff = finish - start;
    cout << "Total time taken: " << diff << "ms \n" <<  endl;
}

/** Runs check on number of multiplications that can be performed for all given parameter sets
 *  before incorrect results are returned.
 */
template<class ParamType, class Element, typename T>
void runMultCheck(T seed, map<int, ParamType> paramSets, string schemeName,
                  ParamsRunner<Element, T> *paramsRunner) {
    typename map<int, ParamType>::iterator iter;

    for (iter = paramSets.begin(); iter != paramSets.end(); iter++) {
        auto key = iter->first;
        auto value = iter->second;

        printHeader(schemeName, to_string(key));

        runMultCheck(seed, value, paramsRunner);
    }
}

void runMultCheckBGVrns(int64_t seed) {
    string schemeName = "BGVrns";
    ParamsRunner<DCRTPoly, int64_t> paramsRunner;
    runMultCheck<BGVrnsParam, DCRTPoly, int64_t>(seed, BGVrnsParam::ParamSets, schemeName, &paramsRunner);
}

void runMultCheckBGV(int64_t seed) {
    string schemeName = "BGV";
    ParamsRunner<Poly, int64_t> paramsRunner;
    runMultCheck<BGVParam, Poly, int64_t>(seed, BGVParam::ParamSets, schemeName, &paramsRunner);
}

void runMultCheckCKKS(complex<double> seed) {
    string schemeName = "CKKS";
    ParamsRunner<DCRTPoly, complex<double>> paramsRunner;
    runMultCheck<CKKSParam, DCRTPoly, complex<double>>(seed, CKKSParam::ParamSets, schemeName, &paramsRunner);
}

int main() {
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

    complex<double> stadiumXCoordDouble = 1.304;
    complex<double> stadiumYCoordDouble = 103.874;
    complex<double> dsoXCoordDouble = 1.290;
    complex<double> dsoYCoordDouble = 103.789;

    cout << "RUNNING DISTANCE COMPUTATION FOR ALL SCHEMES..." << endl;
    runDistCompBGVrns(stadiumXCoord, stadiumYCoord, dsoXCoord, dsoYCoord, false);
    runDistCompBGV(stadiumXCoord, stadiumYCoord, dsoXCoord, dsoYCoord, false);
    runDistCompCKKS(stadiumXCoordDouble, stadiumYCoordDouble, dsoXCoordDouble, dsoYCoordDouble, false);

    cout << "RUNNING DISTANCE COMPUTATION TIME CHECKS..." << endl;
    int sampleNum = 5; // number of times to run each parameter set
    runDistCompBGVrns(stadiumXCoord, stadiumYCoord, dsoXCoord, dsoYCoord, true, sampleNum);
    runDistCompBGV(stadiumXCoord, stadiumYCoord, dsoXCoord, dsoYCoord, true, sampleNum);
    runDistCompCKKS(stadiumXCoordDouble, stadiumYCoordDouble, dsoXCoordDouble, dsoYCoordDouble, true, sampleNum);

    cout << "RUNNING MULTIPLY CHECK FOR BGVrns and BGV..." << endl;
    runMultCheckBGVrns(1); // use 1 so that the result will always be less than the plaintext modulus
    runMultCheckBGV(1);
    // there is currently no support for CKKS as there are approximation errors for this scheme
    // and there is no function to compare plaintext values

    return 0;
}
