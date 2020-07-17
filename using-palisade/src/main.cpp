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

template <class ParamType, class Element, typename T>
double computeAvgTime(T x1, T y1, T x2, T y2, ParamType value,
                      ParamsRunner<Element, T> *paramsRunner, int sampleNum) {
    double totalTime = 0;

    streambuf *old = cout.rdbuf(0); // change cout's stream buffer to remove all the print statements when running

    for (int i = 0; i < sampleNum; i++) {
        double start = currentDateTime();

        auto cryptoContext = value.generateCryptoContext();
        run(x1, y1, x2, y2, cryptoContext, paramsRunner);

        double finish = currentDateTime();
        double diff = finish - start;
        totalTime += diff;
    }

    cout.rdbuf(old);
    double avgTime = totalTime / sampleNum;
    return avgTime;
}

/** @brief Runs each parameter set multiple times and prints the average time taken for it to run.
 *
 * @param sampleNum Number of times each parameter set is run
 */
template<class ParamType, class Element, typename T>
void runAvgTimeCheck(T x1, T y1, T x2, T y2, map<int, ParamType> paramSets, string schemeName,
                    ParamsRunner<Element, T> *paramsRunner, int sampleNum) {
    typename map<int, ParamType>::iterator iter;

    cout << "Running each " << schemeName << " parameter set " << sampleNum << " times" << endl;

    for (iter = paramSets.begin(); iter != paramSets.end(); iter++) {
        auto key = iter->first;
        auto value = iter->second;

        printHeader(schemeName, to_string(key));
        double avgTime = computeAvgTime<ParamType, Element, T>(x1, y1, x2, y2, value, paramsRunner, sampleNum);
        cout << "Average Time Taken: " << avgTime << "\n" <<  endl;
    }
}

template<class Element, typename T>
void run(T x1, T y1, T x2, T y2, CryptoContext<Element> cryptoContext,
         ParamsRunner<Element, T> *paramsRunner) {
    CKKSParamsRunner<Element>* ckksParamsRunner = dynamic_cast<CKKSParamsRunner<Element>*>(paramsRunner);

    if (ckksParamsRunner != nullptr) {
        ckksParamsRunner->run(x1, y1, x2, y2, cryptoContext);
    } else {
        paramsRunner->run(x1, y1, x2, y2, cryptoContext);
    }
}

template<class ParamType, class Element, typename T>
void run(T x1, T y1, T x2, T y2, map<int, ParamType> paramSets, string schemeName,
         ParamsRunner<Element, T> *paramsRunner) {

    typename map<int, ParamType>::iterator iter;

    for (iter = paramSets.begin(); iter != paramSets.end(); iter++) {
        auto key = iter->first;
        auto value = iter->second;

        printHeader(schemeName, to_string(key));
        double start = currentDateTime();

        auto cryptoContext = value.generateCryptoContext();
        run(x1, y1, x2, y2, cryptoContext, paramsRunner);

        double finish = currentDateTime();
        double diff = finish - start;
        cout << "Total time taken: " << diff << "\n" <<  endl;
    }
}

void runBGVrns(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isTimeCheck, int sampleNum = 0) {
    string schemeName = "BGVrns";
    ParamsRunner<DCRTPoly, int64_t> paramsRunner;
    if (isTimeCheck) {
        runAvgTimeCheck<BGVrnsParam, DCRTPoly, int64_t>(x1, y1, x2, y2, BGVrnsParam::ParamSets,
                                                        schemeName, &paramsRunner, sampleNum);
    } else {
        run<BGVrnsParam, DCRTPoly, int64_t>(x1, y1, x2, y2, BGVrnsParam::ParamSets, schemeName, &paramsRunner);
    }
}

void runBGV(int64_t x1, int64_t y1, int64_t x2, int64_t y2, bool isTimeCheck, int sampleNum = 0) {
    string schemeName = "BGV";
    ParamsRunner<Poly, int64_t> paramsRunner;
    if (isTimeCheck) {
        runAvgTimeCheck<BGVParam, Poly, int64_t>(x1, y1, x2, y2, BGVParam::ParamSets,
                                                 schemeName, &paramsRunner, sampleNum);
    } else {
        run<BGVParam, Poly, int64_t>(x1, y1, x2, y2, BGVParam::ParamSets, schemeName, &paramsRunner);
    }
}

void runCKKS(complex<double> x1, complex<double> y1, complex<double> x2, complex<double> y2, bool isTimeCheck, int sampleNum = 0) {
    string schemeName = "CKKS";
    CKKSParamsRunner<DCRTPoly> ckksParamsRunner;
    if (isTimeCheck) {
        runAvgTimeCheck<CKKSParam, DCRTPoly, complex<double>>(x1, y1, x2, y2, CKKSParam::ParamSets,
                                                              schemeName, &ckksParamsRunner, sampleNum);
    } else {
        run<CKKSParam, DCRTPoly, complex<double>>(x1, y1, x2, y2, CKKSParam::ParamSets, schemeName, &ckksParamsRunner);
    }
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

    cout << "RUNNING FOR ALL SCHEMES..." << endl;
    runBGVrns(stadiumXCoord, stadiumYCoord, dsoXCoord, dsoYCoord);
    runBGV(stadiumXCoord, stadiumYCoord, dsoXCoord, dsoYCoord);
    runCKKS(stadiumXCoordDouble, stadiumYCoordDouble, dsoXCoordDouble, dsoYCoordDouble);

    cout << "RUNNING TIME CHECKS..." << endl;
    int sampleNum = 5; // number of times to run each parameter set
    runBGVrns(stadiumXCoord, stadiumYCoord, dsoXCoord, dsoYCoord, true, sampleNum);
    runBGV(stadiumXCoord, stadiumYCoord, dsoXCoord, dsoYCoord, true, sampleNum);
    runCKKS(stadiumXCoordDouble, stadiumYCoordDouble, dsoXCoordDouble, dsoYCoordDouble, true, sampleNum);

    return 0;
}
