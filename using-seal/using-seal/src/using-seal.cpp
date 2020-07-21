// using-seal.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <chrono>
#include "../include/paramsrunner.h"
#include "../include/params.h"

using namespace std;
using namespace seal;
using namespace chrono;

void printHeader(string schemeName, string setNumber) {
    string title = "| Running " + schemeName + " " + setNumber + " parameter set... |";
    string border(title.length(), '-');
    cout << border << endl;
    cout << title << endl;
    cout << border << "\n" << endl;
}

steady_clock::time_point getCurrentTime() {
    return steady_clock::now();
}

template<typename T, class EncoderType, class ParamType>
void runDistComp(T x1, T y1, T x2, T y2, ParamType value, ParamsRunner<T, EncoderType>* paramsRunner) {

    steady_clock::time_point start = getCurrentTime();
    auto context = value.generateContext();
    auto scale = value.getScale();

    paramsRunner->runDistComp(x1, y1, x2, y2, context, scale);

    steady_clock::time_point finish = getCurrentTime();
    auto diff = duration_cast<milliseconds> (finish - start).count();
    cout << "Total time taken: " << diff << "\n" << endl;
}

template <typename T, class EncoderType, class ParamType>
void runDistComp(T x1, T y1, T x2, T y2, map<int, ParamType> paramSets, string schemeName, ParamsRunner<T, EncoderType> paramsRunner) {
    typename map<int, ParamType>::iterator iter;

    for (iter = paramSets.begin(); iter != paramSets.end(); iter++) {
        auto key = iter->first;
        auto value = iter->second;

        printHeader(schemeName, to_string(key));
        runDistComp<T, EncoderType, ParamType>(x1, y1, x2, y2, value, &paramsRunner);
    }
}

void runDistCompCKKS(double x1, double y1, double x2, double y2) {
    string schemeName = "CKKS";
    ParamsRunner<double, CKKSEncoder> paramsRunner;
    /*
    if (isTimeCheck) {
        runDistCompTimeCheck<CKKSParam, DCRTPoly, complex<double>>(x1, y1, x2, y2, CKKSParam::ParamSets,
            schemeName, &ckksParamsRunner, sampleNum);
    }
    */
    runDistComp<double, CKKSEncoder, CKKSParam>(x1, y1, x2, y2, CKKSParam::ParamSets, schemeName, paramsRunner);
}

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

    runDistCompCKKS(stadiumXCoordDouble, stadiumYCoordDouble, dsoXCoordDouble, dsoYCoordDouble);

}