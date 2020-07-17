#ifndef VECTOR_H_INCLUDED
#define VECTOR_H_INCLUDED
#define NDEBUG

#include<algorithm>
#include<functional>
#include<vector>
#include<assert.h>

using namespace std;
using std::vector;

/** Method to multiply two vectors element wise.
 *  Referenced from https://stackoverflow.com/questions/3376124/how-to-add-element-by-element-of-two-stl-vectors
 */
template <typename T>
vector<T> operator*(const vector<T> &a, const vector<T> &b) {

    assert(a.size() == b.size());

    vector<T> result;
    result.reserve(a.size());

    transform(a.begin(), a.end(), b.begin(), back_inserter(result), multiplies<T>());

    return result;
}

#endif // VECTOR_H_INCLUDED
