#ifndef RSAPUBLICKEY_H
#define RSAPUBLICKEY_H

#include <boost/multiprecision/cpp_int.hpp>

struct RSAPublicKey
{
    boost::multiprecision::cpp_int exponent;
    boost::multiprecision::cpp_int modulus;
};

#endif  // RSAPUBLICKEY_H
