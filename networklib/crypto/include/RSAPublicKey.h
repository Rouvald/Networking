#ifndef RSAPUBLICKEY_H
#define RSAPUBLICKEY_H

#include <boost/multiprecision/cpp_int.hpp>

struct RSAPublicKey
{
    boost::multiprecision::cpp_int _exponent;
    boost::multiprecision::cpp_int _modulus;
};

#endif  // RSAPUBLICKEY_H
