#include "LCGRandom.hpp"
#include <random>

using namespace std;

#define LCG_A 0x0019660D
#define LCG_C 0x3C6EF35F

LCGRandom::LCGRandom()
{
    random_device rd;
    this->state = rd();
}

LCGRandom::~LCGRandom()
{
    this->state = 0;
}

int LCGRandom::NextInt(const int start, const int offset)
{
    this->state = LCG_A * this->state + LCG_C;
    return static_cast<int>(this->state % (offset - start) + start);
}
