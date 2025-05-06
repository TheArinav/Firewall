#ifndef LCGRANDOM_HPP
#define LCGRANDOM_HPP
#include <cstdint>

class LCGRandom
{
    private:
    uint32_t state;
    public:
    LCGRandom();
    ~LCGRandom();
    int NextInt(int start, int offset);
};
#endif //LCGRANDOM_HPP
