#ifndef LCGRANDOM_HPP
#define LCGRANDOM_HPP
#include <cstdint>

class LCGRandom
{
    private:
    mutable uint32_t state;


public:
    // Prevent copying
    LCGRandom(const LCGRandom&) = delete;
    LCGRandom& operator=(const LCGRandom&) = delete;

    // Allow moving
    LCGRandom(LCGRandom&&) noexcept = default;
    LCGRandom& operator=(LCGRandom&&) noexcept = default;
    LCGRandom();
    ~LCGRandom();
    int NextInt(int start, int offset) const;
};
#endif //LCGRANDOM_HPP
