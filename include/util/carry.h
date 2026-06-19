#ifndef UTIL_CARRY_H_
#define UTIL_CARRY_H_

#include "types.h"

/* Carry-out of the 32-bit add x + y (1 when the sum wraps past UINT32_MAX). */
static inline u32 addCarryOut32(u32 x, u32 y) {
    return (u32)(x + y) < x;
}

#endif /* UTIL_CARRY_H_ */
