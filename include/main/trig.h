#ifndef MAIN_TRIG_H_
#define MAIN_TRIG_H_

#include "types.h"

/* One full turn is 65536 units; only the low 16 angle bits are used. */
float fsin16Approx(u16 angle);
float fcos16Approx(u16 angle);
float fsin16Precise(int angle);
float fcos16Precise(int angle);
float fsin16HighPrecision(int angle);
float fcos16HighPrecision(int angle);
float fsin16(int angle);
float fcos16(int angle);
float mathSinfFast(float x);

#endif /* MAIN_TRIG_H_ */
