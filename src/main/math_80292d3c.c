#include "main/math_80292d3c.h"

double trigReduceQuadrantHighPrecision(int* quadrant, float angle) {
    double absoluteAngle = __fabsf(angle);
    double scaledAngle = 1.2732395447351628 * absoluteAngle;
    unsigned int roundedQuadrant = __cvt_fp2unsigned(scaledAngle) + 1 & ~1U;
    *quadrant = roundedQuadrant;
    return absoluteAngle - 0.7853981633974483 * (double)roundedQuadrant;
}
