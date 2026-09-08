#include "main/reciprocal.h"

float fastReciprocal(float value) {
    float reciprocal;

    reciprocal = __fres(value);
    reciprocal *= 2.0f - value * reciprocal;
    reciprocal *= 2.0f - value * reciprocal;

    return reciprocal;
}
