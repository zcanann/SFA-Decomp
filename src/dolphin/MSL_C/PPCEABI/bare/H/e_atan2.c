#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/k_tan.h"

typedef struct Vec3f {
    float x;
    float y;
    float z;
} Vec3f;


extern float fastCastS16ToFloat(s16* p);
extern float lbl_803E7AB8;
extern float lbl_803E7BC8;
extern float lbl_803E7BF4;
extern float lbl_803E7BF8;

void Vec_scale(void* v_in, void* v_out, float s);
float Vec_lengthSquared(void* v);
void fastCastFloatToU16(float x, u16* p);
float fastCastU16ToFloat(u16* p);

#pragma optimization_level 0
#pragma optimize_for_size on
float powfBitEstimate(float x, float y) {
    u32 x_bits;
    float result;
    float frac;
    s16 exponent;
    float expFloat;
    int y_int;

    if (x != lbl_803E7AB8) {
        x_bits = *(u32 *)&x;
        exponent = (s16)(((x_bits >> 23) & 0xFF) - 128);
        *(u32 *)&frac = (x_bits & 0x7FFFFF) | 0x3F800000;
        expFloat = fastCastS16ToFloat(&exponent);
        frac = (lbl_803E7BF4 * y) * (frac + expFloat);
        *(u32 *)&result = (u32)(int)frac + 0x3F800000;

        if (x_bits & 0x80000000) {
            y_int = y;
            if (y_int & 1) {
                *(u32 *)&result ^= 0x80000000;
            }
        }

        return result;
    }

    if (y != lbl_803E7AB8) {
        return lbl_803E7AB8;
    }

    return lbl_803E7BC8;
}
#pragma optimize_for_size reset
#pragma optimization_level reset

#pragma optimization_level 0
#pragma peephole off
void Vec_normalize(void* v_in, void* v_out) {
    Vec_scale(v_in, v_out, invSqrt(Vec_lengthSquared(v_in)));
}
#pragma optimization_level reset

#pragma peephole on
void Vec_scale(void* v_in, void* v_out, float s) {
    Vec3f* in = v_in;
    Vec3f* out = v_out;
    out->x = in->x * s;
    out->y = in->y * s;
    out->z = in->z * s;
}

float Vec_lengthSquared(void* v) {
    volatile Vec3f* vec = v;
    return vec->z * vec->z + (vec->x * vec->x + vec->y * vec->y);
}

#pragma optimization_level 0
#pragma optimize_for_size on
#pragma peephole off
float trigReduceQuadrant(u16* p, float x) {
    float scaled = lbl_803E7BF8 * __fabsf(x);
    float reduced;
    fastCastFloatToU16(scaled, p);
    *p = (*p + 1) & 0xFFFE;
    reduced = fastCastU16ToFloat(p);
    return scaled - reduced;
}
#pragma optimize_for_size reset
#pragma optimization_level reset
