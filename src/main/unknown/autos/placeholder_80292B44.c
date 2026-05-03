#include "dolphin.h"

typedef struct Vec3f {
    float x;
    float y;
    float z;
} Vec3f;

extern float invSqrt(float x);
extern float fn_80291E08(s16* p);
extern float lbl_803E7AB8;
extern float lbl_803E7BC8;
extern float lbl_803E7BF4;
extern float lbl_803E7BF8;

void fn_80292C74(void* v_in, void* v_out, float s);
float fn_80292C9C(void* v);
void fn_80291CE4(u16* p, float x);
float fn_80291CC8(u16* p);

float fn_80292B44(float x, float y) {
    union {
        float f;
        u32 u;
    } bits;
    s16 exponent;
    u32 x_bits;
    int y_int;

    if (x != lbl_803E7AB8) {
        bits.f = x;
        x_bits = bits.u;
        exponent = (s16)(((x_bits >> 23) & 0xFF) - 128);
        bits.u = (x_bits & 0x7FFFFF) | 0x3F800000;
        bits.f = (lbl_803E7BF4 * y) * (bits.f + fn_80291E08(&exponent));

        y_int = (int)bits.f;
        bits.u = (u32)y_int + 0x3F800000;

        if ((x_bits & 0x80000000) && ((int)y & 1)) {
            bits.u ^= 0x80000000;
        }

        return bits.f;
    }

    if (y != lbl_803E7AB8) {
        return lbl_803E7AB8;
    }

    return lbl_803E7BC8;
}

void fn_80292C30(void* v_in, void* v_out) {
    float scale = invSqrt(fn_80292C9C(v_in));
    fn_80292C74(v_in, v_out, scale);
}

void fn_80292C74(void* v_in, void* v_out, float s) {
    Vec3f* in = v_in;
    Vec3f* out = v_out;
    out->x = in->x * s;
    out->y = in->y * s;
    out->z = in->z * s;
}

float fn_80292C9C(void* v) {
    Vec3f* vec = v;
    return vec->z * vec->z + (vec->x * vec->x + vec->y * vec->y);
}

float fn_80292CC4(u16* p, float x) {
    float scaled = lbl_803E7BF8 * __fabsf(x);
    fn_80291CE4(p, scaled);
    *p = (*p + 1) & 0xFFFE;
    return scaled - fn_80291CC8(p);
}
