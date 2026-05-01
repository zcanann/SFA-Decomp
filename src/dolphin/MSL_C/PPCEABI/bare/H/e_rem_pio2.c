#include "dolphin.h"

extern float lbl_803E7C94;
extern float lbl_803E7C98;
extern float lbl_803E7C9C;
extern float lbl_803E7CA0;
extern float lbl_803E7CA4;
extern float lbl_803E7CA8;
extern float lbl_803E7CAC;
extern float lbl_803E7CB0;
extern float lbl_803E7CB4;
extern float lbl_803E7CB8;
extern float lbl_803E7CBC;
extern float lbl_803E7CC0;
extern float lbl_803E7CC4;
extern float lbl_803E7CC8;
extern float lbl_803E7CCC;

float fn_80291E08(s16* p);

float __ieee754_rem_pio2(int angle) {
    s16 reduced = angle << 2;
    float y = fn_80291E08(&reduced);
    float y2 = y * y;

    switch (angle & 0xE000) {
        case 0x0000:
        case 0xE000:
            return y * (((lbl_803E7CBC * y2 + lbl_803E7CB8) * y2 + lbl_803E7CB4) * y2 + lbl_803E7CB0);
        case 0x2000:
        case 0x4000:
            return (((lbl_803E7CCC * y2 + lbl_803E7CC8) * y2 + lbl_803E7CC4) * y2 + lbl_803E7CC0) * y2
                   + lbl_803E7CA0;
        case 0x6000:
        case 0x8000:
            return -(y * (((lbl_803E7CBC * y2 + lbl_803E7CB8) * y2 + lbl_803E7CB4) * y2 + lbl_803E7CB0));
        default:
            return lbl_803E7CA0
                   - y2 * (((lbl_803E7CCC * y2 + lbl_803E7CC8) * y2 + lbl_803E7CC4) * y2 + lbl_803E7CC0);
    }
}

float fn_80293D0C(int angle) {
    (void)angle;
    return 0.0f;
}

float fn_80293EAC(int angle) {
    (void)angle;
    return 0.0f;
}

float fn_80293854(int angle) {
    s16 reduced = angle << 2;
    float y = fn_80291E08(&reduced);
    float y2 = y * y;

    switch (angle & 0xE000) {
        case 0x0000:
        case 0xE000:
            return ((lbl_803E7CAC * y2 + lbl_803E7CA8) * y2 + lbl_803E7CA4) * y2 + lbl_803E7CA0;
        case 0x2000:
        case 0x4000:
            return -(y * ((lbl_803E7C9C * y2 + lbl_803E7C98) * y2 + lbl_803E7C94));
        case 0x6000:
        case 0x8000:
            return lbl_803E7CA0 - y2 * ((lbl_803E7CAC * y2 + lbl_803E7CA8) * y2 + lbl_803E7CA4);
        default:
            return y * ((lbl_803E7C9C * y2 + lbl_803E7C98) * y2 + lbl_803E7C94);
    }
}

float fn_8029397C(int angle) {
    (void)angle;
    return 0.0f;
}

float fn_80293AC4(int angle) {
    (void)angle;
    return 0.0f;
}

void fn_80293C64(float x, float* sin_out, float* cos_out) {
    (void)x;
    *sin_out = 0.0f;
    *cos_out = 1.0f;
}

float fn_80293DA4(float x) {
    return x;
}

float fn_80293E80(float x) {
    return x;
}

float fn_80293F7C(float x) {
    return x;
}
