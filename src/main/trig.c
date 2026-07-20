#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "main/fcos16_approx_api.h"
#include "main/trig.h"

extern float lbl_803E7C80;
extern float lbl_803E7C84;
extern float lbl_803E7C88;
extern float lbl_803E7C8C;
extern float lbl_803E7C90;
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
extern double lbl_803E7CD0;
extern double lbl_803E7CD8;
extern double lbl_803E7CE0;
extern double lbl_803E7CE8;
extern double lbl_803E7CF0;
extern double lbl_803E7CF8;
extern double lbl_803E7D00;
extern double lbl_803E7D08;
extern double lbl_803E7D10;
extern double lbl_803E7D18;
extern double lbl_803E7D20;
extern double lbl_803E7D28;
extern double lbl_803E7D30;
extern double lbl_803E7D38;
extern float lbl_803E7D40;
extern float lbl_803E7D44;
extern float lbl_803E7D48;
extern float lbl_803E7D4C;
extern float lbl_803E7D50;
extern float lbl_803E7D54;
extern float lbl_803E7D58;
extern float lbl_803E7D5C;

float fsin16Approx(int angle) {
    s16 reduced = (s16)(int)((angle << 2) & 0x3FFFC);
    float x = fastCastS16ToFloat(&reduced);
    float x2 = x * x;

    switch (angle & 0xE000) {
        case 0x0000:
        case 0xE000:
            return x * (lbl_803E7C90 * x2 + lbl_803E7C8C);
        case 0x2000:
        case 0x4000:
            return (lbl_803E7C88 * x2 + lbl_803E7C84) * x2 + lbl_803E7C80;
        case 0x6000:
        case 0x8000:
            return -(x * (lbl_803E7C90 * x2 + lbl_803E7C8C));
        default:
            return -(x2 * (lbl_803E7C88 * x2 + lbl_803E7C84) + lbl_803E7C80);
    }
}

float fcos16(int angle) {
    s16 reduced = (s16)(int)((angle << 2) & 0x3FFFC);
    float x = fastCastS16ToFloat(&reduced);
    float x2 = x * x;

    switch (angle & 0xE000) {
        case 0x0000:
        case 0xE000:
            return x * ((lbl_803E7C9C * x2 + lbl_803E7C98) * x2 + lbl_803E7C94);
        case 0x2000:
        case 0x4000:
            return (((lbl_803E7CAC * x2 + lbl_803E7CA8) * x2 + lbl_803E7CA4) * x2 + lbl_803E7CA0);
        case 0x6000:
        case 0x8000:
            return -(x * ((lbl_803E7C9C * x2 + lbl_803E7C98) * x2 + lbl_803E7C94));
        default:
            return -(x2 * ((lbl_803E7CAC * x2 + lbl_803E7CA8) * x2 + lbl_803E7CA4) + lbl_803E7CA0);
    }
}

float fsin16Precise(int angle) {
    s16 reduced = (s16)(int)((angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&reduced);
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
            return -(y2 * (((lbl_803E7CCC * y2 + lbl_803E7CC8) * y2 + lbl_803E7CC4) * y2 + lbl_803E7CC0)
                     + lbl_803E7CA0);
    }
}

float fsin16HighPrecision(int angle) {
    s16 reduced = (s16)(int)((angle << 2) & 0x3FFFC);
    float reducedFloat = fastCastS16ToFloat(&reduced);
    double reducedAngle = lbl_803E7CD0 * reducedFloat;
    double reducedSquared = reducedAngle * reducedAngle;

    switch (angle & 0xE000) {
        case 0x0000:
        case 0xE000:
            return (float)(reducedAngle * (((((lbl_803E7D00 * reducedSquared + lbl_803E7CF8) * reducedSquared + lbl_803E7CF0) * reducedSquared
                                  + lbl_803E7CE8)
                                     * reducedSquared
                                 + lbl_803E7CE0)
                                    * reducedSquared
                                + lbl_803E7CD8));
        case 0x2000:
        case 0x4000:
            return (float)(((((((lbl_803E7D38 * reducedSquared + lbl_803E7D30) * reducedSquared + lbl_803E7D28) * reducedSquared + lbl_803E7D20)
                              * reducedSquared
                              + lbl_803E7D18)
                             * reducedSquared
                             + lbl_803E7D10)
                            * reducedSquared
                            + lbl_803E7D08));
        case 0x6000:
        case 0x8000:
            return (float)(-(reducedAngle * (((((lbl_803E7D00 * reducedSquared + lbl_803E7CF8) * reducedSquared + lbl_803E7CF0) * reducedSquared
                                    + lbl_803E7CE8)
                                       * reducedSquared
                                   + lbl_803E7CE0)
                                      * reducedSquared
                                  + lbl_803E7CD8)));
        default:
            return (float)(-(reducedSquared
                                 * (((((lbl_803E7D38 * reducedSquared + lbl_803E7D30) * reducedSquared + lbl_803E7D28) * reducedSquared
                                      + lbl_803E7D20)
                                         * reducedSquared
                                     + lbl_803E7D18)
                                        * reducedSquared
                                    + lbl_803E7D10)
                             + lbl_803E7D08));
    }
}

float fcos16Approx(int angle) {
    s16 reduced = (s16)(int)((angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&reduced);
    float y2 = y * y;

    switch (angle & 0xE000) {
        case 0x0000:
        case 0xE000:
            return (lbl_803E7C88 * y2 + lbl_803E7C84) * y2 + lbl_803E7C80;
        case 0x2000:
        case 0x4000:
            return -(y * (lbl_803E7C90 * y2 + lbl_803E7C8C));
        case 0x6000:
        case 0x8000:
            return -(y2 * (lbl_803E7C88 * y2 + lbl_803E7C84) + lbl_803E7C80);
        default:
            return y * (lbl_803E7C90 * y2 + lbl_803E7C8C);
    }
}

float fsin16(int angle) {
    s16 reduced = (s16)(int)((angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&reduced);
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
            return -(y2 * ((lbl_803E7CAC * y2 + lbl_803E7CA8) * y2 + lbl_803E7CA4) + lbl_803E7CA0);
        default:
            return y * ((lbl_803E7C9C * y2 + lbl_803E7C98) * y2 + lbl_803E7C94);
    }
}

float fcos16Precise(int angle) {
    s16 reduced = (s16)(int)((angle << 2) & 0x3FFFC);
    float y = fastCastS16ToFloat(&reduced);
    float y2 = y * y;

    switch (angle & 0xE000) {
        case 0x0000:
        case 0xE000:
            return (((lbl_803E7CCC * y2 + lbl_803E7CC8) * y2 + lbl_803E7CC4) * y2 + lbl_803E7CC0) * y2
                   + lbl_803E7CA0;
        case 0x2000:
        case 0x4000:
            return -(y * (((lbl_803E7CBC * y2 + lbl_803E7CB8) * y2 + lbl_803E7CB4) * y2 + lbl_803E7CB0));
        case 0x6000:
        case 0x8000:
            return -(y2 * (((lbl_803E7CCC * y2 + lbl_803E7CC8) * y2 + lbl_803E7CC4) * y2 + lbl_803E7CC0)
                     + lbl_803E7CA0);
        default:
            return y * (((lbl_803E7CBC * y2 + lbl_803E7CB8) * y2 + lbl_803E7CB4) * y2 + lbl_803E7CB0);
    }
}

float fcos16HighPrecision(int angle) {
    s16 reduced = (s16)(int)((angle << 2) & 0x3FFFC);
    float reducedFloat = fastCastS16ToFloat(&reduced);
    double reducedAngle = lbl_803E7CD0 * reducedFloat;
    double reducedSquared = reducedAngle * reducedAngle;

    switch (angle & 0xE000) {
        case 0x0000:
        case 0xE000:
            return (float)(((((((lbl_803E7D38 * reducedSquared + lbl_803E7D30) * reducedSquared + lbl_803E7D28) * reducedSquared + lbl_803E7D20)
                              * reducedSquared
                              + lbl_803E7D18)
                             * reducedSquared
                             + lbl_803E7D10)
                            * reducedSquared
                            + lbl_803E7D08));
        case 0x2000:
        case 0x4000:
            return (float)(-(reducedAngle * (((((lbl_803E7D00 * reducedSquared + lbl_803E7CF8) * reducedSquared + lbl_803E7CF0) * reducedSquared
                                    + lbl_803E7CE8)
                                       * reducedSquared
                                   + lbl_803E7CE0)
                                      * reducedSquared
                                  + lbl_803E7CD8)));
        case 0x6000:
        case 0x8000:
            return (float)(-(reducedSquared
                                 * (((((lbl_803E7D38 * reducedSquared + lbl_803E7D30) * reducedSquared + lbl_803E7D28) * reducedSquared
                                      + lbl_803E7D20)
                                         * reducedSquared
                                     + lbl_803E7D18)
                                        * reducedSquared
                                    + lbl_803E7D10)
                             + lbl_803E7D08));
        default:
            return (float)(reducedAngle * (((((lbl_803E7D00 * reducedSquared + lbl_803E7CF8) * reducedSquared + lbl_803E7CF0) * reducedSquared
                                  + lbl_803E7CE8)
                                     * reducedSquared
                                 + lbl_803E7CE0)
                                    * reducedSquared
                                + lbl_803E7CD8));
    }
}

void fn_80293C64(float x, float* outSin, float* outCos) {
    u16 quadrant;
    float reducedAngle = trigReduceQuadrant(&quadrant, x);
    float reducedSquared = reducedAngle * reducedAngle;
    float sinApprox = reducedAngle * ((lbl_803E7D4C * reducedSquared + lbl_803E7D48) * reducedSquared + lbl_803E7D44);
    float cosApprox = ((lbl_803E7D5C * reducedSquared + lbl_803E7D58) * reducedSquared + lbl_803E7D54) * reducedSquared + lbl_803E7D50;

    switch (quadrant & 6) {
        case 0:
            sinApprox = (x >= lbl_803E7D40) ? sinApprox : -sinApprox;
            *outSin = sinApprox;
            *outCos = cosApprox;
            break;
        case 2:
            cosApprox = (x >= lbl_803E7D40) ? cosApprox : -cosApprox;
            *outSin = cosApprox;
            *outCos = -sinApprox;
            break;
        case 4:
            if (x >= lbl_803E7D40) {
                sinApprox = -sinApprox;
            }
            *outSin = sinApprox;
            *outCos = -cosApprox;
            break;
        default:
            if (x >= lbl_803E7D40) {
                cosApprox = -cosApprox;
            }
            *outSin = cosApprox;
            *outCos = sinApprox;
            break;
    }
}
