#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/trig.h"

extern float lbl_803E7D60;
extern float lbl_803E7D64;
extern float lbl_803E7D68;
extern float lbl_803E7D6C;
extern float lbl_803E7D70;
extern float lbl_803E7D74;
extern float lbl_803E7D78;
extern float lbl_803E7D7C;
extern float lbl_803E7D80;
extern float lbl_803E7D84;
extern float lbl_803E7D88;
extern float lbl_803E7D8C;
extern float lbl_803E7D90;
extern float lbl_803E7D94;
extern float lbl_803E7D98;
extern float lbl_803E7D9C;
extern float lbl_803E7DA0;
extern float lbl_803E7DA4;
extern float lbl_803E7DA8;
extern float lbl_803E7DAC;

float fn_80293DA4(float angle) {
    u16 quadrant;
    float reducedAngle;
    float reducedSquared;

    reducedAngle = trigReduceQuadrant(&quadrant, angle);
    quadrant += (*(u32*)&angle & 0x80000000) >> 29;
    reducedSquared = reducedAngle * reducedAngle;

    switch (quadrant & 6) {
        case 0:
            return reducedAngle * (lbl_803E7D64 * reducedSquared + lbl_803E7D60);
        case 2:
            return (lbl_803E7D70 * reducedSquared + lbl_803E7D6C) * reducedSquared + lbl_803E7D68;
        case 4:
            return -(reducedAngle * (lbl_803E7D64 * reducedSquared + lbl_803E7D60));
        default:
            return -(reducedSquared * (lbl_803E7D70 * reducedSquared + lbl_803E7D6C) + lbl_803E7D68);
    }
}

float mathSinf(float angle) {
    u16 quadrant;
    float reducedAngle;
    float reducedSquared;

    reducedAngle = trigReduceQuadrant(&quadrant, angle);
    quadrant += (*(u32*)&angle & 0x80000000) >> 29;
    reducedSquared = reducedAngle * reducedAngle;

    switch (quadrant & 6) {
        case 0:
            return reducedAngle * ((lbl_803E7D7C * reducedSquared + lbl_803E7D78) * reducedSquared + lbl_803E7D74);
        case 2:
            return ((lbl_803E7D8C * reducedSquared + lbl_803E7D88) * reducedSquared + lbl_803E7D84) * reducedSquared + lbl_803E7D80;
        case 4:
            return -(reducedAngle * ((lbl_803E7D7C * reducedSquared + lbl_803E7D78) * reducedSquared + lbl_803E7D74));
        default:
            return -(reducedSquared * ((lbl_803E7D8C * reducedSquared + lbl_803E7D88) * reducedSquared + lbl_803E7D84) + lbl_803E7D80);
    }
}

float fn_80293F7C(float angle) {
    u16 quadrant;
    float reducedAngle;
    float reducedSquared;

    reducedAngle = trigReduceQuadrant(&quadrant, angle);
    quadrant += (*(u32*)&angle & 0x80000000) >> 29;
    reducedSquared = reducedAngle * reducedAngle;

    switch (quadrant & 6) {
        case 0:
            return reducedAngle * (((lbl_803E7D9C * reducedSquared + lbl_803E7D98) * reducedSquared + lbl_803E7D94) * reducedSquared + lbl_803E7D90);
        case 2:
            return (((lbl_803E7DAC * reducedSquared + lbl_803E7DA8) * reducedSquared + lbl_803E7DA4) * reducedSquared + lbl_803E7DA0) * reducedSquared
                   + lbl_803E7D80;
        case 4:
            return -(reducedAngle * (((lbl_803E7D9C * reducedSquared + lbl_803E7D98) * reducedSquared + lbl_803E7D94) * reducedSquared + lbl_803E7D90));
        default:
            return -(reducedSquared * (((lbl_803E7DAC * reducedSquared + lbl_803E7DA8) * reducedSquared + lbl_803E7DA4) * reducedSquared + lbl_803E7DA0)
                     + lbl_803E7D80);
    }
}
