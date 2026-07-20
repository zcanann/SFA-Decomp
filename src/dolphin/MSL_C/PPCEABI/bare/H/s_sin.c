#include "dolphin.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/s_tan.h"

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
extern double lbl_803E7DB0;
extern double lbl_803E7DB8;
extern double lbl_803E7DC0;
extern double lbl_803E7DC8;
extern double lbl_803E7DD0;
extern double lbl_803E7DD8;
extern double lbl_803E7DE0;
extern double lbl_803E7DE8;
extern double lbl_803E7DF0;
extern double lbl_803E7DF8;
extern double lbl_803E7E00;
extern double lbl_803E7E08;
extern double lbl_803E7E10;

float mathCosf(float angle) {
    u16 quadrant;
    float reducedAngle = trigReduceQuadrant(&quadrant, angle);
    float reducedSquared = reducedAngle * reducedAngle;

    switch (quadrant & 6) {
        case 0:
            return ((lbl_803E7D8C * reducedSquared + lbl_803E7D88) * reducedSquared + lbl_803E7D84) * reducedSquared + lbl_803E7D80;
        case 2:
            return -(reducedAngle * ((lbl_803E7D7C * reducedSquared + lbl_803E7D78) * reducedSquared + lbl_803E7D74));
        case 4:
            return -(reducedSquared * ((lbl_803E7D8C * reducedSquared + lbl_803E7D88) * reducedSquared + lbl_803E7D84) + lbl_803E7D80);
        default:
            return reducedAngle * ((lbl_803E7D7C * reducedSquared + lbl_803E7D78) * reducedSquared + lbl_803E7D74);
    }
}

float fn_802942EC(float angle) {
    u16 quadrant;
    float reducedAngle = trigReduceQuadrant(&quadrant, angle);
    float reducedSquared = reducedAngle * reducedAngle;

    switch (quadrant & 6) {
        case 0:
            return (((lbl_803E7DAC * reducedSquared + lbl_803E7DA8) * reducedSquared + lbl_803E7DA4) * reducedSquared + lbl_803E7DA0) * reducedSquared
                   + lbl_803E7D80;
        case 2:
            return -(reducedAngle * (((lbl_803E7D9C * reducedSquared + lbl_803E7D98) * reducedSquared + lbl_803E7D94) * reducedSquared + lbl_803E7D90));
        case 4:
            return -(reducedSquared * (((lbl_803E7DAC * reducedSquared + lbl_803E7DA8) * reducedSquared + lbl_803E7DA4) * reducedSquared + lbl_803E7DA0)
                     + lbl_803E7D80);
        default:
            return reducedAngle * (((lbl_803E7D9C * reducedSquared + lbl_803E7D98) * reducedSquared + lbl_803E7D94) * reducedSquared + lbl_803E7D90);
    }
}

float mathCosfHighPrecision(float angle) {
    int quadrant;
    double reducedAngle = tan(&quadrant, angle);
    double reducedSquared = reducedAngle * reducedAngle;

    switch (quadrant & 6) {
        case 0:
            return (float)((((((lbl_803E7E10 * reducedSquared + lbl_803E7E08) * reducedSquared + lbl_803E7E00) * reducedSquared + lbl_803E7DF8) * reducedSquared
                              + lbl_803E7DF0)
                                 * reducedSquared
                             + lbl_803E7DE8)
                                * reducedSquared
                            + lbl_803E7DE0);
        case 2:
            return (float)(-(reducedAngle * (((((lbl_803E7DD8 * reducedSquared + lbl_803E7DD0) * reducedSquared + lbl_803E7DC8) * reducedSquared
                                    + lbl_803E7DC0)
                                       * reducedSquared
                                   + lbl_803E7DB8)
                                      * reducedSquared
                                  + lbl_803E7DB0)));
        case 4:
            return (float)(-(reducedSquared
                                 * (((((lbl_803E7E10 * reducedSquared + lbl_803E7E08) * reducedSquared + lbl_803E7E00) * reducedSquared
                                      + lbl_803E7DF8)
                                         * reducedSquared
                                     + lbl_803E7DF0)
                                        * reducedSquared
                                    + lbl_803E7DE8)
                             + lbl_803E7DE0));
        default:
            return (float)(reducedAngle * (((((lbl_803E7DD8 * reducedSquared + lbl_803E7DD0) * reducedSquared + lbl_803E7DC8) * reducedSquared
                                  + lbl_803E7DC0)
                                     * reducedSquared
                                 + lbl_803E7DB8)
                                    * reducedSquared
                                + lbl_803E7DB0));
    }
}
