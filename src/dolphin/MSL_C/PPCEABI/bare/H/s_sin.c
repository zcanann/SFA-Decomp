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

float mathCosf(float x) {
    u16 n;
    float y = trigReduceQuadrant(&n, x);
    float y2 = y * y;

    switch (n & 6) {
        case 0:
            return ((lbl_803E7D8C * y2 + lbl_803E7D88) * y2 + lbl_803E7D84) * y2 + lbl_803E7D80;
        case 2:
            return -(y * ((lbl_803E7D7C * y2 + lbl_803E7D78) * y2 + lbl_803E7D74));
        case 4:
            return -(y2 * ((lbl_803E7D8C * y2 + lbl_803E7D88) * y2 + lbl_803E7D84) + lbl_803E7D80);
        default:
            return y * ((lbl_803E7D7C * y2 + lbl_803E7D78) * y2 + lbl_803E7D74);
    }
}

float fn_802942EC(float x) {
    u16 n;
    float y = trigReduceQuadrant(&n, x);
    float y2 = y * y;

    switch (n & 6) {
        case 0:
            return (((lbl_803E7DAC * y2 + lbl_803E7DA8) * y2 + lbl_803E7DA4) * y2 + lbl_803E7DA0) * y2
                   + lbl_803E7D80;
        case 2:
            return -(y * (((lbl_803E7D9C * y2 + lbl_803E7D98) * y2 + lbl_803E7D94) * y2 + lbl_803E7D90));
        case 4:
            return -(y2 * (((lbl_803E7DAC * y2 + lbl_803E7DA8) * y2 + lbl_803E7DA4) * y2 + lbl_803E7DA0)
                     + lbl_803E7D80);
        default:
            return y * (((lbl_803E7D9C * y2 + lbl_803E7D98) * y2 + lbl_803E7D94) * y2 + lbl_803E7D90);
    }
}

float mathCosfHighPrecision(float x) {
    int n;
    double y = tan(&n, x);
    double y2 = y * y;

    switch (n & 6) {
        case 0:
            return (float)((((((lbl_803E7E10 * y2 + lbl_803E7E08) * y2 + lbl_803E7E00) * y2 + lbl_803E7DF8) * y2
                              + lbl_803E7DF0)
                                 * y2
                             + lbl_803E7DE8)
                                * y2
                            + lbl_803E7DE0);
        case 2:
            return (float)(-(y * (((((lbl_803E7DD8 * y2 + lbl_803E7DD0) * y2 + lbl_803E7DC8) * y2
                                    + lbl_803E7DC0)
                                       * y2
                                   + lbl_803E7DB8)
                                      * y2
                                  + lbl_803E7DB0)));
        case 4:
            return (float)(-(y2
                                 * (((((lbl_803E7E10 * y2 + lbl_803E7E08) * y2 + lbl_803E7E00) * y2
                                      + lbl_803E7DF8)
                                         * y2
                                     + lbl_803E7DF0)
                                        * y2
                                    + lbl_803E7DE8)
                             + lbl_803E7DE0));
        default:
            return (float)(y * (((((lbl_803E7DD8 * y2 + lbl_803E7DD0) * y2 + lbl_803E7DC8) * y2
                                  + lbl_803E7DC0)
                                     * y2
                                 + lbl_803E7DB8)
                                    * y2
                                + lbl_803E7DB0));
    }
}
