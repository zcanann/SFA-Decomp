#include "dolphin.h"

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
extern float lbl_803E7E18;
extern float lbl_803E7E1C;
extern float lbl_803E7E20;
extern float lbl_803E7E24;
extern float lbl_803E7E28;
extern float lbl_803E7E2C;

float fastCastS16ToFloat(s16* p);
float fn_80292CC4(u16* p, float x);
double tan(int* out_n, float x);

float sin(float x) {
    u16 n;
    float y = fn_80292CC4(&n, x);
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
    float y = fn_80292CC4(&n, x);
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

float fn_802943F4(float x) {
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

float fn_8029454C(float x) {
    u16 n;
    float y = fn_80292CC4(&n, x);
    float y2 = y * y;
    float result = y * (((lbl_803E7E2C * y2 + lbl_803E7E28) * y2 + lbl_803E7E24) * y2 + lbl_803E7E20);

    if (n & 2) {
        result = lbl_803E7E18 / result;
    }

    if (x >= lbl_803E7E1C) {
        return result;
    }
    return -result;
}

float fn_802945E0(float x) {
    u32 bits;
    float mantissa;
    float tail;
    s16 exponent;

    bits = *(u32*)&x;
    exponent = (s16)(((bits >> 23) & 0xFF) - 128);
    *(u32*)&mantissa = (bits & 0x7FFFFF) | 0x3F800000;

    tail = fastCastS16ToFloat(&exponent);
    return mantissa + tail;
}
