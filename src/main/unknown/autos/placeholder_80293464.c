#include "dolphin.h"

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

float fastCastS16ToFloat(s16* p);
float fn_80292CC4(u16* p, float x);

float __ieee754_rem_pio2(int angle) {
    s16 reduced = (u16)angle << 2;
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
            return lbl_803E7CA0
                   - y2 * (((lbl_803E7CCC * y2 + lbl_803E7CC8) * y2 + lbl_803E7CC4) * y2 + lbl_803E7CC0);
    }
}

float fn_80293D0C(int angle) {
    s16 reduced = (u16)angle << 2;
    double y = lbl_803E7CD0 * fastCastS16ToFloat(&reduced);
    double y2 = y * y;

    switch (angle & 0xE000) {
        case 0x0000:
        case 0xE000:
            return (float)(y * (((((lbl_803E7D00 * y2 + lbl_803E7CF8) * y2 + lbl_803E7CF0) * y2
                                  + lbl_803E7CE8)
                                     * y2
                                 + lbl_803E7CE0)
                                    * y2
                                + lbl_803E7CD8));
        case 0x2000:
        case 0x4000:
            return (float)(((((((lbl_803E7D38 * y2 + lbl_803E7D30) * y2 + lbl_803E7D28) * y2 + lbl_803E7D20)
                              * y2
                              + lbl_803E7D18)
                             * y2
                             + lbl_803E7D10)
                            * y2
                            + lbl_803E7D08));
        case 0x6000:
        case 0x8000:
            return (float)(-(y * (((((lbl_803E7D00 * y2 + lbl_803E7CF8) * y2 + lbl_803E7CF0) * y2
                                    + lbl_803E7CE8)
                                       * y2
                                   + lbl_803E7CE0)
                                      * y2
                                  + lbl_803E7CD8)));
        default:
            return (float)(lbl_803E7D08
                           - y2
                                 * (((((lbl_803E7D38 * y2 + lbl_803E7D30) * y2 + lbl_803E7D28) * y2
                                      + lbl_803E7D20)
                                         * y2
                                     + lbl_803E7D18)
                                        * y2
                                    + lbl_803E7D10));
    }
}

float fn_80293EAC(int angle) {
    s16 reduced = (u16)angle << 2;
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
            return lbl_803E7C80 - y2 * (lbl_803E7C88 * y2 + lbl_803E7C84);
        default:
            return y * (lbl_803E7C90 * y2 + lbl_803E7C8C);
    }
}

float fsin16(int angle) {
    s16 reduced = (u16)angle << 2;
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
            return lbl_803E7CA0 - y2 * ((lbl_803E7CAC * y2 + lbl_803E7CA8) * y2 + lbl_803E7CA4);
        default:
            return y * ((lbl_803E7C9C * y2 + lbl_803E7C98) * y2 + lbl_803E7C94);
    }
}

float fn_8029397C(int angle) {
    s16 reduced = (u16)angle << 2;
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
            return lbl_803E7CA0
                   - y2 * (((lbl_803E7CCC * y2 + lbl_803E7CC8) * y2 + lbl_803E7CC4) * y2 + lbl_803E7CC0);
        default:
            return y * (((lbl_803E7CBC * y2 + lbl_803E7CB8) * y2 + lbl_803E7CB4) * y2 + lbl_803E7CB0);
    }
}

float fn_80293AC4(int angle) {
    s16 reduced = (u16)angle << 2;
    double y = lbl_803E7CD0 * fastCastS16ToFloat(&reduced);
    double y2 = y * y;

    switch (angle & 0xE000) {
        case 0x0000:
        case 0xE000:
            return (float)(((((((lbl_803E7D38 * y2 + lbl_803E7D30) * y2 + lbl_803E7D28) * y2 + lbl_803E7D20)
                              * y2
                              + lbl_803E7D18)
                             * y2
                             + lbl_803E7D10)
                            * y2
                            + lbl_803E7D08));
        case 0x2000:
        case 0x4000:
            return (float)(-(y * (((((lbl_803E7D00 * y2 + lbl_803E7CF8) * y2 + lbl_803E7CF0) * y2
                                    + lbl_803E7CE8)
                                       * y2
                                   + lbl_803E7CE0)
                                      * y2
                                  + lbl_803E7CD8)));
        case 0x6000:
        case 0x8000:
            return (float)(lbl_803E7D08
                           - y2
                                 * (((((lbl_803E7D38 * y2 + lbl_803E7D30) * y2 + lbl_803E7D28) * y2
                                      + lbl_803E7D20)
                                         * y2
                                     + lbl_803E7D18)
                                        * y2
                                    + lbl_803E7D10));
        default:
            return (float)(y * (((((lbl_803E7D00 * y2 + lbl_803E7CF8) * y2 + lbl_803E7CF0) * y2
                                  + lbl_803E7CE8)
                                     * y2
                                 + lbl_803E7CE0)
                                    * y2
                                + lbl_803E7CD8));
    }
}

void fn_80293C64(float x, float* sin_out, float* cos_out) {
    u16 n;
    float y = fn_80292CC4(&n, x);
    float y2 = y * y;
    float sin_y = y * ((lbl_803E7D4C * y2 + lbl_803E7D48) * y2 + lbl_803E7D44);
    float cos_y = ((lbl_803E7D5C * y2 + lbl_803E7D58) * y2 + lbl_803E7D54) * y2 + lbl_803E7D50;

    switch (n & 6) {
        case 0:
            if (x < lbl_803E7D40) {
                sin_y = -sin_y;
            }
            *sin_out = sin_y;
            *cos_out = cos_y;
            break;
        case 2:
            if (x < lbl_803E7D40) {
                cos_y = -cos_y;
            }
            *sin_out = cos_y;
            *cos_out = -sin_y;
            break;
        case 4:
            if (x >= lbl_803E7D40) {
                sin_y = -sin_y;
            }
            *sin_out = sin_y;
            *cos_out = -cos_y;
            break;
        default:
            if (x >= lbl_803E7D40) {
                cos_y = -cos_y;
            }
            *sin_out = cos_y;
            *cos_out = sin_y;
            break;
    }
}

float fn_80293DA4(float x) {
    union {
        float f;
        u32 u;
    } bits;
    u16 n;
    float y;
    float y2;

    bits.f = x;
    y = fn_80292CC4(&n, bits.f);
    n += (bits.u >> 29) & 4;
    y2 = y * y;

    switch (n & 6) {
        case 0:
            return y * (lbl_803E7D64 * y2 + lbl_803E7D60);
        case 2:
            return (lbl_803E7D70 * y2 + lbl_803E7D6C) * y2 + lbl_803E7D68;
        case 4:
            return -(y * (lbl_803E7D64 * y2 + lbl_803E7D60));
        default:
            return lbl_803E7D68 - y2 * (lbl_803E7D70 * y2 + lbl_803E7D6C);
    }
}

float fn_80293E80(float x) {
    union {
        float f;
        u32 u;
    } bits;
    u16 n;
    float y;
    float y2;

    bits.f = x;
    y = fn_80292CC4(&n, bits.f);
    n += (bits.u >> 29) & 4;
    y2 = y * y;

    switch (n & 6) {
        case 0:
            return y * ((lbl_803E7D7C * y2 + lbl_803E7D78) * y2 + lbl_803E7D74);
        case 2:
            return ((lbl_803E7D8C * y2 + lbl_803E7D88) * y2 + lbl_803E7D84) * y2 + lbl_803E7D80;
        case 4:
            return -(y * ((lbl_803E7D7C * y2 + lbl_803E7D78) * y2 + lbl_803E7D74));
        default:
            return lbl_803E7D80 - y2 * ((lbl_803E7D8C * y2 + lbl_803E7D88) * y2 + lbl_803E7D84);
    }
}

float fn_80293F7C(float x) {
    union {
        float f;
        u32 u;
    } bits;
    u16 n;
    float y;
    float y2;

    bits.f = x;
    y = fn_80292CC4(&n, bits.f);
    n += (bits.u >> 29) & 4;
    y2 = y * y;

    switch (n & 6) {
        case 0:
            return y * (((lbl_803E7D9C * y2 + lbl_803E7D98) * y2 + lbl_803E7D94) * y2 + lbl_803E7D90);
        case 2:
            return (((lbl_803E7DAC * y2 + lbl_803E7DA8) * y2 + lbl_803E7DA4) * y2 + lbl_803E7DA0) * y2
                   + lbl_803E7D80;
        case 4:
            return -(y * (((lbl_803E7D9C * y2 + lbl_803E7D98) * y2 + lbl_803E7D94) * y2 + lbl_803E7D90));
        default:
            return lbl_803E7D80
                   - y2 * (((lbl_803E7DAC * y2 + lbl_803E7DA8) * y2 + lbl_803E7DA4) * y2 + lbl_803E7DA0);
    }
}
