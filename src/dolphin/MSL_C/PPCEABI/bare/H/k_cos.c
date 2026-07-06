typedef unsigned int u32;

extern float lbl_803E79C8;
extern float lbl_803E79E8;
extern double lbl_803E79E0;
extern double lbl_803E7A00;
extern float lbl_803E7A08;
extern float lbl_803E7A0C;
extern float lbl_803E7A1C;
extern float lbl_803E7A20;
extern float lbl_803E7A24;
extern float lbl_803E7A28;
extern double lbl_803E7A30;
extern double lbl_803E7A38;
extern double lbl_803E7A40;
extern double lbl_803E7A48;
extern double lbl_803E7A50;
extern double lbl_803E7A58;
extern double lbl_803E7A60;
extern double lbl_803E7A68;
extern double lbl_803E7A70;
extern double lbl_803E7A78;
extern double lbl_803E7A80;
extern double lbl_803E7A88;
extern double lbl_803E7A90;
extern double lbl_803E7A98;
extern double lbl_803E7AA0;
extern double lbl_803E7AA8;

#pragma peephole on
float __kernel_cos(float y, float x) {
    float ax = __fabsf(x);
    float ay = __fabsf(y);
    float r;
    float r2;
    float value;
    int quadrant;

    if (ax > ay) {
        r = ay / ax;
        r2 = r * r;
        value = r * (lbl_803E7A0C * r2 + lbl_803E7A08);
    } else {
        r = ax / ay;
        r2 = r * r;
        value = lbl_803E79C8 - r * (lbl_803E7A0C * r2 + lbl_803E7A08);
    }

    quadrant = (*(u32 *)&y & 0x80000000) | ((*(u32 *)&x >> 1) & 0x40000000);
    switch (quadrant) {
        case 0x00000000:
            return value;
        case 0x80000000:
            return -value;
        case 0x40000000:
            return lbl_803E79E8 - value;
        default:
            return value - lbl_803E79E8;
    }
}

float fn_802924B4(float y, float x) {
    float ax = __fabsf(x);
    float ay = __fabsf(y);
    float r;
    float r2;
    float value;
    int quadrant;

    if (ax > ay) {
        r = ay / ax;
        r2 = r * r;
        value = r * (((lbl_803E7A28 * r2 + lbl_803E7A24) * r2 + lbl_803E7A20) * r2 + lbl_803E7A1C);
    } else {
        r = ax / ay;
        r2 = r * r;
        value = lbl_803E79C8 - r * (((lbl_803E7A28 * r2 + lbl_803E7A24) * r2 + lbl_803E7A20) * r2 + lbl_803E7A1C);
    }

    quadrant = (*(u32 *)&y & 0x80000000) | ((*(u32 *)&x >> 1) & 0x40000000);
    switch (quadrant) {
        case 0x00000000:
            return value;
        case 0x80000000:
            return -value;
        case 0x40000000:
            return lbl_803E79E8 - value;
        default:
            return value - lbl_803E79E8;
    }
}

float fn_802925C4(float y, float x) {
    float ax = __fabsf(x);
    float ay = __fabsf(y);
    double r;
    double r2;
    double value;
    int quadrant;

    if (ax >= ay) {
        r = ay / ax;
        r2 = r * r;
        value = r * (((((((((((((((lbl_803E7AA8 * r2 + lbl_803E7AA0) * r2 + lbl_803E7A98) * r2 + lbl_803E7A90) * r2
                       + lbl_803E7A88) * r2 + lbl_803E7A80) * r2 + lbl_803E7A78) * r2 + lbl_803E7A70) * r2
                    + lbl_803E7A68) * r2 + lbl_803E7A60) * r2 + lbl_803E7A58) * r2 + lbl_803E7A50) * r2
                 + lbl_803E7A48) * r2 + lbl_803E7A40) * r2 + lbl_803E7A38) * r2 + lbl_803E7A30);
    } else {
        r = ax / ay;
        r2 = r * r;
        value = lbl_803E79E0 - r * (((((((((((((((lbl_803E7AA8 * r2 + lbl_803E7AA0) * r2 + lbl_803E7A98) * r2 + lbl_803E7A90) * r2
                       + lbl_803E7A88) * r2 + lbl_803E7A80) * r2 + lbl_803E7A78) * r2 + lbl_803E7A70) * r2
                    + lbl_803E7A68) * r2 + lbl_803E7A60) * r2 + lbl_803E7A58) * r2 + lbl_803E7A50) * r2
                 + lbl_803E7A48) * r2 + lbl_803E7A40) * r2 + lbl_803E7A38) * r2 + lbl_803E7A30);
    }

    quadrant = (*(u32 *)&y & 0x80000000) | ((*(u32 *)&x >> 1) & 0x40000000);
    switch (quadrant) {
        case 0x00000000:
            return (float)value;
        case 0x80000000:
            return (float)-value;
        case 0x40000000:
            return (float)(lbl_803E7A00 - value);
        default:
            return (float)(value - lbl_803E7A00);
    }
}
