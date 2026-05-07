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

static float finish_quadrant(float y, float x, float value) {
    union {
        float f;
        u32 u;
    } y_bits, x_bits;
    u32 quadrant;

    y_bits.f = y;
    x_bits.f = x;
    quadrant = (y_bits.u & 0x80000000) | ((x_bits.u & 0x80000000) >> 1);

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

static float finish_quadrant_d(float y, float x, double value) {
    union {
        float f;
        u32 u;
    } y_bits, x_bits;
    u32 quadrant;

    y_bits.f = y;
    x_bits.f = x;
    quadrant = (y_bits.u & 0x80000000) | ((x_bits.u & 0x80000000) >> 1);

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

float __kernel_cos(float y, float x) {
    float ax = __fabsf(x);
    float ay = __fabsf(y);
    float r;
    float r2;
    float value;

    if (ax > ay) {
        r = ay / ax;
        r2 = r * r;
        value = r * (lbl_803E7A0C * r2 + lbl_803E7A08);
    } else {
        r = ax / ay;
        r2 = r * r;
        value = lbl_803E79C8 - r * (lbl_803E7A0C * r2 + lbl_803E7A08);
    }

    return finish_quadrant(y, x, value);
}

float fn_802924B4(float y, float x) {
    float ax = __fabsf(x);
    float ay = __fabsf(y);
    float r;
    float r2;
    float value;

    if (ax > ay) {
        r = ay / ax;
        r2 = r * r;
        value = r * (((lbl_803E7A28 * r2 + lbl_803E7A24) * r2 + lbl_803E7A20) * r2 + lbl_803E7A1C);
    } else {
        r = ax / ay;
        r2 = r * r;
        value = lbl_803E79C8 - r * (((lbl_803E7A28 * r2 + lbl_803E7A24) * r2 + lbl_803E7A20) * r2 + lbl_803E7A1C);
    }

    return finish_quadrant(y, x, value);
}

float fn_802925C4(float y, float x) {
    float ax = __fabsf(x);
    float ay = __fabsf(y);
    double r;
    double r2;
    double p;
    double value;

    if (ax >= ay) {
        r = ay / ax;
        r2 = r * r;
        p = ((((((((((((((lbl_803E7AA8 * r2 + lbl_803E7AA0) * r2 + lbl_803E7A98) * r2 + lbl_803E7A90) * r2
                       + lbl_803E7A88) * r2 + lbl_803E7A80) * r2 + lbl_803E7A78) * r2 + lbl_803E7A70) * r2
                    + lbl_803E7A68) * r2 + lbl_803E7A60) * r2 + lbl_803E7A58) * r2 + lbl_803E7A50) * r2
                 + lbl_803E7A48) * r2 + lbl_803E7A40) * r2 + lbl_803E7A38) * r2 + lbl_803E7A30;
        value = r * p;
    } else {
        r = ax / ay;
        r2 = r * r;
        p = ((((((((((((((lbl_803E7AA8 * r2 + lbl_803E7AA0) * r2 + lbl_803E7A98) * r2 + lbl_803E7A90) * r2
                       + lbl_803E7A88) * r2 + lbl_803E7A80) * r2 + lbl_803E7A78) * r2 + lbl_803E7A70) * r2
                    + lbl_803E7A68) * r2 + lbl_803E7A60) * r2 + lbl_803E7A58) * r2 + lbl_803E7A50) * r2
                 + lbl_803E7A48) * r2 + lbl_803E7A40) * r2 + lbl_803E7A38) * r2 + lbl_803E7A30;
        value = lbl_803E79E0 - r * p;
    }

    return finish_quadrant_d(y, x, value);
}
