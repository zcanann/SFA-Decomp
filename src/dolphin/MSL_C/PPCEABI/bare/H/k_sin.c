extern float lbl_803E79C0;
extern float lbl_803E79C4;
extern float lbl_803E79C8;
extern float lbl_803E79CC;
extern float lbl_803E79D0;
extern float lbl_803E79D4;
extern float lbl_803E79D8;
extern float lbl_803E79E8;
extern float lbl_803E79EC;
extern float lbl_803E79F0;
extern float lbl_803E79F4;
extern float lbl_803E79F8;
extern float lbl_803E79FC;
extern double lbl_803E79E0;
extern float lbl_803E7A10;
extern float lbl_803E7A14;
extern float lbl_803E7A18;
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
extern double lbl_803E7AB0;

extern float __kernel_tan(float x);
extern float fn_80292DEC(float x);

float __kernel_sin(float x) {
    float ax = __fabsf(x);
    float y;
    float p;

    if (ax <= lbl_803E79C0) {
        y = x * x;
        return x * (lbl_803E79D4 * y + lbl_803E79D0);
    }

    y = lbl_803E79C0 - lbl_803E79C0 * ax;
    p = __kernel_tan(y) * (lbl_803E79D4 * y + lbl_803E79D0);
    if (x >= lbl_803E79C4) {
        return lbl_803E79C8 - lbl_803E79CC * p;
    }
    return lbl_803E79CC * p - lbl_803E79C8;
}

float fn_80291FF4(float x) {
    float ax = __fabsf(x);
    float y;
    float p;

    if (ax <= lbl_803E79C0) {
        y = x * x;
        return lbl_803E79C8 - x * (lbl_803E79D4 * y + lbl_803E79D0);
    }

    y = lbl_803E79C0 - lbl_803E79C0 * ax;
    p = __kernel_tan(y) * (lbl_803E79D4 * y + lbl_803E79D0);
    if (x >= lbl_803E79C4) {
        return lbl_803E79CC * p;
    }
    return lbl_803E79E8 - lbl_803E79CC * p;
}

float fn_802920A4(float x) {
    float ax = __fabsf(x);
    float y;
    float p;

    if (ax <= lbl_803E79C0) {
        y = x * x;
        return lbl_803E79C8 - x * (((((lbl_803E79FC * y + lbl_803E79F8) * y + lbl_803E79F4) * y
                                      + lbl_803E79F0) * y + lbl_803E79EC) * y + lbl_803E79D8);
    }

    y = lbl_803E79C0 - lbl_803E79C0 * ax;
    p = __kernel_tan(y)
        * (((((lbl_803E79FC * y + lbl_803E79F8) * y + lbl_803E79F4) * y + lbl_803E79F0) * y
            + lbl_803E79EC) * y + lbl_803E79D8);
    if (x >= lbl_803E79C4) {
        return lbl_803E79CC * p;
    }
    return lbl_803E79E8 - lbl_803E79CC * p;
}

float fn_80292194(float x) {
    float ax = __fabsf(x);
    float y;
    float p;

    if (ax <= lbl_803E79D8) {
        y = x * x;
        return x * ((lbl_803E7A18 * y + lbl_803E7A14) * y + lbl_803E7A10);
    }

    y = fn_80292DEC(ax);
    p = y * ((lbl_803E7A18 * (y * y) + lbl_803E7A14) * (y * y) + lbl_803E7A10);
    if (x >= lbl_803E79C4) {
        return lbl_803E79C8 - p;
    }
    return p - lbl_803E79C8;
}

float fn_80292248(float x) {
    float ax = __fabsf(x);
    double y;
    double p;
    float result;

    if (ax <= lbl_803E79D8) {
        y = x * x;
        p = ((((((((((((((lbl_803E7AA8 * y + lbl_803E7AA0) * y + lbl_803E7A98) * y + lbl_803E7A90) * y
                       + lbl_803E7A88) * y + lbl_803E7A80) * y + lbl_803E7A78) * y + lbl_803E7A70) * y
                    + lbl_803E7A68) * y + lbl_803E7A60) * y + lbl_803E7A58) * y + lbl_803E7A50) * y
                 + lbl_803E7A48) * y + lbl_803E7A40) * y + lbl_803E7A38) * y + lbl_803E7A30;
        return (float)(x * p);
    }

    y = lbl_803E7AB0 / ax;
    p = ((((((((((((((lbl_803E7AA8 * (y * y) + lbl_803E7AA0) * (y * y) + lbl_803E7A98) * (y * y)
                   + lbl_803E7A90) * (y * y) + lbl_803E7A88) * (y * y) + lbl_803E7A80) * (y * y)
                + lbl_803E7A78) * (y * y) + lbl_803E7A70) * (y * y) + lbl_803E7A68) * (y * y)
             + lbl_803E7A60) * (y * y) + lbl_803E7A58) * (y * y) + lbl_803E7A50) * (y * y)
          + lbl_803E7A48) * (y * y) + lbl_803E7A40) * (y * y) + lbl_803E7A38) * (y * y) + lbl_803E7A30;
    result = (float)(lbl_803E79E0 - y * p);
    if (x >= lbl_803E79C4) {
        return result;
    }
    return -result;
}
