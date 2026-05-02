extern double __frsqrte(double x);
typedef signed short s16;

extern float lbl_803E7C70;
extern float lbl_803E7C74;
extern float lbl_803E7C78;
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

extern float fn_80291E08(s16* p);

float __kernel_tan(float x) {
    float guess;
    float half;

    if (lbl_803E7C70 != x) {
        guess = (float)__frsqrte(x);
        half = lbl_803E7C74 * x;
        guess = guess * (lbl_803E7C78 - guess * (half * guess));
        guess = guess * (lbl_803E7C78 - guess * (half * guess));
        guess = guess * (lbl_803E7C78 - guess * (half * guess));
        return guess * x;
    }

    return lbl_803E7C70;
}

float fn_80293900(float x) {
    float guess;
    float half;

    if (lbl_803E7C70 != x) {
        guess = (float)__frsqrte(x);
        half = lbl_803E7C74 * x;
        guess = guess * (lbl_803E7C78 - guess * (half * guess));
        return guess * x;
    }

    return lbl_803E7C70;
}

float fn_80293954(float x) {
    float guess;
    float half;

    guess = (float)__frsqrte(x);
    half = lbl_803E7C74 * x;
    guess = guess * (lbl_803E7C78 - guess * (half * guess));
    return guess;
}

float fn_80293994(int angle) {
    s16 reduced = (s16)(angle << 2);
    float x = fn_80291E08(&reduced);
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
            return lbl_803E7C80 - x2 * (lbl_803E7C88 * x2 + lbl_803E7C84);
    }
}

float fcos16(int angle) {
    s16 reduced = (s16)(angle << 2);
    float x = fn_80291E08(&reduced);
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
            return lbl_803E7CA0 - x2 * ((lbl_803E7CAC * x2 + lbl_803E7CA8) * x2 + lbl_803E7CA4);
    }
}
