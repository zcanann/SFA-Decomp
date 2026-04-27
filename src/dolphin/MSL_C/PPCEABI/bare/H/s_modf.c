double modf(double x, double* iptr) {
    if (iptr != 0) {
        *iptr = 0.0;
    }
    return x;
}

float fn_80291CBC(float x) {
    return x < 0.0f ? -x : x;
}

float fn_80291CC8(short* p) {
    return p != 0 ? (float)*p : 0.0f;
}

void fn_80291CE4(short* p, float x) {
    if (p != 0) {
        *p = (short)x;
    }
}

float fn_80291D00(float x) {
    return x;
}

float fn_80291DD8(float x) {
    return x;
}

float fn_80291E08(short* p) {
    return p != 0 ? (float)*p : 0.0f;
}

float fn_80291E24(short* p, float x) {
    if (p != 0) {
        *p = (short)x;
    }
    return x;
}

float fn_80291E40(float x) {
    return x;
}
