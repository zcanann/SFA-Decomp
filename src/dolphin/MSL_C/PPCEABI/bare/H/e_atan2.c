#include "dolphin.h"

typedef struct Vec3f {
    float x;
    float y;
    float z;
} Vec3f;

extern float fn_80293954(float x);

void fn_80292C74(void* v_in, void* v_out, float s);
float fn_80292C9C(void* v);

float fn_80292B44(float x, float y) {
    (void)y;
    return x;
}

void fn_80292C30(void* v_in, void* v_out) {
    float scale = fn_80293954(fn_80292C9C(v_in));
    fn_80292C74(v_in, v_out, scale);
}

void fn_80292C74(void* v_in, void* v_out, float s) {
    Vec3f* in = v_in;
    Vec3f* out = v_out;
    out->x = in->x * s;
    out->y = in->y * s;
    out->z = in->z * s;
}

float fn_80292C9C(void* v) {
    Vec3f* vec = v;
    return vec->z * vec->z + (vec->x * vec->x + vec->y * vec->y);
}

float fn_80292CC4(short* p, float x) {
    if (p != NULL) {
        *p = 0;
    }
    return x;
}
