#include <dolphin.h>

const f32 lbl_803E7630 = 1.0f;
const f32 lbl_803E7634 = 2.0f;
const f32 lbl_803E7638 = 0.0f;
const f32 lbl_803E763C = -1.0f;
const f32 lbl_803E7640 = 0.5f;
const f32 lbl_803E7644 = 0.017453292f;

extern f32 tanf(f32);

extern const f32 lbl_803E7630;
extern const f32 lbl_803E7634;
extern const f32 lbl_803E7638;
extern const f32 lbl_803E763C;
extern const f32 lbl_803E7640;
extern const f32 lbl_803E7644;

void C_MTXPerspective(Mtx44 m, f32 fovY, f32 aspect, f32 n, f32 f) {
    f32 angle;
    f32 cot;
    f32 tmp;

    angle = *(f32*)&lbl_803E7640 * fovY;
    angle = *(f32*)&lbl_803E7644 * angle;
    cot = *(f32*)&lbl_803E7630 / tanf(angle);

    m[0][0] = cot / aspect;
    m[0][1] = *(f32*)&lbl_803E7638;
    m[0][2] = *(f32*)&lbl_803E7638;
    m[0][3] = *(f32*)&lbl_803E7638;
    m[1][0] = *(f32*)&lbl_803E7638;
    m[1][1] = cot;
    m[1][2] = *(f32*)&lbl_803E7638;
    m[1][3] = *(f32*)&lbl_803E7638;
    m[2][0] = *(f32*)&lbl_803E7638;
    m[2][1] = *(f32*)&lbl_803E7638;

    tmp = *(f32*)&lbl_803E7630 / (f - n);
    m[2][2] = -n * tmp;
    m[2][3] = tmp * -(f * n);
    m[3][0] = *(f32*)&lbl_803E7638;
    m[3][1] = *(f32*)&lbl_803E7638;
    m[3][2] = *(f32*)&lbl_803E763C;
    m[3][3] = *(f32*)&lbl_803E7638;
}

void C_MTXOrtho(Mtx44 m, f32 t, f32 b, f32 l, f32 r, f32 n, f32 f) {
    f32 tmp;

    tmp = *(f32*)&lbl_803E7630 / (r - l);
    m[0][0] = *(f32*)&lbl_803E7634 * tmp;
    m[0][1] = *(f32*)&lbl_803E7638;
    m[0][2] = *(f32*)&lbl_803E7638;
    m[0][3] = tmp * -(r + l);

    tmp = *(f32*)&lbl_803E7630 / (t - b);
    m[1][0] = *(f32*)&lbl_803E7638;
    m[1][1] = *(f32*)&lbl_803E7634 * tmp;
    m[1][2] = *(f32*)&lbl_803E7638;
    m[1][3] = tmp * -(t + b);

    tmp = *(f32*)&lbl_803E7630 / (f - n);
    m[2][0] = *(f32*)&lbl_803E7638;
    m[2][1] = *(f32*)&lbl_803E7638;
    m[2][2] = *(f32*)&lbl_803E763C * tmp;
    m[2][3] = (-f) * tmp;
    m[3][0] = *(f32*)&lbl_803E7638;
    m[3][1] = *(f32*)&lbl_803E7638;
    m[3][2] = *(f32*)&lbl_803E7638;
    m[3][3] = *(f32*)&lbl_803E7630;
}
