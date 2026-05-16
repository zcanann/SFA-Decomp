#include "ghidra_import.h"
#include "main/dll/DR/DRCloudball.h"

extern f32 sqrtf(f32 x);
extern f32 sin(double x);
extern f32 fn_80293E80(double x); /* cos-like */
extern int randomGetRange(int lo, int hi);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern int Obj_GetActiveModel(int obj);
extern int Obj_GetPlayerObject(void);
extern s16 getAngle(f32 dx, f32 dz);
extern int objMove(int obj, f32 vx, f32 vy, f32 vz);
extern void ObjAnim_SampleRootCurvePhase(f32 distance, int obj, f32 *out);
extern void ObjAnim_AdvanceCurrentMove(int obj, f32 phase, f32 dt, int flag);
extern int objBboxFn_800640cc(int p1, int p2, f32 r, int p4, int p5, int obj, int p7, int p8, int p9, int p10);
extern void fn_8002273C(int p1, int p2, int p3);
extern f32 getXZDistance(int *p1, int *p2);
extern void itemPickupDoParticleFx(int obj, f32 a, int b, int c);
extern void objFn_800972dc(int obj, int p2, f32 f1, int p4, int p5, int p6, f32 f2, int p7, int p8);

extern f32 timeDelta;
extern u16 lbl_803E5A70;
extern u8 lbl_803E5A72;
extern f32 lbl_803E5A74;
extern f32 lbl_803E5A78;
extern f32 lbl_803E5A7C;
extern f32 lbl_803E5A80;
extern f32 lbl_803E5A84;
extern f32 lbl_803E5A88;
extern f32 lbl_803E5A8C;
extern f32 lbl_803E5A90;
extern f32 lbl_803E5A94;
extern f64 lbl_803E5A98; /* int->float magic 0x4330000000000000 */

extern void spscarab_hitDetect(void);
extern void spscarab_render(void);
extern void spscarab_free(int x);
extern int spscarab_func08(void);
extern int spscarab_getExtraSize(void);

/*
 * --INFO--
 *
 * Function: spscarab_update
 * EN v1.0 Address: 0x801E8EE0
 * EN v1.0 Size: 588b
 */
#pragma peephole off
#pragma scheduling off
void spscarab_update(int param_1)
{
    int p_b8;
    int p_4c;
    s16 angle;
    f32 distance;
    f32 phase;        /* sp+0x10 */
    f32 outV[3];      /* sp+0x14 (output of fn_8002273C) */
    f32 hit_buf[24];  /* sp+0x20 .. sp+0x80 (collision struct, objBboxFn_800640cc out) */

    p_b8 = *(int *)(param_1 + 0xb8);
    p_4c = *(int *)(param_1 + 0x4c);

    if (*(f32 *)(param_1 + 0x10) > *(f32 *)(p_b8 + 0)) {
        *(f32 *)(param_1 + 0x28) = *(f32 *)(param_1 + 0x28) - lbl_803E5A74 * timeDelta;
    }

    objMove(param_1,
                timeDelta * (*(f32 *)(param_1 + 0x24) * *(f32 *)(p_b8 + 4)),
                *(f32 *)(param_1 + 0x28) * timeDelta,
                timeDelta * (*(f32 *)(param_1 + 0x2c) * *(f32 *)(p_b8 + 4)));

    distance = sqrtf(*(f32 *)(param_1 + 0x24) * *(f32 *)(param_1 + 0x24) +
                     *(f32 *)(param_1 + 0x2c) * *(f32 *)(param_1 + 0x2c));

    ObjAnim_SampleRootCurvePhase(distance, param_1, &phase);
    ObjAnim_AdvanceCurrentMove(param_1, phase, timeDelta, 0);

    if (*(f32 *)(param_1 + 0x10) < *(f32 *)(p_b8 + 0)) {
        *(f32 *)(param_1 + 0x10) = *(f32 *)(p_b8 + 0);
        *(f32 *)(param_1 + 0x28) = lbl_803E5A78;
    }

    if (objBboxFn_800640cc(param_1 + 0x80, param_1 + 0xc,
                    lbl_803E5A7C, 0, (int)&hit_buf[0] /* sp+0x20 */, param_1,
                    8, -1, 0xff, 0xa) != 0) {
        fn_8002273C((int)&hit_buf[7] /* sp+0x3c */, param_1 + 0x24, (int)outV);
        *(f32 *)(param_1 + 0x24) = outV[0];
        *(f32 *)(param_1 + 0x2c) = outV[2];
        angle = (s16)getAngle(-*(f32 *)(param_1 + 0x24), -*(f32 *)(param_1 + 0x2c));
        *(s16 *)(param_1) = angle;
    }

    if (getXZDistance((int *)(Obj_GetPlayerObject() + 0x18), (int *)(param_1 + 0x18))
        < lbl_803E5A80) {
        Sfx_PlayFromObject(param_1, (u16)*(s16 *)(p_b8 + 0xc));
        itemPickupDoParticleFx(param_1, lbl_803E5A84, *(s16 *)(p_b8 + 0xe), 0x28);
        *(u16 *)(param_1 + 0xb0) = *(u16 *)(param_1 + 0xb0) | 0x8000;
        *(s16 *)(param_1 + 0x6) = *(s16 *)(param_1 + 0x6) | 0x4000;

        {
            int r5val = (*(s8 *)(p_4c + 0x19) == 0) ? 1 : 0;
            int v3 = *(int *)(p_b8 + 8);
            int r4val = (*(s8 *)(p_4c + 0x19) == 0) ? 0 : 1;
            (*(void (**)(int, int, int))(*(int *)(*(int *)(v3 + 0x68)) + 0x50))(
                v3, r4val, r5val);
        }
    }

    if ((*(u16 *)(param_1 + 0xb0) & 0x800) != 0) {
        if (*(s16 *)(p_b8 + 0x10) != 0) {
            objFn_800972dc(param_1, 5, lbl_803E5A84, (u8)*(s16 *)(p_b8 + 0x10), 1, 0x14,
                        lbl_803E5A88, 0, 0);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: spscarab_init
 * EN v1.0 Address: 0x801E912C
 * EN v1.0 Size: 500b
 */
#pragma peephole off
#pragma scheduling off
void spscarab_init(int param_1, int param_2)
{
    int p_b8;
    int model;
    struct { u16 a; u8 b; } pair;

    p_b8 = *(int *)(param_1 + 0xb8);
    pair.a = lbl_803E5A70;
    pair.b = lbl_803E5A72;

    *(u16 *)(param_1 + 0xb0) = *(u16 *)(param_1 + 0xb0) | 0x6000;
    *(s16 *)(param_1) = (s16)((s32)(s8)*(u8 *)(param_2 + 0x18) << 8);

    *(f32 *)(param_1 + 0x24) =
        -fn_80293E80(lbl_803E5A8C * (f32)(s32)*(s16 *)(param_1) /
                     lbl_803E5A90);
    *(f32 *)(param_1 + 0x2c) =
        -sin(lbl_803E5A8C * (f32)(s32)*(s16 *)(param_1) /
             lbl_803E5A90);

    *(s8 *)(param_1 + 0xad) = (s8)(1 - *(u8 *)(param_2 + 0x19));

    *(f32 *)(p_b8 + 0) = (f32)(s32)*(s16 *)(param_2 + 0x1a);
    *(f32 *)(p_b8 + 4) = lbl_803E5A94 + (f32)randomGetRange(0, 0x64) / lbl_803E5A80;
    *(int *)(p_b8 + 8) = *(int *)(param_2 + 0x14);
    *(int *)(param_2 + 0x14) = -1;

    Sfx_AddLoopedObjectSound(param_1, 0x406);
    model = Obj_GetActiveModel(param_1);

    switch ((s8)*(u8 *)(param_2 + 0x19)) {
    case 0:
        *(u8 *)(*(int *)(model + 0x34) + 8) = *((u8 *)&pair + randomGetRange(0, 2));
        *(s16 *)(p_b8 + 0xc) = 0x41;
        *(s16 *)(p_b8 + 0xe) = 4;
        *(s16 *)(p_b8 + 0x10) = 2;
        break;
    case 1:
        *(s16 *)(p_b8 + 0xc) = 0x42;
        *(s16 *)(p_b8 + 0xe) = 1;
        *(s16 *)(p_b8 + 0x10) = 0;
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: spscarab_release
 * EN v1.0 Address: 0x801E9320
 * EN v1.0 Size: 4b
 */
void spscarab_release(void)
{
}

/*
 * --INFO--
 *
 * Function: spscarab_initialise
 * EN v1.0 Address: 0x801E9324
 * EN v1.0 Size: 4b
 */
void spscarab_initialise(void)
{
}

u32 gSPScarabObjDescriptor[] = {
    0,
    0,
    0,
    0x00090000,
    (u32)spscarab_initialise,
    (u32)spscarab_release,
    0,
    (u32)spscarab_init,
    (u32)spscarab_update,
    (u32)spscarab_hitDetect,
    (u32)spscarab_render,
    (u32)spscarab_free,
    (u32)spscarab_func08,
    (u32)spscarab_getExtraSize,
};

/*
 * --INFO--
 *
 * Function: spdrape_getExtraSize
 * EN v1.0 Address: 0x801E9328
 * EN v1.0 Size: 8b
 */
int spdrape_getExtraSize(void)
{
    return 0x18;
}

/*
 * --INFO--
 *
 * Function: spdrape_func08
 * EN v1.0 Address: 0x801E9330
 * EN v1.0 Size: 8b
 */
int spdrape_func08(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: spdrape_free
 * EN v1.0 Address: 0x801E9338
 * EN v1.0 Size: 4b
 */
void spdrape_free(void)
{
}

/*
 * --INFO--
 *
 * Function: spdrape_render
 * EN v1.0 Address: 0x801E933C
 * EN v1.0 Size: 4b
 */
void spdrape_render(void)
{
}

/*
 * --INFO--
 *
 * Function: spdrape_hitDetect
 * EN v1.0 Address: 0x801E9340
 * EN v1.0 Size: 4b
 */
void spdrape_hitDetect(void)
{
}
