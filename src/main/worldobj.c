#include "ghidra_import.h"

typedef struct {
    f32 f0;
    f32 f4;
    f32 f8;
    f32 fc;
    u8 f10;
    u8 f11;
    u8 pad12[2];
} GreatFoxFxEntry;

extern int *gExpgfxInterface;
extern void ModelLightStruct_free(int model);
extern int *gScreenTransitionInterface;
extern void objRenderFn_8003b8f4(f32 e);
extern f32 lbl_803E6678;
extern int randomGetRange(int min, int max);
extern void GXSetScissor(int x, int y, int w, int h);
extern void Camera_ApplyCurrentViewport(int cam);
extern int fn_8012DDAC(void);
extern int lbl_803DDD34;
extern int fn_8001DB64(int model);
extern void queueGlowRender(int model);
extern int *gPartfxInterface;
extern void mathFn_80021ac8(void *in, void *out);
extern int ObjList_FindObjectById(int id);
extern f32 Vec_distance(void *a, void *b);
extern int objCreateLight(int obj, int arg);
extern void modelLightStruct_setField50(int light, int v);
extern void lightVecFn_8001dd88(int light, f32 a, f32 b, f32 c);
extern void modelLightStruct_setColorsA8AC(int light, int r, int g, int b, int a);
extern void lightDistAttenFn_8001dc38(int light, f32 a, f32 b);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int e, f32 f);
extern void modelLightStruct_setGlowProjectionRadius(int light, f32 a);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern int Obj_SetupObject(int obj, int a, int b, int c, int d);
extern u8 lbl_803DC210[8];
extern int lbl_803DDD30;
extern f32 lbl_803E6668;
extern f32 lbl_803E66B4;
extern f32 lbl_803E66C8;
extern f32 lbl_803E66CC;
extern f32 lbl_803E66D0;
extern f32 lbl_803E66D4;
extern f32 lbl_803E66A0;
extern f32 lbl_803E66AC;
extern f32 lbl_803E66D8;
extern f32 lbl_803E665C;
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int extraSize, int id);
extern GreatFoxFxEntry lbl_8032A210[10];
extern f32 lbl_803E6640;
extern f32 lbl_803E6644;
extern f32 lbl_803E6648;
extern f32 lbl_803E664C;
extern f32 lbl_803E6650;
extern f32 lbl_803E6654;
extern f32 lbl_803E6658;
extern f32 lbl_803E6660;
extern f32 lbl_803E6664;
extern f32 lbl_803E666C;
extern void objfx_spawnMaskedHitEffect(int obj, f32 scale, int a, int b, int c, void *params);
extern void objfx_spawnLightPulse(int obj, f32 scale, int a, int b, int c, f32 arg2, void *params);

int worldobj_getExtraSize(void);
void worldobj_hitDetect(void);
void worldobj_release(void);
void worldobj_initialise(void);
int worldobj_getObjectTypeId(int *obj);
void worldobj_free(int obj);
void worldobj_init(int obj, int arg);
void worldobj_spawnGreatFoxEffects(int obj);
void worldobj_spawnAsteroidBatch(int obj, int xMin, int xMax, int yMin, int yMax, int count, int dispatchId);
void worldobj_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

int worldobj_getExtraSize(void) { return 0x284; }

void worldobj_hitDetect(void) {}

void worldobj_release(void) {}

void worldobj_initialise(void) {}

#pragma scheduling off
#pragma peephole off
int worldobj_getObjectTypeId(int *obj) {
    if (*(s16 *)*(int **)((char *)obj + 0x4c) != 0x5e3) {
        return 0x0;
    }
    return 0x8;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void worldobj_free(int obj) {
    int *inner = *(int **)(obj + 0xb8);
    if (*(void **)inner != NULL) {
        ModelLightStruct_free(*inner);
        *inner = 0;
    }
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x14)))(obj);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void worldobj_init(int obj, int arg) {
    int inner = *(int *)(obj + 0xb8);
    int objA, objB;
    int sub;
    int idx;
    int i;
    f32 base;
    f32 d;

    switch (*(s16 *)arg) {
    case 0x5dd:
    case 0x5ed:
    case 0x5ee:
    case 0x5ef:
    case 0x5f0:
    case 0x5f1:
    case 0x5f2:
    case 0x5f3:
        *(u8 *)(inner + 0x27d) = 0;
        break;
    case 0x80f:
        objA = ObjList_FindObjectById(0x42fe7);
        objB = ObjList_FindObjectById(0x4305a);
        base = *(f32 *)(objB + 0x10) - *(f32 *)(objA + 0x10);
        *(f32 *)(inner + 0x264) = (*(f32 *)(objA + 0x10) - base) + (f32)(int)randomGetRange(-0x3e8, 0x3e8);
        *(f32 *)(inner + 0x268) = *(f32 *)(objB + 0x10) + (f32)(int)randomGetRange(-5, 5);
        *(f32 *)(inner + 0x26c) = lbl_803E6668 * ((f32)(int)randomGetRange(0, 0x64) / lbl_803E66B4) + lbl_803E6668;
        *(f32 *)(obj + 8) = *(f32 *)(obj + 8) * *(f32 *)(inner + 0x26c);
        *(s8 *)(inner + 0x280) = (s8)randomGetRange(0xa, 0x19);
        if (randomGetRange(0, 1) != 0) {
            *(s8 *)(inner + 0x280) = (s8)(-*(s8 *)(inner + 0x280));
            *(int *)(inner + 0x270) = 0x8000;
        }
        base = (f32)(int)randomGetRange(0xc8, 0x190);
        d = Vec_distance((char *)objB + 0x18, (char *)objA + 0x18);
        *(f32 *)(inner + 0x25c) = lbl_803E66C8 * d + base;
        *(f32 *)(inner + 0x260) = *(f32 *)(inner + 0x25c) * (lbl_803E66CC * ((f32)(int)randomGetRange(0, 0x64) / lbl_803E66B4) + lbl_803E66CC);
        *(int *)(obj + 0) = objCreateLight(obj, 1);
        if (*(int *)(obj + 0) != 0) {
            modelLightStruct_setField50(*(int *)(obj + 0), 2);
            lightVecFn_8001dd88(*(int *)(obj + 0), lbl_803E665C, lbl_803E665C, lbl_803E665C);
            modelLightStruct_setColorsA8AC(*(int *)(obj + 0), 0xff, 0xff, 0xff, 0);
            lightDistAttenFn_8001dc38(*(int *)(obj + 0), lbl_803E66AC, lbl_803E66D0);
            modelLightStruct_setupGlow(*(int *)(obj + 0), 0, 0xff, 0xff, 0xff, 0x82, lbl_803E66D4 * *(f32 *)(inner + 0x26c));
            modelLightStruct_setGlowProjectionRadius(*(int *)(obj + 0), lbl_803E66A0);
        }
        break;
    case 0x5f5:
        *(f32 *)(obj + 8) = lbl_803E66D8;
        break;
    case 0x5e3:
        *(u8 *)(inner + 0x27c) = 0;
        *(u8 *)(inner + 0x27e) = 0;
        break;
    case 0x5e2:
        idx = *(u8 *)(arg + 0x1b);
        Obj_SetActiveModelIndex(obj, idx);
        *(u8 *)(obj + 0x36) = lbl_803DC210[idx];
        for (i = 0; i < 0xb; i++) {
            sub = *(int *)(obj + 0x4c);
            if (Obj_IsLoadingLocked() != 0) {
                int o2 = Obj_AllocObjectSetup(0x20, 0x5da);
                *(u8 *)(o2 + 4) = *(u8 *)(sub + 4);
                *(u8 *)(o2 + 6) = *(u8 *)(sub + 6);
                *(u8 *)(o2 + 5) = *(u8 *)(sub + 5);
                *(u8 *)(o2 + 7) = *(u8 *)(sub + 7);
                *(f32 *)(o2 + 8) = *(f32 *)(obj + 0xc);
                *(f32 *)(o2 + 0xc) = *(f32 *)(obj + 0x10);
                *(f32 *)(o2 + 0x10) = *(f32 *)(obj + 0x14);
                Obj_SetupObject(o2, 5, (s8)*(u8 *)(obj + 0xac), -1, 0);
            }
        }
        break;
    case 0x5da:
        *(s16 *)(obj + 4) = (s16)randomGetRange(0, 0xffff);
        *(s16 *)(obj + 2) = (s16)randomGetRange(0, 0xffff);
        *(s16 *)(obj + 0) = (s16)randomGetRange(0, 0xffff);
        *(u8 *)(inner + 0x27c) = (u8)randomGetRange(0, 0xff);
        *(s8 *)(inner + 0x27e) = (s8)randomGetRange(-0xa, 0xa);
        *(s8 *)(inner + 0x27f) = (s8)randomGetRange(-0xa, 0xa);
        *(s8 *)(inner + 0x280) = (s8)randomGetRange(-0xa, 0xa);
        break;
    case 0x61e:
        *(u8 *)(inner + 0x27c) = 0;
        break;
    case 0x740:
        *(u8 *)(inner + 0x27d) = 0;
        lbl_803DDD30 = obj;
        break;
    case 0x5d5:
        *(int *)(inner + 0x274) = 0x4aaf7;
        *(int *)(inner + 0x278) = 0x4ab08;
        break;
    case 0x5d6:
        *(int *)(inner + 0x274) = 0x4ab03;
        *(int *)(inner + 0x278) = 0x4ab09;
        break;
    case 0x5d8:
        *(int *)(inner + 0x274) = 0x4ab04;
        *(int *)(inner + 0x278) = 0x4ab0a;
        break;
    case 0x5d7:
        *(int *)(inner + 0x274) = 0x4ab05;
        *(int *)(inner + 0x278) = 0x4ab0b;
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 sin(f32 x);
extern f32 sqrtf(f32 x);
extern f32 fn_80293E80(f32 x);
extern int getAngle(f32 dx, f32 dz);
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern int gAudioStreamCurrentId;
extern void Obj_FreeObject(int obj);
extern void lightFn_8001db6c(int light, int a, f32 b);
extern void modelLightStruct_updateGlowAlpha(int light);
extern void lightSetFieldB0(int light, int r, int g, int b, int a);
extern void modelLightStruct_startColorFade(int light, int a, int b);
extern void modelStruct2_setVectors(int light, f32 a, f32 b, f32 c);
extern void objfx_spawnFlaggedTrailBurst(int obj, f32 scale, int a, int b, int c, void *vec);
extern void ObjAnim_AdvanceCurrentMove(int obj, f32 weight, f32 dt, f32 *out);
extern void ObjAnim_SetCurrentMove(int obj, int moveId, f32 progress, int flags);
extern void ObjLink_AttachChild(int obj, int child, int slot);
extern void ObjPath_GetPointWorldPosition(int obj, int idx, f32 *x, f32 *y, f32 *z, int flag);
extern int objFindTexture(int obj, int a, int b);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern u8 *Camera_GetCurrentViewSlot(void);
extern f32 lbl_8032A200[];
extern int lbl_803DDD34;
extern f32 lbl_803E667C;
extern f32 lbl_803E6680;
extern f32 lbl_803E6684;
extern f32 lbl_803E6688;
extern f32 lbl_803E668C;
extern f32 lbl_803E6690;
extern f32 lbl_803E6694;
extern f32 lbl_803E6698;
extern f32 lbl_803E669C;
extern f32 lbl_803E66A4;
extern f32 lbl_803E66A8;
extern f32 lbl_803E66B0;
extern f32 lbl_803E66B8;
extern f32 lbl_803E6678;

#pragma scheduling off
#pragma peephole off
void worldobj_update(int obj) {
    s16 rot[3];
    f32 vec[4];
    struct {
        u8 pad0[6];
        s16 f6;
        u8 pad8[4];
        f32 fc;
        f32 f10;
        f32 f14;
    } params;
    int state;
    int setup;
    int objA;
    int objB;
    int tmp;
    u8 i;
    int child;
    int tex;
    u8 *view;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 dist;
    f32 sv;

    state = *(int *)(obj + 0xb8);
    setup = *(int *)(obj + 0x4c);

    switch (*(s16 *)setup) {
    case 0x80f:
        if (*(int *)(state + 0x270) > 0x8000 || *(int *)(state + 0x270) < 0) {
            if (*(void **)state != NULL) {
                lightFn_8001db6c(*(int *)state, 0, lbl_803E6678);
            }
            tmp = (int)((f32)*(u8 *)(obj + 0x36) - lbl_803E667C * timeDelta);
            if (tmp < 0) {
                tmp = 0;
            }
            *(u8 *)(obj + 0x36) = tmp;
            if (*(u8 *)(obj + 0x36) == 0) {
                Obj_FreeObject(obj);
            }
        } else {
            objA = ObjList_FindObjectById(0x42fe7);
            objB = ObjList_FindObjectById(0x4305a);
            if ((void *)objA != NULL && (void *)objB != NULL) {
                *(int *)(state + 0x270) =
                    (int)((f32)*(s8 *)(state + 0x280) * timeDelta + (f32)*(int *)(state + 0x270));
                vec[0] = *(f32 *)(state + 0x260) *
                          sin(lbl_803E6680 * (f32)*(int *)(state + 0x270) / lbl_803E6684);
                vec[1] = lbl_803E665C;
                vec[2] = *(f32 *)(state + 0x25c) *
                          fn_80293E80(lbl_803E6680 * (f32)*(int *)(state + 0x270) / lbl_803E6684);
                dx = *(f32 *)(objB + 0xc) - *(f32 *)(objA + 0xc);
                dz = *(f32 *)(objB + 0x14) - *(f32 *)(objA + 0x14);
                rot[0] = getAngle(dx, dz);
                rot[1] = 0;
                rot[2] = 0;
                mathFn_80021ac8(rot, vec);
                *(f32 *)(obj + 0xc) = vec[0] + (*(f32 *)(objA + 0xc) - dx);
                *(f32 *)(obj + 0x10) =
                    *(f32 *)(state + 0x264) +
                    (f32)*(int *)(state + 0x270) *
                        (*(f32 *)(state + 0x268) - *(f32 *)(state + 0x264)) / lbl_803E6688;
                *(f32 *)(obj + 0x14) = vec[2] + (*(f32 *)(objA + 0x14) - dz);
            }
            *(f32 *)(obj + 0x24) = oneOverTimeDelta * (*(f32 *)(obj + 0xc) - *(f32 *)(obj + 0x80));
            *(f32 *)(obj + 0x2c) = oneOverTimeDelta * (*(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88));
            vec[0] = *(f32 *)(obj + 0x24);
            vec[1] = lbl_803E665C;
            vec[2] = *(f32 *)(obj + 0x2c);
            objfx_spawnFlaggedTrailBurst(obj, lbl_803E6668 * *(f32 *)(state + 0x26c), 2, 0xdf,
                                         8, vec);
            *(s16 *)(obj + 0) = lbl_803E668C * timeDelta + (f32)*(s16 *)(obj + 0);
            *(s16 *)(obj + 2) = lbl_803E6690 * timeDelta + (f32)*(s16 *)(obj + 2);
            if (*(void **)state != NULL && fn_8001DB64(*(int *)state) != 0) {
                modelLightStruct_updateGlowAlpha(*(int *)state);
            }
        }
        break;
    case 0x740:
        ObjAnim_AdvanceCurrentMove(obj, lbl_803E6694, timeDelta, NULL);
        *(s16 *)(obj + 0) = lbl_803E668C * timeDelta + (f32)*(s16 *)(obj + 0);
        break;
    case 0x5dc:
        if (*(int *)(obj + 0xf4) == 0) {
            *(int *)(obj + 0xf4) = ObjList_FindObjectById(0x431dc);
            ObjLink_AttachChild(obj, *(int *)(obj + 0xf4), 0);
        }
        if (*(int *)(obj + 0xf8) == 0) {
            *(int *)(obj + 0xf8) = ObjList_FindObjectById(0x4325b);
            ObjLink_AttachChild(obj, *(int *)(obj + 0xf8), 0);
        }
        tex = objFindTexture(obj, 0, 0);
        if ((void *)tex != NULL) {
            tmp = (s16)-*(s16 *)(tex + 8);
            tmp -= 2;
            if ((s16)tmp < 0) {
                tmp += 0x2710;
            }
            *(s16 *)(tex + 8) = (s16)-tmp;
        }
        break;
    case 0x5dd:
    case 0x5ed:
    case 0x5ee:
    case 0x5ef:
    case 0x5f0:
    case 0x5f1:
    case 0x5f2:
    case 0x5f3:
        if (*(u8 *)(state + 0x27d) == 2) {
            for (i = 0; i < 0x16; i++) {
                char *e = (char *)state + i * 0x18;
                ObjPath_GetPointWorldPosition(obj, i, (f32 *)(e + 0x10), (f32 *)(e + 0x14),
                                              (f32 *)(e + 0x18), 0);
            }
        }
        break;
    case 0x5e2:
        switch (*(u8 *)(setup + 0x1b)) {
        case 0:
            *(s16 *)(obj + 0) += 0x64;
            break;
        case 1:
            *(s16 *)(obj + 2) += 0x64;
            break;
        case 2:
            *(s16 *)(obj + 4) += 0x64;
            break;
        }
        break;
    case 0x5da:
        *(s16 *)(obj + 0) += *(s8 *)(state + 0x280);
        *(s16 *)(obj + 2) += *(s8 *)(state + 0x27f);
        *(s16 *)(obj + 4) += *(s8 *)(state + 0x27e);
        *(u8 *)(state + 0x27c) += 2;
        sv = sin(lbl_803E6680 * (f32)(s16)(*(u8 *)(state + 0x27c) << 8) / lbl_803E6684);
        *(f32 *)(obj + 8) = lbl_803E669C * (lbl_803E6678 + sv) + lbl_803E6698;
        break;
    case 0x5db:
        *(s16 *)(obj + 0) = 0x21a8;
        *(f32 *)(obj + 8) = lbl_803E66A0;
        break;
    case 0x5f5:
        *(s16 *)(obj + 0) += 1;
        break;
    case 0x602:
        ObjAnim_AdvanceCurrentMove(obj, lbl_803E66A4, timeDelta, &vec[3]);
        break;
    case 0x5e3:
        if (*(u8 *)(state + 0x27c) != *(s8 *)(obj + 0xad)) {
            Obj_SetActiveModelIndex(obj, *(u8 *)(state + 0x27c));
        }
        if (*(s8 *)(state + 0x27e) != (gAudioStreamCurrentId != 0)) {
            if (gAudioStreamCurrentId != 0) {
                ObjAnim_SetCurrentMove(obj, 1, lbl_803E665C, 0);
            } else {
                ObjAnim_SetCurrentMove(obj, 0, lbl_803E665C, 0);
            }
        }
        *(s8 *)(state + 0x27e) = gAudioStreamCurrentId != 0;
        ObjAnim_AdvanceCurrentMove(obj, lbl_8032A200[*(u8 *)(state + 0x27c)], timeDelta,
                                   &vec[3]);
        if (*(u8 *)(state + 0x27d) == 0 && *(void **)state != NULL) {
            ModelLightStruct_free(*(int *)state);
            *(int *)state = 0;
        }
        break;
    case 0x5df:
        worldobj_spawnGreatFoxEffects(obj);
    case 0x5d5:
    case 0x5d6:
    case 0x5d7:
    case 0x5d8:
        if (*(int *)(obj + 0xf8) == 0) {
            child = ObjList_FindObjectById(*(int *)(state + 0x278));
            if ((void *)child != NULL) {
                *(f32 *)(child + 8) *= lbl_803E6668;
                *(u8 *)(child + 0x36) = 0x96;
                *(s16 *)(child + 6) |= 0x4000;
                ObjLink_AttachChild(obj, child, 0);
                *(int *)(obj + 0xf8) = 1;
            }
        }
        if (*(int *)(obj + 0xf4) != 0 && *(void **)(state + 0x274) != NULL) {
            view = Camera_GetCurrentViewSlot();
            dx = *(f32 *)(view + 0xc) - *(f32 *)(obj + 0xc);
            dy = *(f32 *)(view + 0x10) - *(f32 *)(obj + 0x10);
            dz = *(f32 *)(view + 0x14) - *(f32 *)(obj + 0x14);
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (dist > lbl_803E665C) {
                dx /= dist;
                dy /= dist;
                dz /= dist;
            }
            sv = lbl_803E66A8;
            *(f32 *)(*(int *)(state + 0x274) + 0xc) = sv * dx + *(f32 *)(obj + 0xc);
            *(f32 *)(*(int *)(state + 0x274) + 0x10) = sv * dy + *(f32 *)(obj + 0x10);
            *(f32 *)(*(int *)(state + 0x274) + 0x14) = sv * dz + *(f32 *)(obj + 0x14);
        }
        if (*(u8 *)(state + 0x27d) != 0) {
            if ((u8)fn_8012DDAC() == 0 &&
                (*(int (*)(void))(*(int *)(*gScreenTransitionInterface + 0x14)))() != 0 &&
                lbl_803DDD34 == 0) {
                if (*(void **)state == NULL) {
                    *(int *)state = objCreateLight(obj, 1);
                    if (*(void **)state != NULL) {
                        modelLightStruct_setField50(*(int *)state, 2);
                        lightVecFn_8001dd88(*(int *)state, lbl_803E665C, lbl_803E66AC,
                                            lbl_803E665C);
                        modelLightStruct_setColorsA8AC(*(int *)state, 0xff, 0, 0, 0xff);
                        lightSetFieldB0(*(int *)state, 0, 0, 0, 0xff);
                        lightFn_8001db6c(*(int *)state, 1, lbl_803E665C);
                        lightDistAttenFn_8001dc38(*(int *)state, lbl_803E66B0, lbl_803E66B4);
                        modelLightStruct_startColorFade(*(int *)state, 2, 0x3c);
                        modelStruct2_setVectors(*(int *)state, lbl_803E665C, lbl_803E6644,
                                                lbl_803E665C);
                    }
                }
            } else if (*(void **)state != NULL) {
                ModelLightStruct_free(*(int *)state);
                *(int *)state = 0;
            }
            *(u8 *)(*(int *)(lbl_803DDD30 + 0xb8) + 0x27d) = 1;
            *(f32 *)(lbl_803DDD30 + 0xc) = *(f32 *)(obj + 0xc);
            *(f32 *)(lbl_803DDD30 + 0x10) = lbl_803E66B8 + *(f32 *)(obj + 0x10);
            *(f32 *)(lbl_803DDD30 + 0x14) = *(f32 *)(obj + 0x14);
            objA = ObjList_FindObjectById(0x4300c);
            if ((void *)objA != NULL && (*(s16 *)(objA + 6) & 0x4000)) {
                Obj_SetActiveModelIndex(lbl_803DDD30, 1);
            } else {
                Obj_SetActiveModelIndex(lbl_803DDD30, 0);
            }
        } else if (*(void **)state != NULL) {
            ModelLightStruct_free(*(int *)state);
            *(int *)state = 0;
        }
        break;
    case 0x61e:
        *(s16 *)(obj + 2) = 0x3448;
        *(s16 *)(obj + 0) = 0x4000;
        switch (*(u8 *)(setup + 0x1b)) {
        case 0:
            *(s16 *)(obj + 4) -= 0xe;
            break;
        case 1:
            *(s16 *)(obj + 4) -= 0x10;
            break;
        case 2:
            *(s16 *)(obj + 4) -= 0x13;
            break;
        }
        if (*(u8 *)(state + 0x27c) == 0) {
            switch (*(u8 *)(setup + 0x1b)) {
            case 0:
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x5, 0x5, 0x4b, 0x6f3);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x7, 0x7, 0x4b, 0x6f4);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x5, 0x5, 0x4b, 0x6f5);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x7, 0x7, 0x32, 0x6f6);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x5, 0x5, 0x4b, 0x6f7);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x7, 0x7, 0x32, 0x6f8);
                break;
            case 1:
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0x8, 0x8, 0x4b, 0x6f3);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0xa, 0xa, 0x4b, 0x6f4);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0x8, 0x8, 0x4b, 0x6f5);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0xa, 0xa, 0x32, 0x6f6);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0x8, 0x8, 0x4b, 0x6f7);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0xa, 0xa, 0x32, 0x6f8);
                break;
            case 2:
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x5, 0x5, 0x32, 0x6f3);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x7, 0x7, 0x32, 0x6f4);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x5, 0x5, 0x32, 0x6f5);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x7, 0x7, 0x19, 0x6f6);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x5, 0x5, 0x32, 0x6f7);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x7, 0x7, 0x19, 0x6f8);
                break;
            }
            *(u8 *)(state + 0x27c) = 1;
        }
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void worldobj_spawnGreatFoxEffects(int obj) {
    struct {
        u8 pad0[8];
        f32 f8;
        f32 fc;
        f32 f10;
        f32 f14;
    } params;
    u8 i;
    f32 s;
    f32 k = lbl_803E6640;

    for (i = 0; i < 0xa; i++) {
        GreatFoxFxEntry *e;
        s = *(f32 *)(obj + 8);
        e = &lbl_8032A210[i];
        params.fc = k * (s * e->f0);
        params.f10 = k * (s * e->f4);
        params.f14 = k * (s * e->f8);
        objfx_spawnMaskedHitEffect(obj, s * e->fc, 3, e->f10, e->f11, &params);
    }
    params.f8 = lbl_803E6644;
    params.fc = lbl_803E6640 * (lbl_803E6648 * *(f32 *)(obj + 8));
    params.f10 = lbl_803E6640 * (lbl_803E664C * *(f32 *)(obj + 8));
    params.f14 = lbl_803E6640 * (lbl_803E6650 * *(f32 *)(obj + 8));
    objfx_spawnLightPulse(obj, lbl_803E6654 * *(f32 *)(obj + 8), 1, 0, 6, lbl_803E6658, &params);
    params.fc = lbl_803E665C;
    params.f10 = lbl_803E6640 * (lbl_803E6660 * *(f32 *)(obj + 8));
    params.f14 = lbl_803E6640 * (lbl_803E6664 * *(f32 *)(obj + 8));
    objfx_spawnLightPulse(obj, lbl_803E6654 * *(f32 *)(obj + 8), 1, 0, 6, lbl_803E6668, &params);
    params.fc = lbl_803E6640 * (lbl_803E666C * *(f32 *)(obj + 8));
    params.f10 = lbl_803E6640 * (lbl_803E664C * *(f32 *)(obj + 8));
    params.f14 = lbl_803E6640 * (lbl_803E6650 * *(f32 *)(obj + 8));
    objfx_spawnLightPulse(obj, lbl_803E6654 * *(f32 *)(obj + 8), 1, 0, 6, lbl_803E6658, &params);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void worldobj_spawnAsteroidBatch(int obj, int xMin, int xMax, int yMin, int yMax, int count, int dispatchId) {
    s16 rot[3];
    f32 vec[3];
    struct {
        u8 pad0[6];
        s16 f6;
        u8 pad8[4];
        f32 fc;
        f32 f10;
        f32 f14;
    } params;
    int i;
    f32 base;

    for (i = 0, base = lbl_803E665C; i < count; i++) {
        vec[0] = base;
        vec[1] = (f32)(int)randomGetRange(xMin, xMax);
        vec[2] = (f32)(int)randomGetRange(yMin, yMax);
        rot[0] = 0;
        rot[1] = 0;
        rot[2] = (s16)randomGetRange(-0x7fff, 0x7fff);
        mathFn_80021ac8(rot, vec);
        params.fc = vec[0];
        params.f10 = vec[1];
        params.f14 = vec[2];
        params.f6 = 0x64;
        (*(void (*)(int, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(obj, dispatchId, &params, 2, -1, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void worldobj_render(int p1, int p2, int p3, int p4, int p5, s8 visible) {
    int *inner = *(int **)(p1 + 0xb8);
    int modelId = *(s16 *)*(int **)(p1 + 0x4c);

    if (modelId == 0x5f5) {
        objRenderFn_8003b8f4(lbl_803E6678);
        return;
    }
    if (visible == 0) {
        return;
    }
    if (modelId == 0x61e) {
        return;
    }
    switch (modelId) {
    case 0x5de:
        if (*(u8 *)((char *)inner + 0x27d) == 0) {
            objRenderFn_8003b8f4(lbl_803E6678);
        }
        break;
    case 0x5e3:
        if (randomGetRange(0, 0x19) != 0 && *(u8 *)((char *)inner + 0x27d) != 0) {
            GXSetScissor(0x1e0, 0x32, 0x82, 0x96);
            ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6678);
            Camera_ApplyCurrentViewport(p2);
        }
        break;
    case 0x740:
        if (*(u8 *)((char *)inner + 0x27d) != 0 && (u8)fn_8012DDAC() == 0 &&
            (*(int (*)(void))(*(int *)(*gScreenTransitionInterface + 0x14)))() != 0) {
            if (lbl_803DDD34 != 0) {
                lbl_803DDD34 = lbl_803DDD34 - 1;
            } else {
                ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6678);
            }
        } else {
            lbl_803DDD34 = 2;
        }
        break;
    case 0x80f:
        if (*(void **)inner != NULL && fn_8001DB64(*(int *)inner) != 0) {
            queueGlowRender(*(int *)inner);
        }
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6678);
        break;
    case 0x5da:
    case 0x5dc:
    default:
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6678);
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset
