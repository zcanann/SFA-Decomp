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
extern void fn_8001D730(int light, int a, int r, int g, int b, int e, f32 f);
extern void fn_8001D714(int light, f32 a);
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
extern void objfx_spawnMaskedHitEffect(int obj, int a, int b, int c, void *params, f32 scale);
extern void objfx_spawnLightPulse(int obj, int a, int b, int c, void *params, f32 scale, f32 arg2);

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
            fn_8001D730(*(int *)(obj + 0), 0, 0xff, 0xff, 0xff, 0x82, lbl_803E66D4 * *(f32 *)(inner + 0x26c));
            fn_8001D714(*(int *)(obj + 0), lbl_803E66A0);
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
        objfx_spawnMaskedHitEffect(obj, 3, e->f10, e->f11, &params, s * e->fc);
    }
    s = *(f32 *)(obj + 8);
    params.f8 = lbl_803E6644;
    params.fc = lbl_803E6640 * (lbl_803E6648 * s);
    params.f10 = lbl_803E6640 * (lbl_803E664C * s);
    params.f14 = lbl_803E6640 * (lbl_803E6650 * s);
    objfx_spawnLightPulse(obj, 1, 0, 6, &params, lbl_803E6654 * s, lbl_803E6658);
    s = *(f32 *)(obj + 8);
    params.fc = lbl_803E665C;
    params.f10 = lbl_803E6640 * (lbl_803E6660 * s);
    params.f14 = lbl_803E6640 * (lbl_803E6664 * s);
    objfx_spawnLightPulse(obj, 1, 0, 6, &params, lbl_803E6654 * s, lbl_803E6668);
    s = *(f32 *)(obj + 8);
    params.fc = lbl_803E6640 * (lbl_803E666C * s);
    params.f10 = lbl_803E6640 * (lbl_803E664C * s);
    params.f14 = lbl_803E6640 * (lbl_803E6650 * s);
    objfx_spawnLightPulse(obj, 1, 0, 6, &params, lbl_803E6654 * s, lbl_803E6658);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void worldobj_spawnAsteroidBatch(int obj, int xMin, int xMax, int yMin, int yMax, int count, int dispatchId) {
    struct {
        s16 f8;
        s16 fa;
        s16 fc;
        s16 pad_e;
        f32 f10;
        f32 f14;
        f32 f18;
    } dir;
    struct {
        u8 pad0[6];
        s16 f6;
        u8 pad8[4];
        f32 fc;
        f32 f10;
        f32 f14;
    } params;
    int i;
    f32 base = lbl_803E665C;

    for (i = 0; i < count; i++) {
        dir.f10 = base;
        dir.f14 = (f32)(int)randomGetRange(xMin, xMax);
        dir.f18 = (f32)(int)randomGetRange(yMin, yMax);
        dir.f8 = 0;
        dir.fa = 0;
        dir.fc = (s16)randomGetRange(-0x7fff, 0x7fff);
        mathFn_80021ac8(&dir.f8, &dir.f10);
        params.fc = dir.f10;
        params.f10 = dir.f14;
        params.f14 = dir.f18;
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
