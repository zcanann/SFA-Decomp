

#include "ghidra_import.h"
#include "main/objanim.h"

/* Pattern wrappers. */
int ktrex_stateHandlerA00(void) { return 0x0; }
int drshackle_getExtraSize(void) { return 0x20; }
int drshackle_getObjectTypeId(void) { return 0x0; }
void drshackle_release(void) {}
void drshackle_initialise(void) {}
int hightop_defaultStateHandler(void) { return 0x0; }
void hightop_func15(void) {}
int hightop_func14(void) { return 0x0; }
int hightop_func10(void) { return 0x0; }
int hightop_func0E(void) { return 0x1; }

void cagecontrol_free(void) {}
int cagecontrol_getExtraSize(void) { return 0x4; }
int cagecontrol_getObjectTypeId(void) { return 0x0; }
void cagecontrol_hitDetect(void) {}
void cagecontrol_initialise(void) {}
void cagecontrol_release(void) {}
int drakorhoverpad_func0B(void) { return 0x1; }
int drakorhoverpad_func0E(void) { return 0x1; }
int drakorhoverpad_func10(void) { return 0x0; }
void drakorhoverpad_func11(void) {}
int drakorhoverpad_func14(void) { return 0x0; }
void drakorhoverpad_func15(void) {}
int drakorhoverpad_getExtraSize(void) { return 0x17c; }
int drakorhoverpad_getObjectTypeId(void) { return 0x0; }
void drakorhoverpad_hitDetect(void) {}
void drakorhoverpad_initialise(void) {}
void drakorhoverpad_release(void) {}
int drakormissile_getExtraSize(void) { return 0x38; }
int drakormissile_getObjectTypeId(void) { return 0x2; }
void drakormissile_hitDetect(void) {}
void drakormissile_initialise(void) {}
void drakormissile_release(void) {}
int drcagewith_getExtraSize(void) { return 0x34; }
int drcagewith_getObjectTypeId(void) { return 0x0; }
void drcagewith_initialise(void) {}
void drcagewith_release(void) {}
void drcagewith_update(void) {}
int drchimmey_getExtraSize(void) { return 0x18; }
void drcreator_free(void) {}
int drcreator_getExtraSize(void) { return 0x1c; }
int drcreator_getObjectTypeId(void) { return 0x0; }
void drcreator_hitDetect(void) {}
void drcreator_initialise(void) {}
void drcreator_release(void) {}
void drcreator_render(void) {}
int drgenerator_getExtraSize(void) { return 0x19c; }
int drgenerator_getObjectTypeId(void) { return 0x0; }
void drgenerator_initialise(void) {}
void drgenerator_release(void) {}
int drlasercannon_getExtraSize(void) { return 0x1ac; }
int drlasercannon_getObjectTypeId(void) { return 0x0; }
void drlasercannon_initialise(void) {}
void drlasercannon_release(void) {}
void explodeplan_free(void) {}
int explodeplan_getExtraSize(void) { return 0x4; }
int explodeplan_getObjectTypeId(void) { return 0x0; }
void explodeplan_hitDetect(void) {}
void explodeplan_initialise(void) {}
void explodeplan_release(void) {}
int gmmazewell_getExtraSize(void) { return 0x8; }
int hightop_func0B(void) { return 0x1; }
int hightop_getExtraSize(void) { return 0xc4c; }
int hightop_getObjectTypeId(void) { return 0x43; }
void hightop_release(void) {}
int hightop_render2(void) { return 0x0; }
int hightop_setScale(void) { return 0x0; }
int ktfallingrocks_getExtraSize(void) { return 0x0; }
int ktfallingrocks_getObjectTypeId(void) { return 0x0; }
void ktfallingrocks_hitDetect(void) {}
void ktfallingrocks_initialise(void) {}
void ktfallingrocks_release(void) {}
int ktlazerlight_getExtraSize(void) { return 0x14; }
int ktlazerlight_getObjectTypeId(void) { return 0x0; }
void ktlazerlight_hitDetect(void) {}
void ktlazerlight_initialise(void) {}
void ktlazerlight_release(void) {}
void ktlazerlight_render(void) {}
int ktlazerwall_getExtraSize(void) { return 0x14; }
int ktlazerwall_getObjectTypeId(void) { return 0x0; }
void ktlazerwall_hitDetect(void) {}
void ktlazerwall_initialise(void) {}
void ktlazerwall_release(void) {}
void ktrexfloorswitch_free(void) {}
int ktrexfloorswitch_getExtraSize(void) { return 0x14; }
int ktrexfloorswitch_getObjectTypeId(void) { return 0x0; }
void ktrexfloorswitch_hitDetect(void) {}
void ktrexfloorswitch_initialise(void) {}
void ktrexfloorswitch_release(void) {}
void ktrex_func0B(void) {}
int ktrex_getExtraSize(void) { return 0x5a4; }
int ktrex_getObjectTypeId(void) { return 0x49; }
int ktrexlevel_getExtraSize(void) { return 0x4; }
int ktrexlevel_getObjectTypeId(void) { return 0x0; }
void ktrexlevel_hitDetect(void) {}
void ktrexlevel_initialise(void) {}
void ktrexlevel_release(void) {}
void ktrex_release(void) {}
int kytesmum_getExtraSize(void) { return 0x6ec; }
int kytesmum_getObjectTypeId(void) { return 0x43; }
void kytesmum_hitDetect(void) {}
void kytesmum_initialise(void) {}
void kytesmum_release(void) {}

extern u8 framesThisStep;
extern f32 lbl_803E6A3C;
extern f32 lbl_803E6A40;
extern f32 lbl_803E6AA8;
extern f32 lbl_803E6AB4;
extern f32 lbl_803E6AB8;
extern f32 lbl_803E6ABC;
extern f32 lbl_803E6AC0;
extern f32 lbl_803E6AC4;
extern f32 lbl_803E6AC8;
extern f32 lbl_803E6B34;

extern f32 lbl_803E67A0;
extern f32 lbl_803E67B8;
extern f32 lbl_803E6808;
extern f32 lbl_803E6858;
extern f32 lbl_803E6994;
extern f32 lbl_803E6978;
extern f32 lbl_803E69D0;
extern f32 lbl_803E69D8;
extern f32 lbl_803E69E0;
extern f32 lbl_803E69E8;
extern f32 lbl_803E6A44;
extern f32 lbl_803E6B00;
extern f32 lbl_803E6B58;

extern void *gKTRexState;
extern void *gKTRexRuntime;
extern undefined4 *gExpgfxInterface;
extern void ktrex_initialiseStateHandlerTables(void);
extern void objRenderFn_8003b8f4(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, double scale);
extern void ObjGroup_RemoveObject(int obj, int group);
extern void *Obj_GetPlayerObject(void);
extern void ModelLightStruct_free(void *p);
extern void GameBit_Set(int eventId, int value);
extern void Music_Trigger(int trackId, int restart);
extern void Obj_FreeObject(int obj);
extern void mm_free(void *ptr);
extern void storeZeroToFloatParam(void *timer);
extern void **gGameUIInterface;
extern int gmmazewell_clearPendingTriggerCallback(int obj, int unused, u8 *arg);
extern u32 GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);
extern void explodeplan_updateTriggerCallback(void);
extern void firepipe_clearLinkedUpdateFlag(int handle);
extern void ObjLink_DetachChild(int obj, int child);
extern void ObjHits_EnableObject(int obj);
extern void ObjHits_DisableObject(int obj);
extern void *objCreateLight(int v1, int v2);
extern void modelLightStruct_setField50(void *light, int v);
extern void lightVecFn_8001dd88(void *light, f32 x, f32 y, f32 z);
extern void lightSetField2FB(void *handle, int v);
extern int *objFindTexture(int obj, int idx, int p3);
extern void buttonDisable(int index, u32 flags);
extern void **gObjectTriggerInterface;
extern void *gHighTopStateHandlers[];
extern void *gHighTopDefaultStateHandler;

extern int hightop_stateHandler01();
extern int hightop_stateHandler02();
extern int hightop_stateHandler04();
extern int hightop_stateHandler07();
extern int hightop_stateHandler09();
extern int hightop_stateHandler10();

extern void ObjGroup_AddObject(int obj, int group);
extern void drcreator_spawnProjectileCallback(void);
extern void setMatrixFromObjectPos(f32 *mtx, void *desc);
extern void Matrix_TransformPoint(f32 *mtx, double x, double y, double z, f32 *ox, f32 *oy, f32 *oz);
extern f32 lbl_803E6B38;
extern f32 lbl_803E6B3C;
extern f32 lbl_803E6A48;
extern f32 lbl_803DC300;
extern f32 lbl_803DC304;

typedef struct {
    s16 rx;
    s16 ry;
    s16 rz;
    s16 pad;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ObjPosParams;

extern f32 lbl_803E68E8;
extern f32 lbl_803E68EC;
extern f32 lbl_803E6A38;
extern void ObjPath_GetPointWorldPosition(int obj, int idx, f32 *x, f32 *y, f32 *z, int p6);
extern void lightFn_8001d6b0(void *p);

extern f32 lbl_803E6898;
extern f32 lbl_803E68BC;
extern f32 lbl_803E67A4;
extern f32 lbl_803E67A8;
extern int lbl_803DDD40;
extern void setDrawCloudsAndLights(int v);
extern void skyFn_80088c94(int a, int b);
extern void getEnvfxAct(int a, int b, int c, int d);
extern void skyFn_80088e54(int a, f32 b);
extern int drshackle_toggleEventCallback(int obj, int unused, u8 *arg);

extern f32 lbl_803E6A2C;
extern f32 lbl_803E6B30;
extern s16 lbl_803DC310;
extern void seqFn_800394a0(int obj);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void fn_8009A8C8(int obj, f32 v);

extern f32 lbl_803E683C;
extern f32 lbl_803E6840;
extern f32 lbl_803E6844;
extern void *lbl_803DDD50;
extern void *lbl_803DDD48;
extern int lbl_803DC2A0;
extern f32 lbl_803AD1C8[];
extern void **gRomCurveInterface;
extern void **gBaddieControlInterface;
extern void *ObjPath_GetPointModelMtx(int obj, int idx);
extern void mtx44_mult(f32 *dst, f32 *a, f32 *b);
extern void fn_8003B950(f32 *mtx);
extern void Stack_Free(void *p);
extern void Resource_Release(void *p);

extern s16 lbl_803DC328;
extern f32 Vec_xzDistance(f32 *a, f32 *b);
extern int *getTrickyObject(void);
extern int fn_802972A8(void);
extern int dll_2E_func0A(int a, f32 *buf);
extern s16 getAngle(f32 dx, f32 dz);

extern f32 lbl_803E69F0;
extern f32 lbl_803AD208[];
extern void ObjPath_GetPointLocalPosition(int obj, int idx, f32 *x, f32 *y, f32 *z);
extern void ObjHits_RegisterActiveHitVolumeObject(int obj);
extern void objRemoveFromListFn_8002ce88(int obj);
extern int dll_2E_func07(int obj, u8 *arg, char *p, int a, int b);

extern f32 lbl_803E68C0;
extern void lightFn_8001db6c(void *light, int v, f32 f);
extern void modelLightStruct_setColorsA8AC(void *light, int a, int b, int c, int d);
extern void lightDistAttenFn_8001dc38(void *light, f32 a, f32 b);

typedef struct {
    u8 b0 : 1;
    u8 b1 : 1;
    u8 b2 : 1;
    u8 b3 : 1;
    u8 b4 : 1;
    u8 b5 : 1;
    u8 b6 : 1;
    u8 b7 : 1;
} BitFlags8;

#pragma scheduling off
int ktrex_isPlayerInLaneThreatRange(int obj) {
    u8 state = *(u8 *)((char *)gKTRexState + 0x100);
    f32 center;
    f32 lo;
    f32 hi;
    if (state == 0) {
        return 0;
    }
    switch (state) {
    case 1:
    case 2:
        center = *(f32 *)((char *)obj + 0x14);
        lo = (center - lbl_803E683C) - *(f32 *)((char *)lbl_803DDD50 + 0x28);
        hi = (lbl_803E683C + center) - *(f32 *)((char *)lbl_803DDD50 + 0x28);
        if (lo > lbl_803E6840) {
            return 0;
        }
        if (hi >= lbl_803E6840) {
            return 1;
        }
        return 0;
    case 4:
    case 8:
        center = *(f32 *)((char *)obj + 0xc);
        lo = (center - lbl_803E683C) - *(f32 *)((char *)lbl_803DDD50 + 0x24);
        hi = (lbl_803E683C + center) - *(f32 *)((char *)lbl_803DDD50 + 0x24);
        if (lo > lbl_803E6844) {
            return 0;
        }
        if (hi >= lbl_803E6844) {
            return 1;
        }
        return 0;
    }
    return 0;
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int drcagewith_setScale(int obj) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    return p[0x30];
}

void ktfallingrocks_init(int obj) {
    *(int *)((char *)obj + 0xbc) = 0;
}

int drakorhoverpad_setScale(int obj) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    return (p[0x179] >> 2) & 1;
}

int drakorhoverpad_render2(int obj) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    return ((p[0x179] >> 2) & 1) == 0;
}

int ktrex_setScale(int obj) {
    void *p = *(void **)((char *)obj + 0xb8);
    gKTRexRuntime = p;
    return *(s16 *)((char *)p + 0x274);
}

int drshackle_func0B(int obj) {
    int p = *(int *)((char *)obj + 0x4c);
    return *(s8 *)(p + 0x19);
}

void hightop_func11(int obj, int val) {
    u8 v = val;
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    p[0xc43] = v;
}

f32 hightop_func13(int obj, f32 *out) {
    *out = lbl_803E6B34;
    return lbl_803E6AA8;
}

void drakorhoverpad_func12(int obj, f32 *a, int *b) {
    *a = lbl_803E6A3C;
    *b = 0;
}

void hightop_func12(int obj, f32 *a, int *b) {
    *a = lbl_803E6AA8;
    *b = 0;
}

int drakormissile_setScale(int obj) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    return p[0x4] == 1;
}

void drakormissile_render2(int obj) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    if (p[0x4] == 3) {
        p[0x4] = 2;
    }
}

void hightop_modelMtxFn(int obj, f32 *a, f32 *b, f32 *c) {
    f32 *p = *(f32 **)((char *)obj + 0xb8);
    *a = *(f32 *)((char *)p + 0xb6c);
    *b = *(f32 *)((char *)p + 0xb70);
    *c = *(f32 *)((char *)p + 0xb74);
}

void drakorhoverpad_modelMtxFn(int obj, f32 *a, f32 *b, f32 *c) {
    *a = *(f32 *)((char *)obj + 0xc);
    *b = lbl_803E6A40 + *(f32 *)((char *)obj + 0x10);
    *c = *(f32 *)((char *)obj + 0x14);
}

void ktrex_initialise(void) {
    ktrex_initialiseStateHandlerTables();
}

void drgenerator_free(int obj) {
    ObjGroup_RemoveObject(obj, 0x3);
}

void drshackle_free(int obj) {
    ObjGroup_RemoveObject(obj, 0x37);
}

int kytesmum_idleCallback(void) {
    Obj_GetPlayerObject();
    return 0;
}

void ktlazerlight_free(int obj) {
    void *p = *(void **)((char *)obj + 0xb8);
    void *m = *(void **)((char *)p + 0x4);
    if (m != 0) {
        ModelLightStruct_free(m);
    }
}

void ktfallingrocks_free(u8 *obj) {
    ((void (*)(u8 *))(*(u32 *)(*gExpgfxInterface + 0x18)))(obj);
}

void gmmazewell_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6978);
}

void cagecontrol_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E69D0);
    }
}

void explodeplan_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E69D8);
    }
}

void drchimmey_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E69E0);
    }
}

void drgenerator_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6B58);
    }
}

void ktrexfloorswitch_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6858);
    }
}

void ktrexlevel_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E67A0);
    }
}

void kytesmum_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6994);
    }
}

f32 drakorhoverpad_func13(int obj, f32 *out) {
    *out = lbl_803E6A44;
    return lbl_803E6A3C;
}

void gmmazewell_free(void) {
    GameBit_Set(0xefc, 0);
    Music_Trigger(0x36, 0);
}

void kytesmum_free(int obj) {
    int p = *(int *)((char *)obj + 0x4c);
    if (*(s8 *)(p + 0x19) != 0) {
        ObjGroup_RemoveObject(obj, 0x3);
    }
}

void drakorhoverpad_free(int obj) {
    ObjGroup_RemoveObject(obj, 0x46);
    ObjGroup_RemoveObject(obj, 0xa);
}

void drakormissile_modelMtxFn(int obj) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    p[0x5] |= 1;
    if (p[0x4] == 1) {
        Obj_FreeObject(obj);
    }
}

void ktlazerwall_free(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    void *m = *(void **)(p + 0x10);
    if (m != 0) {
        mm_free(m);
        *(void **)(p + 0x10) = 0;
    }
}

void ktrexlevel_clearPathGameBits(void) {
    GameBit_Set(0x54a, 0);
    GameBit_Set(0x54e, 0);
    GameBit_Set(0x552, 0);
    GameBit_Set(0x556, 0);
}

void hightop_free(int obj) {
    void *ui;
    ObjGroup_RemoveObject(obj, 0x26);
    ObjGroup_RemoveObject(obj, 0xa);
    ui = *gGameUIInterface;
    (*(void (**)(void *))((char *)ui + 0x60))(ui);
}

void drchimmey_init(int obj, char *arg) {
    int p;
    *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
    p = *(int *)((char *)obj + 0xb8);
    *(f32 *)(p + 0xc) = lbl_803E69E8;
    *(s16 *)(p + 0x14) = *(s16 *)(arg + 0x1e);
    *(u8 *)(p + 0x16) = 3;
    storeZeroToFloatParam((void *)(p + 0x10));
}

void drakormissile_free(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    void *m = *(void **)p;
    if (m != 0) {
        ModelLightStruct_free(m);
        *(void **)p = 0;
    }
    ObjGroup_RemoveObject(obj, 0x2);
}

void gmmazewell_init(int obj) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    p[0] = 0;
    GameBit_Set(0xefc, 1);
    Music_Trigger(0x36, 1);
    *(void **)((char *)obj + 0xbc) = (void *)gmmazewell_clearPendingTriggerCallback;
}

void drakorhoverpad_func17(int obj, int sel, int *out) {
    switch (sel) {
    case 2:
        *out = *(s16 *)obj;
        break;
    case 3:
        *out = 0x1000;
        break;
    case 4:
        *out = 1;
        break;
    }
}

int hightop_stateHandler00(int obj) {
    int p = *(int *)((char *)obj + 0x4c);
    if (*(s8 *)(p + 0x19) != 0) {
        return 0xa;
    }
    if (GameBit_Get(0x631) != 0) {
        return 8;
    }
    return 5;
}

int hightop_stateHandler06(int obj, u8 *p2) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    if ((s8)p2[0x27a] != 0) {
        p[0x9fd] |= 1;
    }
    if (GameBit_Get(0x632) != 0) {
        return 8;
    }
    return 2;
}

void ktrexlevel_free(void) {
    GameBit_Set(0xefd, 0);
    GameBit_Set(0xcd1, 0);
    GameBit_Set(0xccd, 0);
    GameBit_Set(0xccf, 0);
    GameBit_Set(0xcd0, 0);
    GameBit_Set(0xedb, 0);
    GameBit_Set(0xcbb, 0);
}

void explodeplan_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    *(void **)((char *)obj + 0xbc) = (void *)explodeplan_updateTriggerCallback;
    if (GameBit_Get(*(s16 *)(arg + 0x1e)) != 0) {
        ((BitFlags8 *)(p + 0x4))->b2 = 1;
        *(int *)p = 2;
    } else {
        *(int *)p = 0;
    }
}

void drlasercannon_free(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    if (*(void **)(p + 0x194) != 0) {
        firepipe_clearLinkedUpdateFlag((int)*(void **)(p + 0x194));
        ObjLink_DetachChild(obj, (int)*(void **)(p + 0x194));
    }
    if (*(void **)(p + 0x190) != 0) {
        Obj_FreeObject((int)*(void **)(p + 0x190));
    }
    ObjGroup_RemoveObject(obj, 0x3);
}

void cagecontrol_init(int obj, char *arg) {
    ObjHits_EnableObject(obj);
    if (GameBit_Get(*(s16 *)(arg + 0x1e)) != 0) {
        *(s16 *)((char *)obj + 0x6) |= 0x4000;
        ObjHits_DisableObject(obj);
    }
    *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
}

void ktlazerlight_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    *(void **)(p + 0x4) = objCreateLight(0, 1);
    if (*(void **)(p + 0x4) != 0) {
        modelLightStruct_setField50(*(void **)(p + 0x4), 2);
        lightVecFn_8001dd88(*(void **)(p + 0x4), *(f32 *)(arg + 0x8), *(f32 *)(arg + 0xc), *(f32 *)(arg + 0x10));
        lightSetField2FB(*(void **)(p + 0x4), 1);
    }
}

void drcagewith_free(int obj, int arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    char *x = *(char **)p;
    if (x != 0 && arg == 0 && *(void **)(x + 0x50) != 0) {
        char *y = *(char **)(p + 0x4);
        if (y != 0) {
            *(int *)(y + 0xf4) = 0;
        }
        *(int *)(*(char **)p + 0xf4) = 0;
        Obj_FreeObject(*(int *)p);
    }
    ObjGroup_RemoveObject(obj, 0x18);
}

void hightop_func0F(int obj, f32 *ox, f32 *oy, f32 *oz) {
    int *player;
    ObjPosParams pos;
    f32 mtx[16];
    player = Obj_GetPlayerObject();
    pos.x = *(f32 *)((char *)player + 0xc);
    pos.y = *(f32 *)((char *)player + 0x10);
    pos.z = *(f32 *)((char *)player + 0x14);
    pos.rx = *(s16 *)player;
    pos.ry = *(s16 *)((char *)player + 0x2);
    pos.rz = *(s16 *)((char *)player + 0x4);
    pos.scale = lbl_803E6AB8;
    setMatrixFromObjectPos(mtx, &pos);
    Matrix_TransformPoint(mtx, lbl_803E6AA8, lbl_803E6B38, lbl_803E6B3C, ox, oy, oz);
}

void drakorhoverpad_func0F(int obj, f32 *ox, f32 *oy, f32 *oz) {
    ObjPosParams pos;
    f32 mtx[16];
    int *src = Obj_GetPlayerObject();
    if (src == 0) {
        src = (int *)obj;
    }
    pos.x = *(f32 *)((char *)src + 0xc);
    pos.y = *(f32 *)((char *)src + 0x10);
    pos.z = *(f32 *)((char *)src + 0x14);
    pos.rx = *(s16 *)src;
    pos.ry = *(s16 *)((char *)src + 0x2);
    pos.rz = *(s16 *)((char *)src + 0x4);
    pos.scale = lbl_803E6A48;
    setMatrixFromObjectPos(mtx, &pos);
    Matrix_TransformPoint(mtx, lbl_803E6A3C, lbl_803DC300, lbl_803DC304, ox, oy, oz);
}

void drcreator_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)arg[0x1e] << 8);
    *(s16 *)(p + 0x4) = *(s16 *)(arg + 0x18);
    *(s16 *)(p + 0x6) = *(s16 *)(arg + 0x1c);
    *(s16 *)(p + 0x8) = (s16)randomGetRange(0, *(s16 *)(p + 0x6));
    *(s16 *)(p + 0xa) = (s8)arg[0x1f];
    *(int *)p = (u8)arg[0x20];
    ((BitFlags8 *)(p + 0x18))->b0 = 1;
    GameBit_Set(0x5dd, 0);
    *(void **)((char *)obj + 0xbc) = (void *)drcreator_spawnProjectileCallback;
}

void ktrexlevel_updatePathGameBits(void) {
    if (GameBit_Get(0x55a) != 0) {
        GameBit_Set(0x54a, 2);
        GameBit_Set(0x54e, 2);
        GameBit_Set(0x552, 1);
        GameBit_Set(0x556, 1);
    } else if (GameBit_Get(0x55b) != 0) {
        GameBit_Set(0x54a, 1);
        GameBit_Set(0x54e, 1);
        GameBit_Set(0x552, 2);
        GameBit_Set(0x556, 2);
    }
}

int gmmazewell_clearPendingTriggerCallback(int obj, int unused, u8 *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    int i;
    for (i = 0; i < arg[0x8b]; i++) {
        if (arg[i + 0x81] == 1 && *(int *)(p + 0x4) != -1) {
            (*(void (**)(int, int, int, int))((char *)*gGameUIInterface + 0x38))(*(int *)(p + 0x4), 0x14, 0x8c, 0);
            *(int *)(p + 0x4) = -1;
        }
    }
    return 0;
}

int kytesmum_spawnInteractionCallback(int obj) {
    Obj_GetPlayerObject();
    if ((*(u8 *)((char *)obj + 0xaf) & 1) != 0) {
        buttonDisable(0, 0x100);
        if ((*(int (**)(void *))((char *)*gGameUIInterface + 0x1c))(*gGameUIInterface) == 0) {
            (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(0, obj, -1);
        }
        return 0;
    }
    return 0;
}

int drgenerator_eventCallback(int obj, int unused, u8 *arg) {
    int i;
    for (i = 0; i < arg[0x8b]; i++) {
        if (arg[i + 0x81] == 1) {
            int *t = objFindTexture(obj, 0, 0);
            if (t != 0) {
                *t = 0;
            }
        }
    }
    return 0;
}

int hightop_stateHandler03(int obj, u8 *p2) {
    int p = *(int *)((char *)obj + 0xb8);
    f32 zero = lbl_803E6AA8;
    *(f32 *)(p2 + 0x294) = zero;
    *(f32 *)(p2 + 0x284) = zero;
    *(f32 *)(p2 + 0x280) = zero;
    *(f32 *)((char *)obj + 0x24) = zero;
    *(f32 *)((char *)obj + 0x28) = zero;
    *(f32 *)((char *)obj + 0x2c) = zero;
    if ((s8)p2[0x27a] != 0) {
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x78);
        if (*(u32 *)(p + 0xc3c) == 4) {
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E6AA8, 0);
            *(f32 *)(p2 + 0x2a0) = lbl_803E6AC8;
        } else {
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E6AA8, 0);
            *(f32 *)(p2 + 0x2a0) = lbl_803E6AC8;
        }
    }
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E6B00) {
        return *(int *)(p + 0xc3c) + 1;
    }
    return 0;
}

int hightop_stateHandler05(int obj, u8 *p2) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    if ((s8)p2[0x27a] != 0) {
        ((BitFlags8 *)(p + 0xc49))->b1 = 0;
        p[0xc4b] = 0xa;
    }
    switch ((s8)p[0xc4b]) {
    case 1:
        if (GameBit_Get(0x62c) != 0) {
            p[0xc4b] = 2;
        }
        break;
    case 0xa:
        if (GameBit_Get(0x630) != 0) {
            return 7;
        }
        break;
    }
    return 0;
}

int ktrex_stateHandlerB00(int obj, u8 *p2) {
    if ((s8)p2[0x27a] != 0) {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E67B8, 0);
    }
    *(f32 *)(p2 + 0x2a0) = lbl_803E6808;
    return 0;
}

void ktfallingrocks_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
    }
}

void cagecontrol_update(int obj) {
    int p = *(int *)((char *)obj + 0x4c);
    if (GameBit_Get(*(s16 *)(p + 0x1e)) != 0) {
        *(s16 *)((char *)obj + 0x6) |= 0x4000;
        ObjHits_DisableObject(obj);
    } else {
        *(s16 *)((char *)obj + 0x6) &= ~0x4000;
        ObjHits_EnableObject(obj);
    }
}

void drakorhoverpad_resetPendingMotion(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    if (((BitFlags8 *)(p + 0x179))->b6 != 0) {
        ((BitFlags8 *)(p + 0x179))->b6 = 0;
        *(f32 *)p = lbl_803E6A38;
    }
}

int drchimmey_countdownCallback(int obj, int dec) {
    s8 *p = (s8 *)*(char **)((char *)obj + 0xb8);
    p[0x16] -= dec;
    return p[0x16] == 0;
}

int drcagewith_toggleRopeStateCallback(int obj, int unused, u8 *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    int i;
    for (i = 0; i < arg[0x8b]; i++) {
        if (arg[i + 0x81] == 1) {
            ((BitFlags8 *)(p + 0x31))->b1 ^= 1;
        }
    }
    return 0;
}

void ktrex_hitDetect(int obj) {
    f32 z, y, x;
    if (*(void **)((char *)gKTRexState + 0x178) != 0) {
        ObjPath_GetPointWorldPosition(obj, 5, &x, &y, &z, 0);
        lightVecFn_8001dd88(*(void **)((char *)gKTRexState + 0x178), x, y, z);
        lightFn_8001d6b0(*(void **)((char *)gKTRexState + 0x178));
    }
}

void drlasercannon_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    char *p = *(char **)((char *)obj + 0xb8);
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E68E8);
        ObjPath_GetPointWorldPosition((int)obj, 0, (f32 *)(p + 0x10), (f32 *)(p + 0x14), (f32 *)(p + 0x18), 0);
        *(f32 *)(p + 0x14) = *(f32 *)(p + 0x14) - lbl_803E68EC;
    }
}

void ktrexlevel_init(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    setDrawCloudsAndLights(0);
    GameBit_Set(0x572, 0);
    GameBit_Set(0x56e, 1);
    GameBit_Set(0x566, 1);
    GameBit_Set(0x569, 1);
    *(f32 *)p = lbl_803E67A8;
    GameBit_Set(0x55a, 1);
    GameBit_Set(0x54a, 2);
    GameBit_Set(0x54e, 2);
    GameBit_Set(0x552, 1);
    GameBit_Set(0x556, 1);
    *(int *)((char *)obj + 0xf4) = 0;
    GameBit_Set(0xefd, 1);
}

void ktrexlevel_update(int obj) {
    if (*(int *)((char *)obj + 0xf4) == 0) {
        skyFn_80088c94(7, 1);
        getEnvfxAct(obj, obj, 0x18f, 0);
        getEnvfxAct(obj, obj, 0x18e, 0);
        getEnvfxAct(obj, obj, 0x190, 0);
        skyFn_80088e54(1, lbl_803E67A4);
        GameBit_Set(0x55e, 1);
        *(int *)((char *)obj + 0xf4) = 1;
    }
    lbl_803DDD40 = GameBit_Get(0x572);
}

void ktlazerwall_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
    *(f32 *)(p + 0x4) = lbl_803E6898;
    *(f32 *)(p + 0xc) = lbl_803E68BC * (f32)(int)randomGetRange(0x50, 0x78);
    if (randomGetRange(0, 1) != 0) {
        *(f32 *)(p + 0xc) = -*(f32 *)(p + 0xc);
    }
}

void drshackle_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    ObjGroup_AddObject(obj, 0x37);
    ((BitFlags8 *)(p + 0x1a))->b0 = (GameBit_Get(*(s16 *)(arg + 0x1e)) == 0);
    *(u8 *)(p + 0x1b) = (s8)arg[0x18] % 2;
    *(void **)((char *)obj + 0xbc) = (void *)drshackle_toggleEventCallback;
    if (*(s16 *)(arg + 0x1c) == 1) {
        *(int *)(p + 0x14) = 2;
        *(u8 *)(p + 0x1c) = 1 - *(u8 *)(p + 0x1b);
    } else {
        *(int *)(p + 0x14) = 1;
    }
}

int drshackle_toggleEventCallback(int obj, int unused, u8 *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    void *q = *(void **)p;
    int i;
    if (q != 0) {
        *(f32 *)((char *)q + 0xc) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)q + 0x10) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)q + 0x14) = *(f32 *)((char *)obj + 0x14);
    }
    for (i = 0; i < arg[0x8b]; i++) {
        switch (arg[i + 0x81]) {
        case 1:
            ((BitFlags8 *)(p + 0x1a))->b0 = 0;
            break;
        case 2:
            ((BitFlags8 *)(p + 0x1a))->b0 = 1;
            break;
        }
    }
    return 0;
}

int hightop_interactionCallback(int obj) {
    char *p;
    seqFn_800394a0(obj);
    p = *(char **)((char *)obj + 0xb8);
    *(u8 *)(p + 0x9fd) &= ~1;
    ((BitFlags8 *)(p + 0xc49))->b4 = 0;
    ((BitFlags8 *)(p + 0xc49))->b6 = 1;
    if ((s8)p[0xc4b] == 0) {
        ((BitFlags8 *)(p + 0xc4a))->b0 = 1;
    }
    return 0;
}

void drshackle_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    int i;
    int *ptr;
    if (((BitFlags8 *)(p + 0x1a))->b0 == 0 && visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6A2C);
        ptr = (int *)p;
        for (i = 0; i < *(int *)(p + 0x14); i++) {
            int *entry = *(int **)ptr;
            if (entry != 0) {
                ObjPath_GetPointWorldPosition((int)obj, p[i + 0x1b], (f32 *)((char *)entry + 0xc), (f32 *)((char *)entry + 0x10), (f32 *)((char *)entry + 0x14), 0);
            }
            ptr++;
        }
    }
}

void hightop_playMovementSfx(int obj, int p2, int p3) {
    int flags = *(int *)((char *)p3 + 0x314);
    int idx;
    if ((flags & 0x81) != 0) {
        if (flags & 1) {
            idx = 0;
        }
        if (flags & 0x80) {
            idx = 1;
        }
        Sfx_PlayFromObject(obj, (u16)(&lbl_803DC310)[idx]);
    }
    if (*(int *)((char *)p3 + 0x314) & 0x100) {
        fn_8009A8C8(obj, lbl_803E6B30);
        Sfx_PlayFromObject(obj, (u16)lbl_803DC310);
    }
}

void drakorhoverpad_func16(int obj, f32 scale) {
    f32 *mtx;
    ObjPosParams pos;
    mtx = (f32 *)ObjPath_GetPointModelMtx(obj, 0);
    pos.x = lbl_803E6A3C;
    pos.y = lbl_803E6A40;
    pos.z = lbl_803E6A3C;
    pos.rx = 0;
    pos.ry = 0;
    pos.rz = 0;
    pos.scale = scale / *(f32 *)(*(int *)((char *)obj + 0x50) + 0x4);
    setMatrixFromObjectPos(lbl_803AD1C8, &pos);
    mtx44_mult(lbl_803AD1C8, mtx, lbl_803AD1C8);
    fn_8003B950(lbl_803AD1C8);
}

void ktrexfloorswitch_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    int q;
    int r;
    *(s16 *)obj = (s16)(((u8 *)arg)[0x18] << 8);
    *(f32 *)(p + 0x8) = (f32)(u32)((u8 *)arg)[0x19];
    *(int *)((char *)obj + 0xf4) = 1;
    *(int *)((char *)obj + 0xf8) = 1;
    q = *(int *)((char *)obj + 0x4c);
    r = (*(int (**)(int, int, int, f32, f32, f32))((char *)*gRomCurveInterface + 0x14))((int)&lbl_803DC2A0, 1, 0, *(f32 *)(q + 0x8), *(f32 *)(q + 0xc), *(f32 *)(q + 0x10));
    if (r != -1) {
        r = (*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(r);
        if (r != 0) {
            *(f32 *)((char *)obj + 0xc) = *(f32 *)(r + 0x8);
            *(f32 *)((char *)obj + 0x14) = *(f32 *)(r + 0x10);
        }
    }
}

void ktrex_free(int obj) {
    int i;
    gKTRexRuntime = *(void **)((char *)obj + 0xb8);
    ObjGroup_RemoveObject(obj, 0x3);
    (*(void (**)(int, void *, int))((char *)*gBaddieControlInterface + 0x40))(obj, gKTRexRuntime, 0);
    Stack_Free(*(void **)gKTRexState);
    if (lbl_803DDD48 != 0) {
        Resource_Release(lbl_803DDD48);
    }
    if (*(void **)((char *)gKTRexState + 0x178) != 0) {
        ModelLightStruct_free(*(void **)((char *)gKTRexState + 0x178));
    }
    for (i = 0; i < 5; i++) {
        void *m = *(void **)((char *)gKTRexState + i * 4 + 0x17c);
        if (m != 0) {
            mm_free(m);
        }
    }
    lbl_803DDD48 = 0;
    Music_Trigger(0x28, 0);
    Music_Trigger(0x93, 0);
    Music_Trigger(0x94, 0);
}

int kytesmum_updateInteractionRangeCallback(int obj, int unused, u8 *arg) {
    int *player = Obj_GetPlayerObject();
    int p = *(int *)((char *)obj + 0x4c);
    f32 dist;
    ObjHits_DisableObject(obj);
    dist = Vec_xzDistance((f32 *)((char *)player + 0x18), (f32 *)((char *)obj + 0x18));
    if (dist < (f32)*(s16 *)(p + 0x1a)) {
        arg[0x90] |= 4;
    } else {
        arg[0x90] &= ~4;
    }
    return 0;
}

int drlasercannon_getTrackedTarget(int obj, int *arg) {
    int *tricky = getTrickyObject();
    void *player;
    void *r;
    int t;
    if (tricky != 0 && arg != 0 &&
        (u8)(*(int (**)(int *))((char *)*(void **)*(void **)((char *)tricky + 0x68) + 0x40))(tricky)) {
        t = *arg - framesThisStep;
        *arg = t;
        if (t < 0) {
            (*(void (**)(int *, int, int))((char *)*(void **)*(void **)((char *)tricky + 0x68) + 0x34))(tricky, 0, 0);
            *arg = 0x258;
        }
        return (int)tricky;
    }
    player = Obj_GetPlayerObject();
    if (player != 0) {
        r = (void *)fn_802972A8();
        if (r != 0 && (*(u16 *)((char *)r + 0xb0) & 0x1000) == 0) {
            return (int)r;
        }
        if ((*(u16 *)((char *)player + 0xb0) & 0x1000) == 0) {
            return (int)player;
        }
    }
    return 0;
}

void hightop_getLookTargetYaw(int obj, int mode, int *out) {
    f32 buf[6];
    char *p;
    switch (mode) {
    case 2:
        if (dll_2E_func0A(0x11, buf) != 0) {
            *out = getAngle(buf[3] - *(f32 *)((char *)obj + 0xc), buf[5] - *(f32 *)((char *)obj + 0x14)) + lbl_803DC328;
            p = *(char **)((char *)obj + 0xb8);
            *(f32 *)(p + 0xc1c) = buf[3];
            *(f32 *)(p + 0xc20) = buf[4];
            *(f32 *)(p + 0xc24) = buf[5];
        } else {
            *out = *(s16 *)obj + 0x4000;
        }
        break;
    case 3:
        *out = 1;
        break;
    case 4:
        *out = 0;
        break;
    }
}

void hightop_renderGroundMarker(int obj, f32 scale) {
    f32 *mtx;
    f32 lx, ly, lz;
    ObjPosParams pos;
    mtx = (f32 *)ObjPath_GetPointModelMtx(obj, 2);
    ObjPath_GetPointLocalPosition(obj, 2, &lx, &ly, &lz);
    pos.x = lx;
    pos.y = ly;
    pos.z = lz;
    pos.rx = -0x8000;
    pos.ry = 0;
    pos.rz = 0;
    pos.scale = scale / *(f32 *)(*(int *)((char *)obj + 0x50) + 0x4);
    setMatrixFromObjectPos(lbl_803AD208, &pos);
    mtx44_mult(lbl_803AD208, mtx, lbl_803AD208);
    fn_8003B950(lbl_803AD208);
}

void drcagewith_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    char *p = *(char **)((char *)obj + 0xb8);
    int *b;
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E69F0);
        if (*(int **)p != 0) {
            ObjPath_GetPointWorldPosition((int)obj, 0, (f32 *)(*(int *)p + 0xc), (f32 *)(*(int *)p + 0x10), (f32 *)(*(int *)p + 0x14), 0);
            objRenderFn_8003b8f4(*(void **)p, p2, p3, p4, p5, (double)lbl_803E69F0);
            b = *(int **)(p + 0x4);
            if (b != 0) {
                *(s16 *)((char *)b + 0x2) = *(s16 *)(*(int *)p + 0x2);
                *(s16 *)((char *)b + 0x4) = *(s16 *)(*(int *)p + 0x4);
                ObjPath_GetPointWorldPosition(*(int *)p, 0, (f32 *)((char *)b + 0xc), (f32 *)((char *)b + 0x10), (f32 *)((char *)b + 0x14), 0);
                objRenderFn_8003b8f4(b, p2, p3, p4, p5, (double)lbl_803E69F0);
            }
        }
    }
}

int kytesmum_animEventCallback(int obj, int unused, u8 *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    int q;
    int i;
    int r;
    Obj_GetPlayerObject();
    q = *(int *)((char *)obj + 0x4c);
    ObjHits_EnableObject(obj);
    ObjHits_RegisterActiveHitVolumeObject(obj);
    for (i = 0; i < arg[0x8b]; i++) {
        if (arg[i + 0x81] == 1 && *(s8 *)(q + 0x19) != 0) {
            objRemoveFromListFn_8002ce88(obj);
            ObjHits_DisableObject(obj);
            *(s16 *)((char *)obj + 0x6) |= 0x4000;
        }
    }
    r = *(int *)(p + 0x6dc);
    return !!dll_2E_func07(obj, arg, p, *(s16 *)(r + 0x4), *(s16 *)(r + 0x4));
}

int ktrex_shouldAdvanceArenaPhase(void) {
    int *s = gKTRexState;
    int r6;
    u8 a;
    u8 b;
    r6 = *(u16 *)((char *)s + 0xfa) & 1;
    a = *(u8 *)((char *)s + 0xfe);
    b = *(u8 *)((char *)s + 0xff);
    if ((a & b) != 0) {
        if (r6 != 0) {
            if (*(f32 *)((char *)s + 0x8) < *(f32 *)((char *)s + 0xf4)) {
                return 1;
            }
            return 0;
        }
        if (*(f32 *)((char *)s + 0x8) > *(f32 *)((char *)s + 0xf4)) {
            return 1;
        }
        return 0;
    }
    if (r6 != 0) {
        if (a == 8 && (b & 1)) {
            return 1;
        }
        if (a == 2 && (b & 8)) {
            return 1;
        }
        if (a == 4 && (b & 2)) {
            return 1;
        }
        if (a == 1 && (b & 4)) {
            return 1;
        }
        return 0;
    }
    if (a == 1 && (b & 8)) {
        return 1;
    }
    if (a == 4 && (b & 1)) {
        return 1;
    }
    if (a == 2 && (b & 4)) {
        return 1;
    }
    if (a == 8 && (b & 2)) {
        return 1;
    }
    return 0;
}

void ktlazerlight_update(int obj) {
    int q = *(int *)((char *)obj + 0x4c);
    char *p = *(char **)((char *)obj + 0xb8);
    s16 v;
    void *light = *(void **)(p + 0x4);
    v = (s16)GameBit_Get(*(s16 *)(q + 0x1a));
    if (v >= 1 || GameBit_Get(*(s16 *)(q + 0x1c)) != 0) {
        if (v == 0) {
            v = 0x10;
        }
        if (light != 0) {
            lightFn_8001db6c(light, 1, lbl_803E68C0);
            modelLightStruct_setColorsA8AC(light, 0x64, 0x6e, 0xff, 0xff);
            lightDistAttenFn_8001dc38(*(void **)(p + 0x4), (f32)(v * 0x1a), (f32)(v * 0x1a + 0x14));
        }
    } else {
        if (light != 0) {
            lightFn_8001db6c(light, 0, lbl_803E68C0);
        }
    }
}

void explodeplan_update(int obj) {
    int q = *(int *)((char *)obj + 0x4c);
    char *p = *(char **)((char *)obj + 0xb8);
    if (((BitFlags8 *)(p + 0x4))->b1 != 0) {
        return;
    }
    if (*(int *)p == 0 && GameBit_Get(*(s16 *)(q + 0x1e)) != 0) {
        ((BitFlags8 *)(p + 0x4))->b1 = 1;
        *(int *)p = 2;
    }
    if (((BitFlags8 *)(p + 0x4))->b2 != 0) {
        ((BitFlags8 *)(p + 0x4))->b1 = 1;
        (*(void (**)(int, int))((char *)*gObjectTriggerInterface + 0x54))(obj, 0x76c);
        if (GameBit_Get(0x9f3) != 0) {
            (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(*(int *)p, obj, 0x60);
        } else {
            (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(*(int *)p, obj, 0x70);
        }
    } else {
        (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(*(int *)p, obj, -1);
    }
}

#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler08(int obj, u8 *p2) {
    int *state = *(int **)((char *)obj + 0xb8);
    if ((s8)p2[0x27a] != 0) {
        f32 zero;
        *(f32 *)((char *)state + 0xc30) = lbl_803E6AB4;
        zero = lbl_803E6AA8;
        *(f32 *)(p2 + 0x294) = zero;
        *(f32 *)(p2 + 0x284) = zero;
        *(f32 *)(p2 + 0x280) = zero;
        *(f32 *)((char *)obj + 0x24) = zero;
        *(f32 *)((char *)obj + 0x28) = zero;
        *(f32 *)((char *)obj + 0x2c) = zero;
    }
    if ((s8)p2[0x346] != 0) {
        s16 cur = *(s16 *)((char *)obj + 0xa0);
        switch (cur) {
        case 10:
            if (*(f32 *)(p2 + 0x2a0) > lbl_803E6AA8) {
                ObjAnim_SetCurrentMove(obj, 5, lbl_803E6AA8, 0);
            } else {
                return 8;
            }
            break;
        case 5:
            if (*(f32 *)((char *)state + 0xc30) < lbl_803E6AA8) {
                ObjAnim_SetCurrentMove(obj, 10, lbl_803E6AB8, 0);
                *(f32 *)(p2 + 0x2a0) = lbl_803E6ABC;
            }
            break;
        default:
            ObjAnim_SetCurrentMove(obj, 10, lbl_803E6AA8, 0);
            *(f32 *)(p2 + 0x2a0) = lbl_803E6AC0;
            break;
        }
    }
    if (*(s16 *)((char *)obj + 0xa0) == 10) {
        if (*(f32 *)(p2 + 0x2a0) < lbl_803E6AA8) {
            if (*(f32 *)((char *)obj + 0x98) < lbl_803E6AC4) {
                ObjAnim_SetCurrentMove(obj, 0, lbl_803E6AA8, 0);
                *(f32 *)(p2 + 0x2a0) = lbl_803E6AC8;
                return 8;
            }
        }
    }
    *(f32 *)((char *)state + 0xc30) -= (f32)(u32)framesThisStep;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_initialise(void) {
    void **t = gHighTopStateHandlers;
    t[0] = (void *)hightop_stateHandler00;
    t[1] = (void *)hightop_stateHandler01;
    t[2] = (void *)hightop_stateHandler02;
    t[3] = (void *)hightop_stateHandler03;
    t[4] = (void *)hightop_stateHandler04;
    t[5] = (void *)hightop_stateHandler05;
    t[6] = (void *)hightop_stateHandler06;
    t[7] = (void *)hightop_stateHandler07;
    t[8] = (void *)hightop_stateHandler08;
    t[9] = (void *)hightop_stateHandler09;
    t[10] = (void *)hightop_stateHandler10;
    gHighTopDefaultStateHandler = (void *)hightop_defaultStateHandler;
}
#pragma peephole reset
#pragma scheduling reset
