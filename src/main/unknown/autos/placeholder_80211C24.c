

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
extern int drcreator_spawnProjectileCallback(int obj, int unused, u8 *arg);
extern char sDrCreatorTimeFormat[];
extern void fn_80137948(char *fmt, ...);
extern f32 lbl_803E69A8;
extern void ktrexfloorswitch_spawnEnergyArc(int obj, f32 scale, int b);
extern f32 lbl_803E68B8;
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
extern void ObjPath_GetPointWorldPositionArray(int obj, int idx, int count, f32 *out);
extern void dll_2E_func06(int obj, void *p, int v);
extern int lbl_8032AB48[];
extern s16 lbl_8032A730[];
extern u8 lbl_803DC968;
extern void **gMapEventInterface;
extern int getCurMapLayer(void);
extern void saveFileStruct_unlockCheat(int v);
typedef struct { s16 v[9]; } HtInitData;
extern HtInitData lbl_802C2590;
extern HtInitData lbl_802C25A4;
extern int lbl_803E6AA0;
extern void **gPathControlInterface;
extern int lbl_803DC318;
extern f32 lbl_803E6B4C;
extern f32 lbl_803E6B50;
extern f32 lbl_803E6B54;
extern int lbl_803DC320;
extern void dll_2E_func05(int obj, void *p, int a, int b, int c);
extern void dll_2E_func08(void *p, int a, int b);
extern void dll_2E_func09(void *p, void *a, void *b, int c);
extern f32 lbl_803E69C0;
extern f32 lbl_803E69C4;
extern f32 lbl_803E69C8;
extern f32 lbl_803E69BC;
extern f32 lbl_803E69B8;
extern f32 sin(f32);
extern f32 fn_80293E80(f32);
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
extern int *ObjGroup_GetObjects(int group, int *count);
extern f32 lbl_803E6B68;
extern f32 lbl_803E6B6C;
extern f32 lbl_803E6964;
extern int *Obj_GetActiveModel(void);
extern int fn_8001DB64(void);
extern void queueGlowRender(void *p);
extern f32 lbl_803E6A30;
extern int Sfx_IsPlayingFromObjectChannel(int obj, int ch);
extern void PSVECSubtract(f32 *a, f32 *b, f32 *out);
extern f32 PSVECMag(f32 *v);

extern int fn_80080150(void *timer);
extern void s16toFloat(void *timer, int v);
extern int timerCountDown(void *timer);
extern void objRenderFn_80041018(int obj);
extern f32 lbl_803E69E4;
extern f32 lbl_803E6A18;
extern f32 lbl_803E6A1C;
extern f32 lbl_803E695C;
extern f32 timeDelta;
extern f32 lbl_803E68B0;
extern f32 lbl_803E68B4;
extern void renderFn_8008f904(void *p);
extern int ObjHits_GetPriorityHitWithPosition(int obj, void *a, int b, int *c, f32 *x, f32 *y, f32 *z);
extern void fn_80221E94(int obj, f32 *p, f32 v);
extern void spawnExplosion(int obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern int ObjGroup_FindNearestObject(int group, int obj, void *out);
extern void timer_addDuration(int obj, s16 dur);
extern void **gPartfxInterface;
extern f32 lbl_803E6B5C;
extern f32 lbl_803E6B60;
extern f32 lbl_803E6B64;
extern int lbl_802C2578[];
extern int lbl_802C2584[];
extern int lbl_8032A7FC[];
extern int ObjTrigger_IsSet(int obj);
extern void saveGame_saveObjectPos(int obj);
extern int objGetAnimState80A(int *obj);
extern void ObjHits_SetHitVolumeSlot(int obj, int a, int b, int c);
extern f32 lbl_803E6988;
extern f32 lbl_803E698C;
extern f32 lbl_803E6990;
extern u8 lbl_8032A7C0[];
extern int lbl_803DC2C8;
extern int lbl_803DC2D0;
extern f32 lbl_803E699C;
extern void **gPlayerInterface;
extern f32 lbl_803E690C;
extern f32 lbl_803E6920;
extern f32 lbl_803E6938;
extern int fn_801702D4(int obj, f32 v);
extern void staffFn_80170380(int handle, int v);
extern f32 lbl_803E68F0;
extern f32 lbl_803E68F4;
extern f32 lbl_803E68F8;
extern f32 lbl_803E6B40;
extern u8 lbl_803DC308;
extern void objSoundFn_800392f0(int obj, int a, void *b, int c);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int type);
extern int Obj_SetupObject(int obj, int a, int b, int c, int d);
extern f32 lbl_803DC324;
extern s16 lbl_803DC314;
extern u8 lbl_8032AAB0[];
extern f32 lbl_803E6B44;
extern f32 lbl_803E6ADC;
extern f32 lbl_803E6B48;
extern int fn_80222358(int obj, f32 *p, f32 a, f32 b, f32 c, int d);
extern void characterDoEyeAnims(int obj, void *p);
extern void objAnimFn_80038f38(int obj, void *p);
extern void dll_2E_func03(int obj, void *p);
int kytesmum_updateNearPlayerCallback(int obj, int unused, u8 *arg);
int kytesmum_updateQuestStateCallback(int obj, int unused, u8 *arg);

typedef struct {
    int v[3];
} QuestTriple;

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

#pragma dont_inline on
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
#pragma dont_inline reset

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

void drshackle_update(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    int q = *(int *)((char *)obj + 0x4c);
    int count;
    int *list;
    int j;
    if (*(s16 *)(q + 0x1a) != 0 && *(void **)p == 0) {
        list = ObjGroup_GetObjects(0x17, &count);
        while (count-- != 0) {
            int sub = *(int *)(*list + 0x4c);
            for (j = 0; j < *(int *)(p + 0x14); j++) {
                if (*(u8 *)(sub + 0x18) == *(s16 *)(q + 0x1a) + j * 4) {
                    *(int *)(p + j * 4) = *list;
                    (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(0, *(int *)(p + j * 4), -1);
                }
            }
            list++;
        }
    }
    if (((BitFlags8 *)(p + 0x1a))->b0 != 0) {
        ((BitFlags8 *)(p + 0x1a))->b0 = (GameBit_Get(*(s16 *)(q + 0x1e)) == 0);
    }
}

void drgenerator_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    f32 fv;
    if (*(s16 *)((char *)obj + 0x46) == 0x72e) {
        int *t;
        *(void **)((char *)obj + 0xbc) = (void *)drgenerator_eventCallback;
        t = objFindTexture(obj, 0, 0);
        if (t != 0) {
            *t = 0x100;
        }
    }
    *(u8 *)(p + 0x19a) = 2;
    ObjHits_EnableObject(obj);
    if (GameBit_Get(*(s16 *)(arg + 0x1e)) != 0) {
        *(s16 *)((char *)obj + 0x6) |= 0x4000;
        objRemoveFromListFn_8002ce88(obj);
        ObjHits_DisableObject(obj);
    }
    ObjGroup_AddObject(obj, 0x3);
    *(int *)p = 0;
    ((BitFlags8 *)(p + 0x19b))->b3 = 1;
    *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
    *(s16 *)(p + 0x198) = (*(s16 *)(arg + 0x1a) == 0) ? 0x14 : *(s16 *)(arg + 0x1a);
    *(s16 *)(p + 0x198) = *(s16 *)(p + 0x198) * 0x3c;
    *(f32 *)(p + 0x124) = lbl_803E6B68;
    if (GameBit_Get(0x9b9) != 0) {
        ((BitFlags8 *)(p + 0x19b))->b0 = 1;
        ((BitFlags8 *)(p + 0x19b))->b4 = 1;
    } else {
        ((BitFlags8 *)(p + 0x19b))->b4 = 0;
    }
    fv = lbl_803E6B6C;
    *(f32 *)((char *)obj + 0x2c) = fv;
    *(f32 *)((char *)obj + 0x28) = fv;
    *(f32 *)((char *)obj + 0x24) = fv;
}

void drakormissile_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    char *p = *(char **)((char *)obj + 0xb8);
    if (visible != 0 && *(u8 *)(p + 0x4) != 1) {
        s16 sv4 = *(s16 *)((char *)obj + 0x4);
        s16 sv2 = *(s16 *)((char *)obj + 0x2);
        f32 sv8 = *(f32 *)((char *)obj + 0x8);
        int *model;
        char *m;
        int i;
        *(u8 *)((char *)obj + 0xad) = 1;
        model = Obj_GetActiveModel();
        m = p;
        for (i = 0; i < 5; i++) {
            *(u16 *)(m + 0x10) = *(u16 *)(m + 0x10) + *(u16 *)(m + 0x1a);
            *(u16 *)(m + 0x24) = *(u16 *)(m + 0x24) + *(u16 *)(m + 0x2e);
            *(s16 *)((char *)obj + 0x4) = *(u16 *)(m + 0x10);
            *(s16 *)((char *)obj + 0x2) = *(u16 *)(m + 0x24);
            *(u16 *)((char *)model + 0x18) &= ~8;
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6964);
            m += 2;
        }
        *(s16 *)((char *)obj + 0x4) = sv4;
        *(s16 *)((char *)obj + 0x2) = sv2;
        *(f32 *)((char *)obj + 0x8) = sv8;
        *(u8 *)((char *)obj + 0xad) = 0;
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6964);
        if (*(void **)p != 0 && fn_8001DB64() != 0) {
            queueGlowRender(*(void **)p);
        }
    }
}

void drshackle_hitDetect(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    if (Sfx_IsPlayingFromObjectChannel(obj, 1) == 0 && ((BitFlags8 *)(p + 0x1a))->b0 != 0) {
        f32 vec[3];
        int n;
        PSVECSubtract((f32 *)((char *)obj + 0xc), (f32 *)(p + 0x8), vec);
        n = 0xc8 - (int)(lbl_803E6A30 * PSVECMag(vec));
        if (n < 1) {
            n = 1;
        } else if (n > 0xc8) {
            n = 0xc8;
        }
        if ((int)randomGetRange(0, n) == 0) {
            Sfx_PlayFromObject(obj, 0x1b3);
        }
    }
}

void ktfallingrocks_update(int obj) {
    int q = *(int *)((char *)obj + 0x4c);
    ObjPosParams params;
    int player;
    int i;
    if (GameBit_Get(*(s16 *)(q + 0x24)) == 0) {
        return;
    }
    player = (int)Obj_GetPlayerObject();
    if (player == 0) {
        return;
    }
    *(f32 *)((char *)obj + 0xc) = *(f32 *)(player + 0xc);
    *(f32 *)((char *)obj + 0x14) = *(f32 *)(player + 0x14);
    for (i = 0; i < 10; i++) {
        params.x = *(f32 *)((char *)obj + 0xc) + (f32)(int)randomGetRange(-200, 200);
        params.y = *(f32 *)((char *)obj + 0x10);
        params.z = *(f32 *)((char *)obj + 0x14) + (f32)(int)randomGetRange(-200, 200);
        (*(void (**)(int, int, ObjPosParams *, int, int, int))((char *)*gPartfxInterface + 0x8))(
            obj, *(u16 *)(q + 0x20), &params, 0x200001, -1, 0);
    }
    Sfx_PlayFromObject(obj, 696);
    GameBit_Set(*(s16 *)(q + 0x24), 0);
}

void hightop_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    char *runtime = *(char **)((char *)obj + 0xb8);
    if (visible != 0) {
        int count;
        int **list;
        int i;
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6AB8);
        ObjPath_GetPointWorldPosition((int)obj, 2, (f32 *)(runtime + 0xb6c), (f32 *)(runtime + 0xb70), (f32 *)(runtime + 0xb74), 0);
        ObjPath_GetPointWorldPositionArray((int)obj, 3, 4, (f32 *)(runtime + 0xb18));
        ObjPath_GetPointWorldPosition((int)obj, 0, (f32 *)(runtime + 0xb78), (f32 *)(runtime + 0xb7c), (f32 *)(runtime + 0xb80), 0);
        ((BitFlags8 *)(runtime + 0xc49))->b5 = 1;
        dll_2E_func06((int)obj, runtime + 0x3ec, 0);
        if (((BitFlags8 *)(runtime + 0xc49))->b1 != 0) {
            list = (int **)ObjGroup_GetObjects(55, &count);
            for (i = 0; i < count; i++) {
                int idx = (*(int (**)(int *))((char *)**(int ***)((char *)*list + 0x68) + 0x24))(*list);
                (*(void (**)(int *, void *, int, undefined4, undefined4, undefined4, undefined4))((char *)**(int ***)((char *)*list + 0x68) + 0x20))(
                    *list, obj, lbl_8032AB48[idx], p2, p3, p4, p5);
                list++;
            }
        }
    } else {
        ((BitFlags8 *)(runtime + 0xc49))->b5 = 0;
    }
}

void gmmazewell_update(void *obj) {
    s16 *base = lbl_8032A730;
    u8 *runtime = *(u8 **)((char *)obj + 0xb8);
    int player;
    int value;
    s16 *p;
    int i;
    if (runtime[1] == 0) {
        player = (int)Obj_GetPlayerObject();
        if (player != 0) {
            (*(void (**)(f32 *, int, int, int))((char *)*gMapEventInterface + 0x1c))(
                (f32 *)(player + 0xc), *(s16 *)player, 0, getCurMapLayer());
            runtime[1] = 1;
        }
    }
    *(u8 *)((char *)obj + 0xaf) &= ~8;
    p = base;
    for (i = 0; i < 9; i++) {
        if (GameBit_Get(*p) != 0) {
            value = base[i];
            goto checkValue;
        }
        p++;
    }
    value = 0;
checkValue:
    if (value != 0) {
        *(u8 *)((char *)obj + 0xaf) &= ~0x10;
    } else {
        *(u8 *)((char *)obj + 0xaf) |= 0x10;
    }
    if ((*(u8 *)((char *)obj + 0xaf) & 1) != 0) {
        int found;
        p = base;
        for (i = 0; i < 9; i++) {
            if ((*(int (**)(int))((char *)*gGameUIInterface + 0x20))(*p) != 0) {
                if (lbl_803DC968 != 0) {
                    runtime = *(u8 **)((char *)obj + 0xb8);
                    if (i < 3 && i >= 0) {
                        GameBit_Set(*(s16 *)((char *)&base[i] + 0x14), 1);
                        saveFileStruct_unlockCheat((u8)i);
                    }
                    *(int *)(runtime + 4) = *(s32 *)((char *)&base[i * 2] + 0x38);
                    GameBit_Set(*(s16 *)((char *)&base[i] + 0x28), 1);
                } else {
                    runtime = *(u8 **)((char *)obj + 0xb8);
                    *(int *)(runtime + 4) = *(s32 *)((char *)&base[i * 2] + 0x38);
                    if (i == 3) {
                        *(int *)(runtime + 4) = 1316;
                    }
                    if (i < 3 && i >= 0) {
                        GameBit_Set(*(s16 *)((char *)&base[i] + 0x14), 1);
                        saveFileStruct_unlockCheat((u8)i);
                    }
                    GameBit_Set(*(s16 *)((char *)&base[i] + 0x28), 1);
                }
                found = 1;
                goto checkFound;
            }
            p++;
        }
        found = 0;
    checkFound:
        if (found != 0) {
            (*(void (**)(int, void *, int))((char *)*gObjectTriggerInterface + 0x48))(0, obj, -1);
            buttonDisable(0, 256);
        }
    }
    objRenderFn_80041018((int)obj);
}

void hightop_init(void *obj, u8 *arg) {
    u8 *base = lbl_8032AAB0;
    char *runtime = *(char **)((char *)obj + 0xb8);
    char *pathObj;
    int *node;
    HtInitData local1;
    HtInitData local2;
    int local8;
    local8 = lbl_803E6AA0;
    local1 = lbl_802C2590;
    local2 = lbl_802C25A4;
    *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
    *(int *)((char *)obj + 0xbc) = (int)hightop_interactionCallback;
    *(u8 *)(runtime + 0xc45) = arg[0x19];
    *(s16 *)(runtime + 0xc16) = 5;
    *(s8 *)(runtime + 0xc4b) = -1;
    node = *(int **)((char *)obj + 0x64);
    if (node != 0) {
        *(int *)((char *)node + 0x30) |= 0xa10;
    }
    ObjGroup_AddObject((int)obj, 38);
    ObjGroup_AddObject((int)obj, 10);
    (*(void (**)(void *, char *, int, int))((char *)*gPlayerInterface + 4))(obj, runtime, 11, 1);
    *(f32 *)(runtime + 0x2a4) = lbl_803E6B4C;
    pathObj = runtime + 4;
    *(u8 *)(pathObj + 0x25b) = 1;
    (*(void (**)(char *, int, int, int))((char *)*gPathControlInterface + 4))(pathObj, 3, 1024, 0);
    (*(void (**)(char *, int, u8 *, int *, int))((char *)*gPathControlInterface + 8))(pathObj, 2, &base[0xe8], &lbl_803DC318, 8);
    (*(void (**)(char *, int, u8 *, u8 *, int *))((char *)*gPathControlInterface + 12))(pathObj, 4, &base[0xa8], &base[0xd8], &local8);
    (*(void (**)(void *, char *))((char *)*gPathControlInterface + 32))(obj, pathObj);
    dll_2E_func05((int)obj, runtime + 0x3ec, -4551, 23665, 6);
    dll_2E_func08(runtime + 0x3ec, 300, 120);
    dll_2E_func09(runtime + 0x3ec, &local2, &local1, 6);
    *(u8 *)(runtime + 0x9fd) |= 2;
    *(u8 *)(runtime + 0x9fd) |= 8;
    *(s16 *)(runtime + 0xc18) = *(s16 *)(arg + 0x1a);
    *(u8 *)(runtime + 0x9fd) |= 1;
    *(u8 *)(*(int *)((char *)obj + 0x50) + 0x71) = 127;
    ((BitFlags8 *)(runtime + 0xc49))->b4 = 0;
    ((BitFlags8 *)(runtime + 0xc49))->b7 = 0;
    lbl_803DC320 = *(s16 *)(arg + 0x1a);
    if (*(s16 *)(arg + 0x1c) == 0) {
        *(f32 *)(runtime + 0xc28) = lbl_803E6B50;
    } else {
        *(f32 *)(runtime + 0xc28) = (f32)*(s16 *)(arg + 0x1c) / lbl_803E6B54;
    }
    ((BitFlags8 *)(runtime + 0xc49))->b6 = 0;
    ((BitFlags8 *)(runtime + 0xc4a))->b0 = 0;
}

void drcreator_update(int obj) {
    int q = *(int *)((char *)obj + 0x4c);
    char *runtime = *(char **)((char *)obj + 0xb8);
    int o;
    int p;
    if (Obj_IsLoadingLocked() != 0) {
        switch (*(s16 *)(q + 0x1a)) {
        case 3:
        case 9:
            if (GameBit_Get(*(s16 *)(runtime + 4)) != 0) {
                (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(
                    (*(s16 *)(q + 0x1a) == 3) ? 0 : 4, obj, -1);
            }
            break;
        case 4:
            if (GameBit_Get(*(s16 *)(runtime + 4)) != 0) {
                *(s16 *)(runtime + 8) -= framesThisStep;
                if (*(s16 *)(runtime + 8) <= 0) {
                    o = Obj_AllocObjectSetup(36, 1725);
                    *(f32 *)(o + 8) = *(f32 *)((char *)obj + 0xc);
                    *(f32 *)(o + 0xc) = *(f32 *)((char *)obj + 0x10);
                    *(f32 *)(o + 0x10) = *(f32 *)((char *)obj + 0x14);
                    *(u8 *)(o + 4) = 1;
                    *(u8 *)(o + 5) = 1;
                    *(u8 *)(o + 6) = 255;
                    *(u8 *)(o + 7) = 250;
                    if ((s8)*(u8 *)((char *)obj + 0xac) == 2) {
                        *(u8 *)(o + 0x19) = 4;
                    } else {
                        *(u8 *)(o + 0x19) = 1;
                    }
                    p = Obj_SetupObject(o, 5, -1, -1, 0);
                    if (p != 0) {
                        *(s16 *)(p + 2) = 0;
                        *(s16 *)p = (s16)randomGetRange(0, 65535);
                        *(f32 *)(p + 0x24) = lbl_803E69B8 * (lbl_803E69BC * ((f32)*(int *)runtime * -fn_80293E80((lbl_803E69C0 * (f32)*(s16 *)obj) / lbl_803E69C4)));
                        *(f32 *)(p + 0x28) = lbl_803E69B8 * ((f32)*(int *)runtime * (lbl_803E69C8 * (f32)(int)randomGetRange(0, 1000)));
                        *(f32 *)(p + 0x2c) = lbl_803E69B8 * (lbl_803E69BC * ((f32)*(int *)runtime * -sin((lbl_803E69C0 * (f32)*(s16 *)obj) / lbl_803E69C4)));
                        *(int *)(p + 0xc4) = obj;
                    }
                    *(s16 *)(runtime + 8) = *(s16 *)(runtime + 6) + randomGetRange(0, *(s16 *)(runtime + 0xa));
                }
            }
            break;
        }
    }
}

int drcreator_spawnProjectileCallback(int obj, int unused, u8 *arg) {
    int q = *(int *)((char *)obj + 0x4c);
    char *runtime;
    int o;
    int p;
    int i;
    fn_80137948(sDrCreatorTimeFormat, *(s16 *)(q + 0x1a), *(s16 *)(arg + 0x58));
    if (Obj_IsLoadingLocked() == 0) {
        return 0;
    }
    for (i = 0; i < arg[0x8b]; i++) {
        switch (*(s16 *)(q + 0x1a)) {
        case 3:
        case 4:
        case 9:
            runtime = *(char **)((char *)obj + 0xb8);
            if (GameBit_Get(*(s16 *)(runtime + 4)) != 0) {
                o = Obj_AllocObjectSetup(36, 1725);
                *(f32 *)(o + 8) = *(f32 *)((char *)obj + 0xc);
                *(f32 *)(o + 0xc) = *(f32 *)((char *)obj + 0x10);
                *(f32 *)(o + 0x10) = *(f32 *)((char *)obj + 0x14);
                *(u8 *)(o + 4) = 1;
                *(u8 *)(o + 5) = 1;
                *(u8 *)(o + 6) = 255;
                *(u8 *)(o + 7) = 255;
                *(u8 *)(o + 0x19) = 2;
                p = Obj_SetupObject(o, 5, -1, -1, 0);
                if (p != 0) {
                    *(s16 *)(p + 2) = 0;
                    *(s16 *)p = (s16)randomGetRange(0, 65535);
                    *(f32 *)(p + 0x24) = lbl_803E69A8 * (f32)(int)randomGetRange(-*(s16 *)(runtime + 0xa), *(s16 *)(runtime + 0xa));
                    *(f32 *)(p + 0x28) = lbl_803E69A8 * (f32)*(int *)runtime;
                    *(f32 *)(p + 0x2c) = lbl_803E69A8 * (f32)(int)randomGetRange(-*(s16 *)(runtime + 0xa), *(s16 *)(runtime + 0xa));
                    *(int *)(p + 0xc4) = obj;
                }
            }
            break;
        }
    }
    return 0;
}

void ktlazerwall_update(int obj) {
    int q = *(int *)((char *)obj + 0x4c);
    u8 *runtime = *(u8 **)((char *)obj + 0xb8);
    int cur;
    int mode;
    int i;
    runtime[1] = runtime[0];
    runtime[0] &= ~3;
    cur = (s16)GameBit_Get(*(s16 *)(q + 0x1a));
    if (cur >= *(s16 *)(q + 0x1c)) {
        runtime[0] |= 4;
    } else {
        runtime[0] &= ~4;
        if (GameBit_Get(*(s16 *)(q + 0x1e)) == 0) {
            return;
        }
    }
    *(s16 *)((char *)obj + 4) += 910;
    if (cur >= 15 && (runtime[0] & 9) == 0) {
        GameBit_Set(*(s16 *)(q + 0x1e), 1);
        runtime[0] |= 9;
        ktrexfloorswitch_spawnEnergyArc(obj, lbl_803E68B8, 120);
        (*(void (**)(int, int, int, int, int, int *))((char *)*gPartfxInterface + 8))(obj, 1150, 0, 2, -1, 0);
        for (i = 10; i != 0; i--) {
            mode = 2;
            (*(void (**)(int, int, int, int, int, int *))((char *)*gPartfxInterface + 8))(obj, 1164, 0, 2, -1, &mode);
        }
        *(f32 *)(runtime + 4) = (f32)(int)randomGetRange(1, 60);
    }
    if (runtime[0] & 4) {
        mode = 0;
        (*(void (**)(int, int, int, int, int, int *))((char *)*gPartfxInterface + 8))(obj, 1164, 0, 2, -1, &mode);
        mode = 1;
        (*(void (**)(int, int, int, int, int, int *))((char *)*gPartfxInterface + 8))(obj, 1164, 0, 2, -1, &mode);
        if ((runtime[1] & 4) == 0) {
            Sfx_PlayFromObject(obj, 130);
        }
    }
    if (runtime[0] & 8) {
        mode = 0;
        (*(void (**)(int, int, int, int, int, int *))((char *)*gPartfxInterface + 8))(obj, 1164, 0, 2, -1, &mode);
        mode = 2;
        (*(void (**)(int, int, int, int, int, int *))((char *)*gPartfxInterface + 8))(obj, 1164, 0, 2, -1, &mode);
    }
    if ((runtime[0] & 8) == 0 && (runtime[1] & 8) != 0) {
        Sfx_PlayFromObject(obj, 132);
    }
    if (*(f32 *)(runtime + 4) > lbl_803E6898) {
        *(f32 *)(runtime + 4) -= timeDelta;
        if (*(f32 *)(runtime + 4) <= lbl_803E6898) {
            Sfx_PlayFromObject(obj, 131);
            *(f32 *)(runtime + 4) = lbl_803E6898;
        }
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

#pragma scheduling off
#pragma peephole off
void drchimmey_update(int obj) {
    int q = *(int *)((char *)obj + 0x4c);
    char *p = *(char **)((char *)obj + 0xb8);
    *(u8 *)((char *)obj + 0xaf) |= 8;
    if (*(s16 *)(q + 0x20) != -1 && GameBit_Get(*(s16 *)(q + 0x20)) == 0) {
        return;
    }
    if (fn_80080150((void *)(p + 0x10)) == 0) {
        if ((s8)p[0x16] <= 0) {
            p[0x17] = 1;
            s16toFloat((void *)(p + 0x10), (int)*(f32 *)(p + 0xc));
            GameBit_Set(*(s16 *)(p + 0x14), 1);
        } else {
            int *tricky = getTrickyObject();
            if (tricky != 0) {
                if ((*(u8 *)((char *)obj + 0xaf) & 4) != 0) {
                    (*(void (**)(int *, int, int, int))((char *)*(void **)*(void **)((char *)tricky + 0x68) + 0x28))(tricky, obj, 1, 4);
                }
                *(u8 *)((char *)obj + 0xaf) &= ~8;
                objRenderFn_80041018(obj);
            }
        }
    }
    if (timerCountDown((void *)(p + 0x10)) != 0) {
        *(int *)p = 0;
        *(f32 *)(p + 0x10) = lbl_803E69E4;
        p[0x17] = 0;
        p[0x16] = 1;
        GameBit_Set(*(s16 *)(p + 0x14), 0);
        GameBit_Set(0xea4, 0);
    }
}

void drcagewith_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    s16 type;
    f32 fz;
    *(void **)((char *)obj + 0xbc) = (void *)drcagewith_toggleRopeStateCallback;
    type = *(s16 *)((char *)obj + 0x46);
    if (type == 0x86a || type == 0x86b) {
        if (GameBit_Get(0x609) == 0) {
            *(s16 *)((char *)obj + 0x6) |= 0x4000;
        }
    } else {
        ObjHits_EnableObject(obj);
        if (GameBit_Get(*(s16 *)(arg + 0x1e)) != 0) {
            ObjHits_DisableObject(obj);
            *(s16 *)((char *)obj + 0x6) |= 0x4000;
            ((BitFlags8 *)(p + 0x31))->b0 = 1;
        } else {
            GameBit_Set(0x7aa, 5);
        }
        *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
        *(f32 *)(p + 0x8) = (f32)*(s16 *)(arg + 0x1c);
        *(f32 *)(p + 0x10) = (f32)*(s16 *)(arg + 0x1a) / lbl_803E6A18;
        *(int *)(p + 0x4) = 0;
        fz = lbl_803E6A1C;
        *(f32 *)(p + 0x14) = fz;
        *(f32 *)(p + 0x18) = fz;
        *(f32 *)(p + 0x1c) = fz;
        *(f32 *)(p + 0x20) = fz;
        ObjGroup_AddObject(obj, 0x18);
    }
}

void drakormissile_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    int s;
    int i;
    *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6e) = 0x13;
    *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6f) = 1;
    s = *(int *)((char *)obj + 0x54);
    *(s16 *)(s + 0x60) = *(s16 *)(s + 0x60) & ~1;
    *(f32 *)((char *)obj + 0xc) = *(f32 *)(arg + 0x8);
    *(f32 *)((char *)obj + 0x10) = *(f32 *)(arg + 0xc);
    *(f32 *)((char *)obj + 0x14) = *(f32 *)(arg + 0x10);
    *(f32 *)((char *)obj + 0x24) = (f32)(u32)(u8)arg[0x18];
    *(f32 *)((char *)obj + 0x28) = (f32)(u32)(u8)arg[0x19];
    *(f32 *)((char *)obj + 0x2c) = (f32)(u32)(u8)arg[0x1a];
    {
        int *r = *(int **)((char *)obj + 0x54);
        if (r != 0) {
            *(s16 *)((char *)r + 0xb2) = 1;
        }
    }
    ObjGroup_AddObject(obj, 0x2);
    *(u8 *)(p + 0x4) = 0;
    *(u8 *)(p + 0x5) = 0;
    *(int *)(p + 0x8) = 0;
    *(int *)p = 0;
    *(f32 *)(p + 0xc) = lbl_803E695C;
    for (i = 0; i < 5; i++) {
        *(u16 *)(p + 0x10) = (u16)randomGetRange(-0x7fff, 0x7fff);
        *(u16 *)(p + 0x1a) = (u16)randomGetRange(-0x400, 0x400);
        *(u16 *)(p + 0x24) = (u16)randomGetRange(-0x7fff, 0x7fff);
        *(u16 *)(p + 0x2e) = (u16)randomGetRange(-0x400, 0x400);
        p += 2;
    }
}

void ktlazerwall_render(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    int q = *(int *)((char *)obj + 0x4c);
    int m;
    if (*(void **)(p + 0x10) != 0) {
        *(f32 *)(p + 0x8) -= timeDelta;
        if (*(f32 *)(p + 0x8) <= lbl_803E6898) {
            f32 t = lbl_803E68B0 * *(f32 *)(p + 0xc);
            m = *(int *)(p + 0x10);
            *(f32 *)(m + 0x10) = *(f32 *)(m + 0x10) - t * lbl_803E68B4;
            *(f32 *)(p + 0x8) = (f32)(int)randomGetRange(0xa, 0x78);
        } else {
            m = *(int *)(p + 0x10);
            *(f32 *)(m + 0x10) = *(f32 *)(p + 0xc) * timeDelta + *(f32 *)(m + 0x10);
        }
        renderFn_8008f904(*(void **)(p + 0x10));
        *(u16 *)(*(int *)(p + 0x10) + 0x20) += framesThisStep;
        m = *(int *)(p + 0x10);
        if (*(u16 *)(m + 0x20) >= *(u16 *)(m + 0x22)) {
            mm_free((void *)m);
            *(int *)(p + 0x10) = 0;
            *(u8 *)p &= ~8;
            GameBit_Set(*(s16 *)(q + 0x1e), 0);
        }
    }
}

void drgenerator_hitDetect(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    int q = *(int *)((char *)obj + 0x4c);
    f32 a18;
    f32 a14;
    f32 a10;
    int ac;
    int a8;
    int found;
    if (((BitFlags8 *)(p + 0x19b))->b0 || ((BitFlags8 *)(p + 0x19b))->b3) {
        return;
    }
    if (ObjHits_GetPriorityHitWithPosition(obj, &a8, 0, &ac, &a10, &a14, &a18) != 5) {
        return;
    }
    p[0x19a] = p[0x19a] - ac;
    fn_80221E94(obj, &a10, lbl_803E6B5C);
    fn_8009A8C8(obj, lbl_803E6B60);
    if (p[0x19a] > 0) {
        return;
    }
    {
        int *tex = objFindTexture(obj, 0, 0);
        spawnExplosion(obj, lbl_803E6B64, 1, 1, 1, 1, 0, 1, 0);
        if (tex != 0) {
            *tex = 0x100;
        }
    }
    ((BitFlags8 *)(p + 0x19b))->b0 = 1;
    GameBit_Set(*(s16 *)(q + 0x1e), 1);
    if (*(s16 *)((char *)obj + 0x46) == 0x716 &&
        (found = ObjGroup_FindNearestObject(0x4c, obj, 0)) != 0) {
        timer_addDuration(found, *(s16 *)(p + 0x198));
    } else {
        ObjHits_DisableObject(obj);
    }
}

void drgenerator_update(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    int q = *(int *)((char *)obj + 0x4c);
    int n;
    if (((BitFlags8 *)(p + 0x19b))->b4 == 0 && GameBit_Get(0x9b9) != 0) {
        ((BitFlags8 *)(p + 0x19b))->b4 = 1;
    }
    if (((BitFlags8 *)(p + 0x19b))->b4 != 0) {
        goto loop;
    }
    if (((BitFlags8 *)(p + 0x19b))->b3 != 0) {
        goto enable;
    }
    if (GameBit_Get(*(s16 *)(q + 0x20)) != 0) {
        goto enable;
    }
    if (*(s16 *)((char *)obj + 0x46) != 0x72e) {
        (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(4, obj, -1);
    }
    ((BitFlags8 *)(p + 0x19b))->b3 = 1;
    ((BitFlags8 *)(p + 0x19b))->b0 = 0;
    ObjHits_DisableObject(obj);
    return;
enable:
    if (((BitFlags8 *)(p + 0x19b))->b3 == 0) {
        goto loop;
    }
    if (GameBit_Get(*(s16 *)(q + 0x20)) == 0) {
        goto loop;
    }
    if (*(s16 *)((char *)obj + 0x46) != 0x72e) {
        (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(3, obj, -1);
    }
    ((BitFlags8 *)(p + 0x19b))->b3 = 0;
    ObjHits_EnableObject(obj);
    return;
loop:
    if (((BitFlags8 *)(p + 0x19b))->b0 == 0) {
        return;
    }
    n = 1;
    do {
        (*(void (**)(int, int, int, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x690, 0, 1, -1, 0);
    } while (n-- != 0);
}

void kytesmum_init(int obj, char *arg) {
    char *base = (char *)lbl_8032A7C0;
    char *runtime = *(char **)((char *)obj + 0xb8);
    int r;
    *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
    if (GameBit_Get(*(s16 *)(arg + 0x1e)) != 0) {
        *(u8 *)(runtime + 0x6e6) = 1;
    }
    switch ((s8)arg[0x19]) {
    case 1:
        *(int *)(runtime + 0x6dc) = (int)base;
        *(void **)(runtime + 0x6d4) = (void *)kytesmum_spawnInteractionCallback;
        *(int *)(runtime + 0x6d8) = 0;
        *(void **)((char *)obj + 0xbc) = (void *)kytesmum_animEventCallback;
        break;
    case 2:
        *(int *)(runtime + 0x6dc) = (int)(base + 0xc);
        *(void **)(runtime + 0x6d4) = (void *)kytesmum_updateNearPlayerCallback;
        *(int *)(runtime + 0x6d8) = (int)&lbl_803DC2C8;
        ObjGroup_AddObject(obj, 0x3);
        if (*(u8 *)(runtime + 0x6e6) != 0) {
            objRemoveFromListFn_8002ce88(obj);
            *(s16 *)((char *)obj + 0x6) |= 0x4000;
        }
        ObjHits_RegisterActiveHitVolumeObject(obj);
        *(void **)((char *)obj + 0xbc) = (void *)kytesmum_animEventCallback;
        break;
    case 0:
    case 3:
        GameBit_Set(0x934, 0);
        GameBit_Set(0x933, 0);
        *(int *)(runtime + 0x6dc) = (int)(base + 0x18);
        *(void **)(runtime + 0x6d4) = (void *)kytesmum_updateQuestStateCallback;
        *(int *)(runtime + 0x6d8) = (int)&lbl_803DC2D0;
        *(void **)((char *)obj + 0xbc) = (void *)kytesmum_updateInteractionRangeCallback;
        break;
    }
    *(int *)(runtime + 0x6d0) = (int)(base + 0x24);
    *(f32 *)(runtime + 0x6e0) = lbl_803E699C;
    r = randomGetRange(0, 1) * 2;
    ObjAnim_SetCurrentMove(obj, *(s16 *)(*(int *)(runtime + 0x6dc) + r), lbl_803E698C, 0);
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
}

int kytesmum_updateNearPlayerCallback(int obj, int unused, u8 *arg) {
    int *player = Obj_GetPlayerObject();
    int *tricky = getTrickyObject();
    char *runtime = *(char **)((char *)obj + 0xb8);
    if (objGetAnimState80A(player) == 0x40) {
        return 1;
    }
    if ((*(u8 *)((char *)obj + 0xaf) & 1) != 0) {
        if ((*(int (**)(void *))((char *)*gGameUIInterface + 0x1c))(*gGameUIInterface) == 0) {
            buttonDisable(0, 0x100);
            *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6e) = 0xb;
            *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6f) = 4;
            (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(randomGetRange(0, 1), obj, -1);
        }
    }
    if ((tricky != 0 && Vec_xzDistance((f32 *)((char *)obj + 0x18), (f32 *)((char *)tricky + 0x18)) < lbl_803E6988) ||
        (player != 0 && Vec_xzDistance((f32 *)((char *)obj + 0x18), (f32 *)((char *)player + 0x18)) < lbl_803E6988)) {
        if (*(s16 *)((char *)obj + 0xa0) != 9) {
            ObjAnim_SetCurrentMove(obj, 9, lbl_803E698C, 0);
            *(f32 *)(runtime + 0x6e0) = lbl_803E6990;
            if (tricky != 0) {
                (*(void (**)(int *, int, int))((char *)*(void **)*(void **)((char *)tricky + 0x68) + 0x34))(tricky, 0, 0);
            }
        }
    }
    if (*(s16 *)((char *)obj + 0xa0) == 9) {
        *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6e) = 0xb;
        *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6f) = 4;
        ObjHits_SetHitVolumeSlot(obj, 0xb, 4, 7);
        ObjHits_RegisterActiveHitVolumeObject(obj);
    }
    return 0;
}

int kytesmum_updateQuestStateCallback(int obj, int unused, u8 *arg) {
    int questBits[3];
    int triggerIds[3];
    int count;
    char *runtime;
    int next;
    *(QuestTriple *)questBits = *(QuestTriple *)lbl_802C2578;
    *(QuestTriple *)triggerIds = *(QuestTriple *)lbl_802C2584;
    count = 0;
    Obj_GetPlayerObject();
    runtime = *(char **)((char *)obj + 0xb8);
    saveGame_saveObjectPos(obj);
    ObjHits_DisableObject(obj);
    for (; questBits[count] != -1 && GameBit_Get(questBits[count]) != 0; count++) {
        ;
    }
    if (count > 0) {
        *(int *)(runtime + 0x6d0) = (int)lbl_8032A7FC;
    }
    GameBit_Set(0xeb9, count == 1);
    next = triggerIds[count];
    if (next == -1) {
        *(u8 *)((char *)obj + 0xaf) |= 8;
        return 1;
    }
    if (ObjTrigger_IsSet(obj) != 0) {
        *(void **)((char *)obj + 0xbc) = (void *)kytesmum_idleCallback;
        (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(next, obj, -1);
    }
    return 0;
}

#pragma dont_inline on
int hightop_handleMotionEvent(int obj, u8 event) {
    char *runtime = *(char **)((char *)obj + 0xb8);
    switch (event) {
    case 5:
        (*(void (**)(int, char *, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 8);
        break;
    case 6:
        GameBit_Set(0x634, 1);
        (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(4, obj, -1);
        break;
    case 7:
        GameBit_Set(0x634, 0);
        GameBit_Set(0x631, 1);
        *(u8 *)(*(int *)((char *)obj + 0x50) + 0x71) |= 1;
        *(u16 *)(runtime + 0xc40) &= ~0x140;
        *(u8 *)(runtime + 0x9fd) &= ~2;
        (*(void (**)(int, char *, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 7);
        break;
    case 8:
        (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(7, obj, -1);
        break;
    case 9:
        (*(void (**)(int, char *, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 7);
        break;
    }
    return 0;
}
#pragma dont_inline reset

void drlasercannon_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    f32 fz;
    *(u8 *)(p + 0x1a6) = 4;
    ObjHits_EnableObject(obj);
    if (GameBit_Get(*(s16 *)(arg + 0x1e)) != 0) {
        *(s16 *)((char *)obj + 0x6) |= 0x4000;
        objRemoveFromListFn_8002ce88(obj);
        ObjHits_DisableObject(obj);
    }
    ObjGroup_AddObject(obj, 0x3);
    *(int *)p = 0;
    ((BitFlags8 *)(p + 0x1a8))->b3 = 0;
    *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
    *(int *)(p + 0x128) = 0x258;
    *(f32 *)(p + 0x124) = lbl_803E6920;
    if (GameBit_Get(*(s16 *)(arg + 0x1e)) != 0) {
        ((BitFlags8 *)(p + 0x1a8))->b0 = 1;
        ((BitFlags8 *)(p + 0x1a8))->b4 = 1;
    } else {
        ((BitFlags8 *)(p + 0x1a8))->b4 = 0;
    }
    ((BitFlags8 *)(p + 0x1a8))->b5 = 0;
    fz = lbl_803E690C;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x28) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    if (GameBit_Get(*(s16 *)(arg + 0x1e)) == 0) {
        *(int *)(p + 0x190) = fn_801702D4(obj, lbl_803E6938);
        if (*(void **)(p + 0x190) != 0) {
            staffFn_80170380(*(int *)(p + 0x190), 4);
        }
        ((BitFlags8 *)(p + 0x1a8))->b6 = 1;
    } else {
        ((BitFlags8 *)(p + 0x1a8))->b6 = 0;
        *(int *)(p + 0x190) = 0;
    }
    storeZeroToFloatParam((void *)(p + 0x12c));
    s16toFloat((void *)(p + 0x12c), (s16)((s8)arg[0x19] * 4 + 1));
    *(u8 *)(p + 0x1a7) = 0;
    ((BitFlags8 *)(p + 0x1a8))->b7 = 1;
    *(int *)(p + 0x19c) = 0x429;
    if (*(s8 *)((char *)obj + 0xac) == 2) {
        *(s16 *)(p + 0x1a4) = 0xe90;
    } else {
        *(s16 *)(p + 0x1a4) = -1;
    }
}

void drlasercannon_hitDetect(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    int q = *(int *)((char *)obj + 0x4c);
    f32 a18;
    f32 a14;
    f32 a10;
    int ac;
    int *a8;
    int hit;
    int *tricky;
    if (((BitFlags8 *)(p + 0x1a8))->b0 || ((BitFlags8 *)(p + 0x1a8))->b3) {
        return;
    }
    hit = ObjHits_GetPriorityHitWithPosition(obj, &a8, 0, &ac, &a10, &a14, &a18);
    if (((BitFlags8 *)(p + 0x1a8))->b6 != 0) {
        if (hit != 0 && *(s16 *)((char *)a8 + 0x46) != *(int *)(p + 0x19c) &&
            *(void **)(p + 0x190) != 0) {
            staffFn_80170380(*(int *)(p + 0x190), 6);
        }
    } else if (((u32)(hit - 0xe) <= 1 || hit == 5) &&
               *(int **)(p + 0xc) != a8 &&
               *(s16 *)((char *)a8 + 0x46) != *(int *)(p + 0x19c)) {
        *(int **)(p + 0xc) = a8;
        p[0x1a6] = p[0x1a6] - ac;
        fn_80221E94(obj, &a10, lbl_803E68F0);
        fn_8009A8C8(obj, lbl_803E68F4);
        Sfx_PlayFromObject(obj, 0x3cc);
        if (p[0x1a6] <= 0) {
            tricky = getTrickyObject();
            Sfx_PlayFromObject(obj, 0x4b6);
            spawnExplosion(obj, lbl_803E68F8, 0, 1, 1, 1, 0, 1, 0);
            ((BitFlags8 *)(p + 0x1a8))->b0 = 1;
            GameBit_Set(*(s16 *)(q + 0x1e), 1);
            if (tricky != 0) {
                (*(void (**)(int *, int, int))((char *)*(void **)*(void **)((char *)tricky + 0x68) + 0x34))(tricky, 0, 0);
            }
            *(s16 *)((char *)obj + 0x6) |= 0x4000;
        }
    }
    if (hit == 0) {
        *(int *)(p + 0xc) = 0;
    } else {
        *(int **)(p + 0xc) = a8;
    }
}

void hightop_hitDetect(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    f32 l10;
    f32 lc;
    f32 l8;
    int hit;
    s16 st;
    hit = ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &l8, &lc, &l10);
    if (hit == 0) {
        return;
    }
    st = *(s16 *)(p + 0x274);
    if (st != 4 && (u16)(st - 9) > 1) {
        if (hit == 0xf || hit == 0xe) {
            return;
        }
    }
    if (*(s16 *)(p + 0xc18) == 0) {
        return;
    }
    fn_80221E94(obj, &l8, lbl_803E6B40);
    objSoundFn_800392f0(obj, (int)(p + 0x3bc), &lbl_803DC308 + randomGetRange(0, 0) * 6, 1);
    st = *(s16 *)(p + 0x274);
    if (st != 3) {
        *(int *)(p + 0xc3c) = st;
    }
    st = *(s16 *)(p + 0x274);
    if (st == 2 || st == 8) {
        *(s16 *)(p + 0xc18) -= 1;
        fn_8009A8C8(obj, lbl_803E6B30);
        if (*(s16 *)(p + 0xc18) <= 0) {
            (*(void (**)(void *))((char *)*gGameUIInterface + 0x60))(*gGameUIInterface);
            ((BitFlags8 *)(p + 0xc49))->b7 = 0;
            GameBit_Set(0x634, 0);
            if (Obj_IsLoadingLocked() != 0) {
                int spawn = Obj_AllocObjectSetup(0x2c, 0xd4);
                *(u8 *)(spawn + 0x4) = 2;
                *(f32 *)(spawn + 0x8) = *(f32 *)((char *)obj + 0xc);
                *(f32 *)(spawn + 0xc) = *(f32 *)((char *)obj + 0x10);
                *(f32 *)(spawn + 0x10) = *(f32 *)((char *)obj + 0x14);
                *(s16 *)(spawn + 0x1a) = 0x675;
                *(s16 *)(spawn + 0x1c) = 0;
                *(s16 *)(spawn + 0x1e) = -1;
                Obj_SetupObject(spawn, 5, *(s8 *)((char *)obj + 0xac), -1, *(int *)((char *)obj + 0x30));
            }
            *(s16 *)((char *)obj + 0x2) = 0;
            *(s16 *)((char *)obj + 0x4) = 0;
            *(u8 *)(p + 0x25f) = 0;
            *(int *)p |= 0x1000000;
            GameBit_Set(0xb48, 1);
            (*(void (**)(void *))((char *)*gGameUIInterface + 0x60))(*gGameUIInterface);
        }
    } else {
        (*(void (**)(int, char *, int))((char *)*gPlayerInterface + 0x14))(obj, p, 3);
    }
}

void hightop_update(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    *(s16 *)(p + 0xc16) = 5;
    *(u8 *)((char *)obj + 0xaf) &= ~8;
    *(s8 *)(p + 0x25f) = !((BitFlags8 *)(p + 0xc49))->b4;
    *(u8 *)(p + 0x354) = 0;
    *(int *)p &= ~0x8000;
    if ((*(u16 *)(p + 0xc40) & 0x40) != 0) {
        int ev = fn_80222358(obj, (f32 *)(p + 0xa10),
                             lbl_803DC324 * (*(f32 *)(p + 0xc28) * timeDelta),
                             lbl_803E6B44, lbl_803E6ADC * timeDelta, 0);
        if (ev != 0) {
            if (ev == -1) {
                *(u16 *)(p + 0xc40) &= ~0x140;
                *(u8 *)(p + 0x9fd) &= ~2;
            } else {
                hightop_handleMotionEvent(obj, (u8)ev);
            }
        }
    } else {
        *(f32 *)(p + 0x290) = lbl_803E6AA8;
        *(f32 *)(p + 0x28c) = lbl_803E6AA8;
    }
    *(int *)(p + 0x31c) = 0;
    *(int *)(p + 0x318) = 0;
    *(s16 *)(p + 0x330) = 0;
    *(int *)p &= ~0x400000;
    (*(void (**)(int, char *, f32, f32, void **, void *))((char *)*gPlayerInterface + 0x8))(
        obj, p, (f32)(u32)framesThisStep, timeDelta, gHighTopStateHandlers, &gHighTopDefaultStateHandler);
    hightop_playMovementSfx(obj, (int)p, (int)p);
    characterDoEyeAnims(obj, (void *)(p + 0x38c));
    objAnimFn_80038f38(obj, (void *)(p + 0x3bc));
    dll_2E_func03(obj, (void *)(p + 0x3ec));
    if (ObjTrigger_IsSet(obj) != 0) {
        s8 v;
        buttonDisable(0, 0x100);
        v = (s8)p[0xc4b];
        if (v != -1) {
            if (v < 0xa) {
                (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(v, obj, -1);
            } else {
                GameBit_Set(*(s16 *)((char *)&lbl_803DC314 + v * 2 - 0x14), 1);
            }
        }
    }
    if ((int)randomGetRange(0, 0x64) == 0) {
        objSoundFn_800392f0(obj, (int)(p + 0x3bc), &lbl_8032AAB0[randomGetRange(0, 2) * 6], 0);
    }
    if (((BitFlags8 *)(p + 0xc49))->b7 != 0) {
        (*(void (**)(int, void *))((char *)*gGameUIInterface + 0x5c))(*(s16 *)(p + 0xc18), *gGameUIInterface);
        *(f32 *)(p + 0xc38) += timeDelta;
        if (*(f32 *)(p + 0xc38) > lbl_803E6B48) {
            *(f32 *)(p + 0xc38) -= lbl_803E6B48;
            Sfx_PlayFromObject(obj, 0x47f);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void kytesmum_playAnimationEventSfx(int obj, u8 *arg, s16 *sfxData) {
    u8 flags = 0;
    int i;
    for (i = 0; i < (s8)arg[0x1b]; i++) {
        switch ((s8)arg[i + 0x13]) {
        case 0:
            if (sfxData != 0) {
                Sfx_PlayFromObject(obj, (u16)sfxData[0]);
            }
            break;
        case 1:
            if (sfxData != 0) {
                Sfx_PlayFromObject(obj, (u16)sfxData[1]);
            }
            break;
        case 2:
            flags |= 1;
            break;
        case 3:
            flags |= 2;
            break;
        case 4:
            flags |= 4;
            break;
        case 5:
            flags |= 8;
            break;
        case 6:
        case 7:
            break;
        }
    }
    if (flags != 0 && sfxData != 0) {
        Sfx_PlayFromObject(obj, (u16)sfxData[3]);
    }
}
#pragma scheduling reset
