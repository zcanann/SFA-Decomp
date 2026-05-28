

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

extern f32 lbl_803E6978;
extern f32 lbl_803E69D0;
extern f32 lbl_803E69D8;

extern void *gKTRexState;
extern void *gKTRexRuntime;
extern undefined4 *gExpgfxInterface;
extern void ktrex_initialiseStateHandlerTables(void);
extern void objRenderFn_8003b8f4(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, double scale);
extern void ObjGroup_RemoveObject(int obj, int group);
extern void *Obj_GetPlayerObject(void);
extern void ModelLightStruct_free(void *p);

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
