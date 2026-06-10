#include "main/dll/explosion_state.h"
#include "main/dll/explosion.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/resource.h"

typedef struct Dll197State {
    u8 pad0[0x2 - 0x0];
    s16 unk2;
    s16 unk4;
    u8 pad6[0x8 - 0x6];
    s16 unk8;
    s16 unkA;
    u8 unkC;
    u8 unkD;
    u8 unkE;
    u8 unkF;
    u8 unk10;
    u8 pad11[0x18 - 0x11];
} Dll197State;



extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80006c10();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_8001771c();
extern int FUN_80017a98();
extern int ObjHits_GetPriorityHit();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern int FUN_80044404();
extern undefined4 FUN_80055ef0();
extern undefined4 FUN_80057690();
extern undefined8 FUN_80080f28();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80294ccc();

extern undefined4 DAT_802c2b48;
extern undefined4 DAT_802c2b4c;
extern undefined4 DAT_802c2b50;
extern undefined4 DAT_802c2b54;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc270;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern undefined4* DAT_803dd6f0;
extern MapEventInterface **gMapEventInterface;
extern undefined4 DAT_803de850;
extern undefined4 DAT_803de858;
extern f64 DOUBLE_803e5de0;
extern f32 lbl_803E5DD0;
extern f32 lbl_803E5DD4;
extern f32 lbl_803E5DD8;
extern f32 lbl_803E5DDC;

/*
 * --INFO--
 *
 * Function: dll_197_init
 * EN v1.0 Address: 0x801CA5B4
 * EN v1.0 Size: 1148b
 * EN v1.1 Address: 0x801CA6BC
 * EN v1.1 Size: 1196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 lbl_803E513C;
extern f32 lbl_803E5140;
extern f32 lbl_803E5144;
extern f64 lbl_803E5148;

void dll_197_init(int obj, int data)
{
    u8 *st;
    void *res;
    struct {
        u8 buf[16];
        f32 f;
    } stk;

    st = ((GameObject *)obj)->extra;
    *(s16 *)obj = (s16)(((s8)*(u8 *)(data + 0x18) & 0x3fu) << 10);
    if (*(s16 *)(data + 0x1a) > 0) {
        ((GameObject *)obj)->anim.rootMotionScale = (f32)*(s16 *)(data + 0x1a) / lbl_803E5140;
    } else {
        ((GameObject *)obj)->anim.rootMotionScale = lbl_803E5144;
    }
    *(u8 *)(st + 0xb) = *(u8 *)(data + 0x19);
    ((Dll197State *)st)->unkC = 0;
    ((Dll197State *)st)->unkF = 0;
    *(int *)st = *(s16 *)(data + 0x1e);
    stk.f = lbl_803E513C;
    switch (*(u8 *)(st + 0xb)) {
    case 0:
        ((Dll197State *)st)->unkC = 1;
        res = Resource_Acquire(0x69, 1);
        if (*(s16 *)(data + 0x1c) == 0) {
            (*(void (**)(int, int, void *, int, int, int))(*(int *)res + 4))(obj, 0, stk.buf, 0x10004, -1, 0);
        }
        break;
    case 1:
        ((Dll197State *)st)->unkF = *(s16 *)(data + 0x1c);
        ((Dll197State *)st)->unkD = 0;
        ((Dll197State *)st)->unk8 = ((Dll197State *)st)->unkF * 0x28 + 0x398;
        ((Dll197State *)st)->unkE = 0;
        break;
    }
    ((Dll197State *)st)->unk4 = 0;
}


/*
 * --INFO--
 *
 * Function: FUN_801caa30
 * EN v1.0 Address: 0x801CAA30
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x801CAB68
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801cacd4
 * EN v1.0 Address: 0x801CACD4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801CAE40
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cacd4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}


/*
 * --INFO--
 *
 * Function: FUN_801caeac
 * EN v1.0 Address: 0x801CAEAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CAEF8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801caeb0
 * EN v1.0 Address: 0x801CAEB0
 * EN v1.0 Size: 1240b
 * EN v1.1 Address: 0x801CAF74
 * EN v1.1 Size: 788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on



/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void dll_197_release(void) {}
void dll_197_initialise(void) {}
void nwsh_levcon_hitDetect(void) {}
void nwsh_levcon_release(void) {}
void nwsh_levcon_initialise(void) {}
void dll_199_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int nwsh_levcon_getExtraSize(void) { return 0x0; }
int nwsh_levcon_getObjectTypeId(void) { return 0x0; }
int dll_199_getExtraSize(void) { return 0x14; }
int dll_199_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5150;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5158;
void nwsh_levcon_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5150); }
void dll_199_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5158); }

extern void Music_Trigger(int track, int param);
extern int GameBit_Set(int eventId, int value);
void nwsh_levcon_free(int obj) {
    Music_Trigger(6, 0);
    GameBit_Set(3837, 0);
}

extern int mapGetDirIdx(int mapId);
extern void unlockLevel(int a, int b, int c);
extern void skyFn_80088c94(int a, int b);
extern void getEnvfxAct(int a, int b, int c, int d);

void nwsh_levcon_update(int *obj) {
    if (((GameObject *)obj)->unkF4 != 0) {
        ((GameObject *)obj)->unkF4 = ((GameObject *)obj)->unkF4 - 1;
        if (((GameObject *)obj)->unkF4 == 0) {
            skyFn_80088c94(7, 1);
            getEnvfxAct(0, 0, 0xd1, 0);
            getEnvfxAct(0, 0, 0xd6, 0);
            getEnvfxAct(0, 0, 0x222, 0);
        }
    }
}

void nwsh_levcon_init(int *obj) {
    ((GameObject *)obj)->animEventCallback = (void *)NWSH_levcon_SeqFn;
    unlockLevel(mapGetDirIdx(0x28), 1, 0);
    Music_Trigger(6, 1);
    ((GameObject *)obj)->unkF4 = 1;
    GameBit_Set(0xea2, 1);
    GameBit_Set(0xefd, 1);
}

extern ModgfxInterface **gModgfxInterface;
extern void *gTitleMenuControlInterface;

void dll_199_free(int *obj) {
    (*gModgfxInterface)->detachSource(obj);
    ((void(*)(int, int))((void**)*(void**)gTitleMenuControlInterface)[14])(3, 0);
    ((void(*)(int, int))((void**)*(void**)gTitleMenuControlInterface)[14])(2, 0);
}

extern void *Obj_GetPlayerObject(void);
extern void fn_80296518(void *player, int a, int b);
extern int getButtonsHeld(int pad);
extern int return0_8005669C(int p);
extern int lbl_803DB610;
extern u32 lbl_803DDBD8;

int NWSH_levcon_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate)
{
    void *player;
    int i;

    player = Obj_GetPlayerObject();
    if (player != 0) {
        for (i = 0; i < animUpdate->eventCount; i++) {
            if (animUpdate->eventIds[i] != 1) {
            } else {
                fn_80296518(player, 0x10, 1);
                GameBit_Set(0x174, 1);
                (*gMapEventInterface)->setAnimEvent(0xb, 4, 1);
                (*gMapEventInterface)->setAnimEvent(0xb, 0x1d, 1);
                (*gMapEventInterface)->setAnimEvent(0xb, 0x1e, 1);
                (*gMapEventInterface)->setAnimEvent(0xb, 0x1f, 1);
                (*gMapEventInterface)->setMode(0xb, 6);
            }
        }
    }
    return 0;
}

int dll_199_SeqFn(int obj, int p2, ObjAnimUpdateState *animUpdate)
{
    u8 *st;
    int i;
    u8 eventId;

    st = ((GameObject *)obj)->extra;
    animUpdate->activeHitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    if (*(s16 *)(st + 0xa) != 0) {
        *(s16 *)(st + 8) += *(s16 *)(st + 0xa);
        if (*(s16 *)(st + 8) <= 1 && *(s16 *)(st + 0xa) <= 0) {
            *(s16 *)(st + 8) = 1;
            *(s16 *)(st + 0xa) = 0;
        } else if (*(s16 *)(st + 8) >= 0x46 && *(s16 *)(st + 0xa) >= 0) {
            *(s16 *)(st + 8) = 0x46;
            *(s16 *)(st + 0xa) = 0;
        }
        (**(void (**)(int, int))(*(int *)gTitleMenuControlInterface + 0x38))(3, *(s16 *)(st + 8) & 0xff);
    }
    for (i = 0; i < animUpdate->eventCount; i++) {
        eventId = animUpdate->eventIds[i];
        switch (eventId) {
        case 0xb:
            *(u8 *)(st + 0xf) = 7;
            break;
        case 1:
            getEnvfxAct(obj, obj, 0xc3, 0);
            break;
        case 2:
            if (lbl_803DB610 == -1) {
                getEnvfxAct(obj, obj, 0x14, 0);
            } else {
                getEnvfxAct(obj, obj, (u16)lbl_803DB610, 0);
            }
            break;
        case 3:
            *(u8 *)(st + 0x10) = 1;
            break;
        case 4:
            *(u8 *)(st + 0xf) = 4;
            *(u8 *)(st + 0x10) = 2;
            GameBit_Set(0x129, 1);
            GameBit_Set(0x1cf, 0);
            GameBit_Set(0x126, 1);
            *(s16 *)(st + 0xa) = -3;
            break;
        case 5:
            *(u8 *)(st + 0x10) = 3;
            *(s16 *)(st + 0xa) = -3;
            GameBit_Set(0x129, 1);
            break;
        case 6:
            GameBit_Set(0x1cf, 1);
            break;
        case 7:
            GameBit_Set(0x1cf, 0);
            *(s16 *)(st + 0xa) = -3;
            break;
        case 9:
            GameBit_Set(0x128, 1);
            if (lbl_803DDBD8 == 0) {
                lbl_803DDBD8 = return0_8005669C(1);
            }
            break;
        case 8:
            GameBit_Set(0x127, 1);
            break;
        case 10:
            *(s16 *)(st + 8) = 100;
            (**(void (**)(int, int, int, int, int))(*(int *)gTitleMenuControlInterface + 0x18))(3, 0x2d, 0x50, *(s16 *)(st + 8) & 0xff, 0);
            break;
        }
        animUpdate->eventIds[i] = 0;
    }
    if (*(u8 *)(st + 0xf) != 7) {
    } else {
        if ((getButtonsHeld(0) & 0x100) != 0) {
            (*gObjectTriggerInterface)->endSequence(animUpdate->sequenceSlot);
            *(u8 *)(st + 0xf) = 8;
            *(s16 *)(st + 2) = 0;
        } else if ((getButtonsHeld(0) & 0x200) != 0) {
            (*gObjectTriggerInterface)->endSequence(animUpdate->sequenceSlot);
            *(u8 *)(st + 0xf) = 7;
            *(s16 *)(st + 2) = 0;
        }
    }
    return 0;
}
