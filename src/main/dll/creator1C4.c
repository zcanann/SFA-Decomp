#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/creator1C4.h"

#define SFXwp_swtst1_c 359

extern undefined8 FUN_80006728();
extern undefined4 FUN_80006770();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern void* ObjGroup_GetObjects();
extern undefined4 FUN_80042b9c();
extern int FUN_80044404();
extern undefined8 FUN_80080f28();
extern undefined4 FUN_801c70c4();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined4 FUN_801d8480();
extern undefined4 FUN_80286834();
extern undefined4 FUN_80286880();
extern uint FUN_80294cd0();

extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e5cc8;
extern f32 lbl_803DC074;
extern f32 lbl_803E5CD4;
extern f32 lbl_803E5CD8;
extern void gpsh_shrine_SeqFn(void);
extern void *objCreateLight(int obj, int kind);

/*
 * --INFO--
 *
 * Function: gpsh_shrine_update
 * EN v1.0 Address: 0x801C7724
 * EN v1.0 Size: 2520b
 * EN v1.1 Address: 0x801C7CD8
 * EN v1.1 Size: 2124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct {
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b10 : 1;
    u8 b08 : 1;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} GpshShrineFlags;

extern void *Obj_GetPlayerObject(void);
extern u32 GameBit_Get(int bit);
extern int GameBit_Set(int bit, int val);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern void skyFn_80088c94(int a, int b);
extern int getEnvfxAct(int obj, int player, int id, int p);
extern void fn_801C70F0(int obj);
extern int mapGetDirIdx(int a);
extern int unlockLevel(int a, int b, int c);
extern void SCGameBitLatch_Update(int state, int a, int b, int c, int d, int e);
extern void SCGameBitLatch_UpdateInverted(int state, int a, int b, int c, int d, int e);
extern void gameTimerInit(int a, int b);
extern void timerSetToCountUp(void);
extern void gameTimerStop(void);
extern int isGameTimerDisabled(void);
extern int Obj_FreeObject(int obj);
extern int objGetAnimStateFlags(int obj, int flag);
extern void audioStopByMask(int mask);
extern int Music_Trigger(int id, int value);
extern int *gObjectTriggerInterface;
extern int *gScreenTransitionInterface;
extern int *gMapEventInterface;
extern f32 timeDelta;
extern f32 lbl_803E503C;
extern f32 lbl_803E5040;

#pragma scheduling off
#pragma peephole off
void gpsh_shrine_update(int obj)
{
    int count;
    int data = *(int *)((char *)obj + 0xb8);
    char *player = Obj_GetPlayerObject();
    u8 b149;
    u8 b14c;
    u8 b14d;
    u8 b14e;
    u8 b14a;
    u8 b14b;
    int *objs;
    f32 t;
    f32 k;

    count = 0;
    if (player != NULL) {
        b149 = GameBit_Get(0x149);
        b14c = GameBit_Get(0x14c);
        b14d = GameBit_Get(0x14d);
        b14e = GameBit_Get(0x14e);
        b14a = GameBit_Get(0x14a);
        b14b = GameBit_Get(0x14b);
        if (b149 == 0 || b14c == 0 || b14d == 0 || b14e == 0 || b14a == 0 || b14b == 0) {
            if (!((GpshShrineFlags *)((char *)data + 0x15))->b40 && b149 != 0) {
                ((GpshShrineFlags *)((char *)data + 0x15))->b40 = 1;
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            } else if (!((GpshShrineFlags *)((char *)data + 0x15))->b20 && b14c != 0) {
                ((GpshShrineFlags *)((char *)data + 0x15))->b20 = 1;
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            } else if (!((GpshShrineFlags *)((char *)data + 0x15))->b10 && b14d != 0) {
                ((GpshShrineFlags *)((char *)data + 0x15))->b10 = 1;
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            } else if (!((GpshShrineFlags *)((char *)data + 0x15))->b08 && b14e != 0) {
                ((GpshShrineFlags *)((char *)data + 0x15))->b08 = 1;
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            } else if (!((GpshShrineFlags *)((char *)data + 0x15))->b04 && b14a != 0) {
                ((GpshShrineFlags *)((char *)data + 0x15))->b04 = 1;
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            } else if (!((GpshShrineFlags *)((char *)data + 0x15))->b02 && b14b != 0) {
                ((GpshShrineFlags *)((char *)data + 0x15))->b02 = 1;
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            }
        }
        if (*(int *)((char *)obj + 0xf4) != 0) {
            *(int *)((char *)obj + 0xf4) -= 1;
            if (*(int *)((char *)obj + 0xf4) == 0) {
                skyFn_80088c94(7, 1);
                getEnvfxAct(obj, (int)player, 0xcc, 0);
                getEnvfxAct(obj, (int)player, 0xcd, 0);
                getEnvfxAct(obj, (int)player, 0x222, 0);
            }
        }
        fn_801C70F0(obj);
        unlockLevel(mapGetDirIdx(0x22), 1, 0);
        SCGameBitLatch_Update(data + 0x13, 2, -1, -1, 0xdd2, 0xb);
        SCGameBitLatch_UpdateInverted(data + 0x13, 1, -1, -1, 0xcbb, 8);
        SCGameBitLatch_Update(data + 0x13, 4, -1, -1, 0xcbb, 0xc4);
        k = lbl_803E503C;
        if (*(f32 *)((char *)data + 4) > k) {
            *(f32 *)((char *)data + 4) -= timeDelta;
            if (*(f32 *)((char *)data + 4) <= k) {
                *(f32 *)((char *)data + 4) = k;
            }
        } else {
            switch (*(u8 *)((char *)data + 0x14)) {
            case 0:
                *(s16 *)((char *)obj + 6) &= ~0x4000;
                t = *(f32 *)((char *)data + 8) - timeDelta;
                *(f32 *)((char *)data + 8) = t;
                if (t <= k) {
                    Sfx_PlayFromObject(obj, 0x343);
                    *(f32 *)((char *)data + 8) = (f32)(int)randomGetRange(500, 1000);
                }
                if (*(u8 *)((char *)obj + 0xaf) & 1) {
                    *(u8 *)((char *)data + 0x14) = 5;
                    GameBit_Set(0x129, 0);
                    GameBit_Set(0x5af, 0);
                    GameBit_Set(0xdd2, 1);
                    (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(0, obj, -1);
                    Music_Trigger(0xd8, 1);
                }
                break;
            case 5:
                *(f32 *)((char *)data + 4) = lbl_803E5040;
                (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0xc)))(0x1e, 1);
                *(u8 *)((char *)data + 0x14) = 1;
                *(s16 *)((char *)obj + 6) |= 0x4000;
                break;
            case 1:
                if (((GpshShrineFlags *)((char *)data + 0x15))->b80 == 1) {
                    GameBit_Set(0x148, 1);
                    *(u8 *)((char *)data + 0x14) = 2;
                    gameTimerInit(0x1d, 0x4e);
                    timerSetToCountUp();
                }
                break;
            case 2:
                *(u8 *)((char *)data + 0x12) = 0;
                if (GameBit_Get(0x149)) {
                    *(u8 *)((char *)data + 0x12) += 1;
                }
                if (GameBit_Get(0x14b)) {
                    *(u8 *)((char *)data + 0x12) += 1;
                }
                if (GameBit_Get(0x14e)) {
                    *(u8 *)((char *)data + 0x12) += 1;
                }
                if (GameBit_Get(0x14d)) {
                    *(u8 *)((char *)data + 0x12) += 1;
                }
                if (GameBit_Get(0x14c)) {
                    *(u8 *)((char *)data + 0x12) += 1;
                }
                if (GameBit_Get(0x14a)) {
                    *(u8 *)((char *)data + 0x12) += 1;
                }
                if (*(u8 *)((char *)data + 0x12) == 6) {
                    *(u8 *)((char *)data + 0x14) = 6;
                    gameTimerStop();
                    GameBit_Set(0xdd2, 0);
                    *(f32 *)((char *)data + 4) = lbl_803E5040;
                    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 8)))(0x1e, 1);
                    Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
                } else if (isGameTimerDisabled()) {
                    *(u8 *)((char *)data + 0x14) = 7;
                    objs = (int *)ObjGroup_GetObjects(0x10, &count);
                    for (; count != 0; count--) {
                        Obj_FreeObject(objs[count - 1]);
                    }
                    *(f32 *)((char *)data + 4) = lbl_803E5040;
                    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 8)))(0x1e, 1);
                } else {
                    *(u8 *)((char *)data + 0x12) = 0;
                }
                break;
            case 7:
                *(u8 *)((char *)data + 0x14) = 4;
                GameBit_Set(0xdd2, 0);
                GameBit_Set(0xe37, 1);
                break;
            case 6:
                *(u8 *)((char *)data + 0x14) = 3;
                break;
            case 3:
                if (objGetAnimStateFlags((int)player, 0x80)) {
                    GameBit_Set(0x129, 1);
                    *(u8 *)((char *)data + 0x14) = 4;
                } else {
                    audioStopByMask(3);
                    (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(1, obj, -1);
                    *(u8 *)((char *)data + 0x14) = 4;
                    GameBit_Set(0x36a, 0);
                    (*(void (*)(int, int, int))(*(int *)(*gMapEventInterface + 0x50)))(0xd, 0, 1);
                    (*(void (*)(int, int, int))(*(int *)(*gMapEventInterface + 0x50)))(0xd, 1, 1);
                    (*(void (*)(int, int, int))(*(int *)(*gMapEventInterface + 0x50)))(0xd, 5, 1);
                    (*(void (*)(int, int, int))(*(int *)(*gMapEventInterface + 0x50)))(0xd, 10, 1);
                    (*(void (*)(int, int, int))(*(int *)(*gMapEventInterface + 0x50)))(0xd, 0xb, 1);
                    GameBit_Set(0xc91, 1);
                    GameBit_Set(0xe05, 0);
                }
                break;
            case 4:
                *(u8 *)((char *)data + 0x14) = 0;
                ((GpshShrineFlags *)((char *)data + 0x15))->b80 = 0;
                GameBit_Set(0xdd2, 0);
                GameBit_Set(0x129, 1);
                GameBit_Set(0x149, 0);
                GameBit_Set(0x14c, 0);
                GameBit_Set(0x14d, 0);
                GameBit_Set(0x14e, 0);
                GameBit_Set(0x14a, 0);
                GameBit_Set(0x14b, 0);
                GameBit_Set(0x14b, 0);
                GameBit_Set(0x5af, 1);
                GameBit_Set(0x148, 0);
                GameBit_Set(0xe37, 0);
                GameBit_Set(0xe3a, 0);
                ((GpshShrineFlags *)((char *)data + 0x15))->b40 = 0;
                ((GpshShrineFlags *)((char *)data + 0x15))->b20 = 0;
                ((GpshShrineFlags *)((char *)data + 0x15))->b10 = 0;
                ((GpshShrineFlags *)((char *)data + 0x15))->b08 = 0;
                ((GpshShrineFlags *)((char *)data + 0x15))->b04 = 0;
                ((GpshShrineFlags *)((char *)data + 0x15))->b02 = 0;
                break;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
void gpsh_shrine_init(int *obj, int *def) {
    u8 *state;

    state = *(u8 **)((char *)obj + 0xb8);
    *(s16 *)obj = 0;
    *(void **)((char *)obj + 0xbc) = (void *)gpsh_shrine_SeqFn;
    *(f32 *)((char *)obj + 0x18) = *(f32 *)((char *)obj + 0xc);
    *(f32 *)((char *)obj + 0x1c) = *(f32 *)((char *)obj + 0x10);
    *(f32 *)((char *)obj + 0x20) = *(f32 *)((char *)obj + 0x14);
    state[0x14] = 0;
    state[0x15] &= 0x7f;
    GameBit_Set(0x129, 1);
    GameBit_Set(0x12b, 0);
    GameBit_Set(0x149, 0);
    GameBit_Set(0x14c, 0);
    GameBit_Set(0x14d, 0);
    GameBit_Set(0x14e, 0);
    GameBit_Set(0x14a, 0);
    GameBit_Set(0x14b, 0);
    *(int *)((char *)obj + 0xf4) = 1;
    if (*(void **)state == NULL) {
        *(void **)state = objCreateLight(0, 1);
    }
    GameBit_Set(0xea1, 1);
    GameBit_Set(0xefa, 1);
}
#pragma peephole reset
#pragma scheduling reset

/* Trivial 4b 0-arg blr leaves. */
void gpsh_shrine_release(void) {}
void gpsh_shrine_initialise(void) {}
void gpsh_objcreator_free(void) {}
void gpsh_objcreator_hitDetect(void) {}
void gpsh_objcreator_release(void) {}
void gpsh_objcreator_initialise(void) {}

extern u8 Obj_IsLoadingLocked(void);
extern void hitDetectFn_80097070(int *obj, int a, int b, int c, int d, f32 e);
extern void Sfx_PlayFromObjectLimited(int obj, int sfx, int v);
extern void *Obj_AllocObjectSetup(int size, int type);
extern int* Obj_SetupObject(void *setup, int a, int b, int c, void *d);
extern f32 timeDelta;
extern f32 lbl_803E504C;
extern f32 lbl_803E5050;
extern f32 lbl_803E5054;
extern s16 lbl_803263B8[];

#pragma scheduling off
#pragma peephole off
void gpsh_objcreator_update(int *obj) {
    u8 *sub;
    void *setup;

    sub = *(u8**)((char*)obj + 0xb8);
    if (GameBit_Get(0x5af) != 0) {
        *(int*)((char*)obj + 0xf8) = 0;
        ((GpshShrineFlags *)(sub + 5))->b80 = 0;
        *(u8*)((char*)obj + 0x37) = 0xff;
        *(u8*)((char*)obj + 0x36) = 0xff;
    }
    if (((GpshShrineFlags *)(sub + 5))->b80) return;
    if (*(int*)((char*)obj + 0xf8) == 0) {
        if (GameBit_Get(0x148) != 0) {
            *(f32*)sub = lbl_803E504C;
            *(int*)((char*)obj + 0xf8) = 1;
        }
    }
    if ((u8)Obj_IsLoadingLocked() == 0) return;
    if (*(f32*)sub == lbl_803E5050) return;
    *(f32*)sub = *(f32*)sub - timeDelta;
    hitDetectFn_80097070(obj, 2, 1, 1, 0, lbl_803E5054);
    if (*(f32*)sub <= lbl_803E5050) {
        Sfx_PlayFromObjectLimited(0, SFXwp_swtst1_c, 1);
        setup = Obj_AllocObjectSetup(0x24, sub[4] + 0x1f4);
        ((GpshShrineFlags *)(sub + 5))->b80 = 1;
        *(u8*)((char*)setup + 7) = 0xff;
        *(u8*)((char*)setup + 4) = 0x20;
        *(u8*)((char*)setup + 5) = 2;
        *(f32*)((char*)setup + 8) = *(f32*)((char*)obj + 0xc);
        *(f32*)((char*)setup + 0xc) = *(f32*)((char*)obj + 0x10);
        *(f32*)((char*)setup + 0x10) = *(f32*)((char*)obj + 0x14);
        *(s16*)setup = (s16)(sub[4] + 0x1f4);
        *(u8*)((char*)setup + 0x18) = (u8)((s32)*(s16*)obj >> 8);
        *(s16*)((char*)setup + 0x1a) = lbl_803263B8[sub[4]];
        Obj_SetupObject(setup, 5, *(s8*)((char*)obj + 0xac), -1, *(void**)((char*)obj + 0x30));
    }
}
#pragma peephole reset
#pragma scheduling reset
void gpsh_scene_free(void) {}
void gpsh_scene_hitDetect(void) {}
void gpsh_scene_update(void) {}
void gpsh_scene_release(void) {}
void gpsh_scene_initialise(void) {}
void ecsh_cup_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int gpsh_objcreator_getExtraSize(void) { return 0x8; }
int gpsh_objcreator_getObjectTypeId(void) { return 0x0; }
int gpsh_scene_getExtraSize(void) { return 0x0; }
int gpsh_scene_getObjectTypeId(void) { return 0x0; }
int ecsh_cup_getExtraSize(void) { return 0x30; }
int ecsh_cup_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5048;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5058;
extern f32 lbl_803E5060;
#pragma peephole off
void gpsh_objcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5048); }
void gpsh_scene_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5058); }
void ecsh_cup_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5060); }
#pragma peephole reset

extern undefined4 *gExpgfxInterface;
#pragma scheduling off
#pragma peephole off
void ecsh_cup_free(int *obj) {
    ((void (*)(int *))((void **)*gExpgfxInterface)[6])(obj);
}
void gpsh_scene_init(int *obj, int *def) {
    *(s16 *)obj = (s16)((s32)*(s8 *)((char *)def + 0x18) << 8);
    *(f32 *)((char *)obj + 0x18) = *(f32 *)((char *)obj + 0xc);
    *(f32 *)((char *)obj + 0x1c) = *(f32 *)((char *)obj + 0x10);
    *(f32 *)((char *)obj + 0x20) = *(f32 *)((char *)obj + 0x14);
    *(u8 *)((char *)obj + 0xaf) = (u8)(*(u8 *)((char *)obj + 0xaf) | 8);
}
void gpsh_objcreator_init(int *obj, int *def) {
    register u32 zero;
    register int *state;
    state = *(int **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s32)*(s8 *)((char *)def + 0x1e) << 8);
    zero = 0;
    *(int *)((char *)obj + 0xf8) = zero;
    *(u8 *)((char *)state + 4) = (u8)*(s16 *)((char *)def + 0x1a);
    ((GpshShrineFlags *)((char *)state + 5))->b80 = 0;
    *(u8 *)((char *)obj + 0x37) = 0xff;
    *(u8 *)((char *)obj + 0x36) = 0xff;
}
#pragma peephole reset
#pragma scheduling reset
