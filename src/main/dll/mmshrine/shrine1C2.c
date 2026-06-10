#include "main/audio/sfx_ids.h"
#include "main/game_ui_interface.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/mapEventTypes.h"
#include "main/dll/mmshrine/shrine1C2.h"
#include "main/dll/mmshrine/torch1C1.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "main/screen_transition.h"

typedef struct EcshShrineState {
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    u8 padC[0x18 - 0xC];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    s16 unk26;
    u8 pad28[0x2E - 0x28];
    u8 unk2E;
    u8 unk2F;
    u8 unk30;
    u8 pad31[0x32 - 0x31];
    u8 unk32;
    u8 pad33[0x34 - 0x33];
    s32 unk34;
} EcshShrineState;


extern undefined8 FUN_80006728();
extern undefined4 FUN_80006770();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017710();
extern uint FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017830();
extern int FUN_80017a98();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_8002fc3c();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 FUN_8003b818();
extern undefined8 FUN_80080f28();
extern undefined4 FUN_8008111c();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined4 FUN_801d8480();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293f90();
extern uint FUN_80294be4();
extern undefined4 FUN_80294c30();
extern undefined4 FUN_80294ccc();
extern uint FUN_80294cd0();
extern uint countLeadingZeros();

extern undefined4 DAT_80326e48;
extern undefined4 DAT_80326e4c;
extern undefined4 DAT_80326e50;
extern undefined4 DAT_80326e54;
extern undefined4 DAT_80326e58;
extern undefined4 DAT_80326e5c;
extern undefined4 DAT_80326e60;
extern undefined4 DAT_80326e64;
extern undefined4 DAT_80326e68;
extern undefined4 DAT_80326e6c;
extern undefined4 DAT_80326e70;
extern undefined4 DAT_80326e74;
extern undefined4 DAT_80326e78;
extern undefined4 DAT_80326e7a;
extern undefined4 DAT_80326e7c;
extern undefined4 DAT_80326e7e;
extern undefined4 DAT_80326e80;
extern undefined4 DAT_80326e82;
extern undefined4 DAT_80326e84;
extern undefined4 DAT_80326e86;
extern undefined4 DAT_80326e88;
extern undefined4 DAT_80326e8a;
extern undefined4 DAT_80326e8c;
extern undefined4 DAT_80326e8e;
extern undefined4 DAT_80326e90;
extern undefined4 DAT_803dc070;
extern MapEventInterface **gMapEventInterface;
extern undefined4 DAT_803de840;
extern undefined4 DAT_803de844;
extern undefined4 DAT_803e90f0;
extern undefined4 DAT_803e90f4;
extern f64 DOUBLE_803e5c58;
extern f64 DOUBLE_803e5cc8;
extern f32 lbl_803DC074;
extern f32 lbl_803E5C40;
extern f32 lbl_803E5C48;
extern f32 lbl_803E5C64;
extern f32 lbl_803E5C68;
extern f32 lbl_803E5C6C;
extern f32 lbl_803E5C70;
extern f32 lbl_803E5C74;
extern f32 lbl_803E5C78;
extern f32 lbl_803E5C7C;
extern f32 lbl_803E5C80;
extern f32 lbl_803E5C84;
extern f32 lbl_803E5C88;
extern f32 lbl_803E5C98;
extern f32 lbl_803E5C9C;
extern f32 lbl_803E5CA0;
extern f32 lbl_803E5CA4;
extern f32 lbl_803E5CB0;
extern f32 lbl_803E5CB4;
extern f32 lbl_803E5CB8;
extern f32 lbl_803E5CBC;
extern f32 lbl_803E5CC0;
extern f32 lbl_803E5CD0;

/*
 * --INFO--
 *
 * Function: ecsh_shrine_update
 * EN v1.0 Address: 0x801C60B8
 * EN v1.0 Size: 3360b
 * EN v1.1 Address: 0x801C666C
 * EN v1.1 Size: 3104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void skyFn_80088c94(int a, int b);
extern void getEnvfxAct(s16 *obj, int *target, int id, int p);
extern void fn_801C5990(s16 *obj);
extern int objIsCurModelNotZero(int *player);
extern void fn_80295CF4(int *player, int a);
extern void SCGameBitLatch_Update(u8 *latch, int mask, int a, int b, int bit, int c);
extern void SCGameBitLatch_UpdateInverted(u8 *latch, int mask, int a, int b, int bit, int c);
extern void audioStopByMask(int mask);
extern int objGetAnimStateFlags(int *player, int flags);
extern void Sfx_KeepAliveLoopedObjectSound(s16 *obj, int sfxId);
extern void Sfx_PlayFromObject(s16 *obj, int sfxId);
extern void Music_Trigger(int id, int restart);
extern void GameBit_Set(int bit, int value);
extern int GameBit_Get(int bit);
extern int *Obj_GetPlayerObject(void);
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern ScreenTransitionInterface **gScreenTransitionInterface;
extern u8 lbl_80326208[];
extern int lbl_803E8470;
extern int lbl_803E8474;
extern f32 timeDelta;
extern f32 lbl_803E4FA8;
extern f32 lbl_803E4FB0;
extern f32 lbl_803E4FCC;
extern f32 lbl_803E4FD0;
extern f32 lbl_803E4FD4;
extern f32 lbl_803E4FD8;
extern f32 lbl_803E4FDC;
extern f32 lbl_803E4FE0;
extern f32 lbl_803E4FE4;
extern f32 lbl_803E4FE8;
extern f32 lbl_803E4FEC;
extern f32 lbl_803E4FF0;

typedef struct EcshPuzzleState {
    f32 f[12];   /* 0x00 */
    s16 cur[6];  /* 0x30 */
    s16 next[7]; /* 0x3c */
} EcshPuzzleState;

typedef struct EcshIntPair {
    int a;
    int b;
} EcshIntPair;

#pragma opt_strength_reduction off
void ecsh_shrine_update(s16 *obj)
{
    f32 t[2];
    int msgC;
    int msgA;
    int msgB;
    EcshPuzzleState *ps;
    u8 *sub;
    int *player;
    u8 gv;
    int pick;
    int n;
    s16 sc;
    f32 z;
    f32 fv;

    ps = (EcshPuzzleState *)lbl_80326208;
    sub = ((GameObject *)obj)->extra;
    player = Obj_GetPlayerObject();
    *(EcshIntPair *)&t[0] = *(EcshIntPair *)&lbl_803E8470;
    if (sub[0x32] == 0) {
        gv = GameBit_Get(0x58b);
        sub[0x32] = gv;
        if (sub[0x32] != 0) {
            (*gGameUIInterface)->showNpcDialogue(0x285, 0x14, 0x8c, 1);
        }
    }
    if (((GameObject *)obj)->unkF4 != 0) {
        ((GameObject *)obj)->unkF4 = ((GameObject *)obj)->unkF4 - 1;
        if (((GameObject *)obj)->unkF4 == 0) {
            skyFn_80088c94(7, 1);
            getEnvfxAct(obj, player, 0x221, 0);
            getEnvfxAct(obj, player, 0x220, 0);
            getEnvfxAct(obj, player, 0x222, 0);
        }
    }
    fn_801C5990(obj);
    if (player != NULL && objIsCurModelNotZero(player) == 0) {
        fn_80295CF4(player, 0);
    }
    msgC = 0;
    while (ObjMsg_Pop(obj, &msgA, &msgB, &msgC) != 0) {
    }
    SCGameBitLatch_Update(sub + 0x34, 2, -1, -1, 0xb9d, 0xd);
    SCGameBitLatch_UpdateInverted(sub + 0x34, 1, -1, -1, 0xcbb, 8);
    SCGameBitLatch_Update(sub + 0x34, 0x10, -1, -1, 0xcbb, 0xc4);
    if (((EcshShrineState *)sub)->unk8 > (z = *(f32 *)&lbl_803E4FCC)) {
        ((EcshShrineState *)sub)->unk8 = ((EcshShrineState *)sub)->unk8 - timeDelta;
        if (((EcshShrineState *)sub)->unk8 <= z) {
            ((EcshShrineState *)sub)->unk8 = z;
        }
    } else {
        switch (sub[0x2f]) {
        case 0:
            ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            fv = *(f32 *)(sub + 0x10) - timeDelta;
            *(f32 *)(sub + 0x10) = fv;
            if (fv <= z) {
                Sfx_PlayFromObject(obj, 0x343);
                *(f32 *)(sub + 0x10) = (f32)(int)randomGetRange(500, 1000);
            }
            if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) != 0) {
                sub[0x2f] = 1;
                GameBit_Set(0x129, 0);
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                Music_Trigger(0xd8, 1);
                {
                    f32 fz = lbl_803E4FCC;
                    ps->f[0] = fz;
                    ps->f[1] = fz;
                    ps->f[2] = fz;
                    ps->f[3] = fz;
                    ps->f[4] = fz;
                    ps->f[5] = fz;
                    ps->f[6] = fz;
                    ps->f[7] = fz;
                    ps->f[8] = fz;
                    ps->f[9] = fz;
                    ps->f[10] = fz;
                    ps->f[11] = fz;
                }
                ps->cur[0] = ps->next[0];
                ps->cur[1] = ps->next[1];
                ps->cur[2] = ps->next[2];
                ps->cur[3] = ps->next[3];
                ps->cur[4] = ps->next[4];
                ps->cur[5] = ps->next[5];
                ps->next[0] = ps->next[6];
            }
            break;
        case 1:
            if (sub[0x30] == 1) {
                sub[0x2f] = 2;
                ((EcshShrineState *)sub)->unk8 = lbl_803E4FD0;
                ((EcshShrineState *)sub)->unk24 = 6;
                Sfx_PlayFromObject(obj, 0x16f);
                ((EcshShrineState *)sub)->unk4 = lbl_803E4FCC;
                GameBit_Set(0xb9d, 1);
                (*gScreenTransitionInterface)->step(0x78, 1);
            }
            ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            break;
        case 2:
            sub[0x2f] = 3;
            ((EcshShrineState *)sub)->unk8 = lbl_803E4FD4;
            ((EcshShrineState *)sub)->unk24 = 8;
            ((EcshShrineState *)sub)->unk4 = lbl_803E4FD8;
            ((EcshShrineState *)sub)->unk22 = 5;
            gv = randomGetRange(0, 5);
            sub[0x2e] = gv;
            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
            break;
        case 3:
        case 4:
        case 5:
            if (((EcshShrineState *)sub)->unk4 > (fv = lbl_803E4FCC)) {
                if (((EcshShrineState *)sub)->unk24 == 1 && sub[0x31] == 0
                    && ((EcshShrineState *)sub)->unk4 < *(f32 *)(sub + 0x14)) {
                    if ((int)randomGetRange(0, 10) > 7) {
                        Sfx_PlayFromObject(obj, 0x345);
                    }
                    sub[0x31] = 1;
                }
                ((EcshShrineState *)sub)->unk4 = ((EcshShrineState *)sub)->unk4 - timeDelta;
                if (((EcshShrineState *)sub)->unk4 < lbl_803E4FCC) {
                    ((EcshShrineState *)sub)->unk4 = *(f32 *)&lbl_803E4FCC;
                }
            } else {
                switch (((EcshShrineState *)sub)->unk24) {
                case 8:
                    ((EcshShrineState *)sub)->unk24 = 2;
                    ((EcshShrineState *)sub)->unk4 = lbl_803E4FD8;
                    ((EcshShrineState *)sub)->unk8 = lbl_803E4FDC;
                    break;
                case 9:
                    ((EcshShrineState *)sub)->unk24 = 8;
                    ((EcshShrineState *)sub)->unk4 = lbl_803E4FD8;
                    ((EcshShrineState *)sub)->unk8 = lbl_803E4FDC;
                    break;
                case 7:
                    ((EcshShrineState *)sub)->unk24 = 3;
                    ((EcshShrineState *)sub)->unk4 = lbl_803E4FD8;
                    ((EcshShrineState *)sub)->unk8 = lbl_803E4FDC;
                    break;
                case 2:
                    ((EcshShrineState *)sub)->unk22 -= 1;
                    if (((EcshShrineState *)sub)->unk22 <= 0) {
                        Sfx_PlayFromObject(0, 0x3a8);
                        ((EcshShrineState *)sub)->unk24 = 5;
                        if (sub[0x2f] == 3) {
                            *(f32 *)(sub + 0xc) = lbl_803E4FA8;
                        } else if (sub[0x2f] == 4) {
                            *(f32 *)(sub + 0xc) = lbl_803E4FA8;
                        } else {
                            *(f32 *)(sub + 0xc) = lbl_803E4FA8;
                        }
                    } else {
                        sub[0x31] = 0;
                        *(f32 *)(sub + 0x14) = (f32)(int)randomGetRange(0x28, 0x3c);
                        Sfx_PlayFromObject(obj, 0x344);
                        ((EcshShrineState *)sub)->unk24 = 0;
                        ((EcshShrineState *)sub)->unk4 = lbl_803E4FE0;
                        if (sub[0x2f] == 3) {
                            pick = randomGetRange(0, 1);
                        } else if (sub[0x2f] == 4) {
                            pick = randomGetRange(0, 5);
                        } else {
                            pick = randomGetRange(0, 7);
                        }
                        if (pick == 0) {
                            for (n = 0; n < 6; n++) {
                                ps->cur[n] += 1;
                                if (ps->cur[n] > 5) {
                                    ps->cur[n] = 0;
                                }
                            }
                        } else if (pick == 1) {
                            for (n = 0; n < 6; n++) {
                                ps->cur[n] -= 1;
                                if (ps->cur[n] < 0) {
                                    ps->cur[n] = 5;
                                }
                            }
                        } else if (pick == 2) {
                            sc = ps->cur[0];
                            ps->cur[0] = ps->cur[2];
                            ps->cur[2] = ps->cur[4];
                            ps->cur[4] = sc;
                        } else if (pick == 3) {
                            sc = ps->cur[4];
                            ps->cur[4] = ps->cur[0];
                            ps->cur[0] = ps->cur[2];
                            ps->cur[2] = sc;
                        } else if (pick == 4) {
                            sc = ps->cur[1];
                            ps->cur[1] = ps->cur[3];
                            ps->cur[3] = ps->cur[5];
                            ps->cur[5] = sc;
                        } else if (pick == 5) {
                            sc = ps->cur[5];
                            ps->cur[5] = ps->cur[1];
                            ps->cur[1] = ps->cur[3];
                            ps->cur[3] = sc;
                        } else if (pick == 6) {
                            t[0] = ps->f[2];
                            t[1] = ps->f[3];
                            ps->f[2] = ps->f[4];
                            ps->f[3] = ps->f[5];
                            ps->f[4] = ps->f[8];
                            ps->f[5] = ps->f[9];
                            ps->f[8] = ps->f[10];
                            ps->f[9] = ps->f[11];
                            ps->f[10] = t[0];
                            ps->f[11] = t[1];
                        } else if (pick == 7) {
                            t[0] = ps->f[10];
                            t[1] = ps->f[11];
                            ps->f[10] = ps->f[8];
                            ps->f[11] = ps->f[9];
                            ps->f[8] = ps->f[4];
                            ps->f[9] = ps->f[5];
                            ps->f[4] = ps->f[2];
                            ps->f[5] = ps->f[3];
                            ps->f[2] = t[0];
                            ps->f[3] = t[1];
                        }
                    }
                    break;
                case 0:
                    ((EcshShrineState *)sub)->unk24 = 1;
                    ((EcshShrineState *)sub)->unk4 = lbl_803E4FE4;
                    break;
                case 1:
                    ((EcshShrineState *)sub)->unk24 = 4;
                    ((EcshShrineState *)sub)->unk4 = fv;
                    break;
                case 4:
                    ((EcshShrineState *)sub)->unk24 = 2;
                    ((EcshShrineState *)sub)->unk4 = fv;
                    break;
                case 5:
                    Sfx_KeepAliveLoopedObjectSound(0, 0x3a8);
                    if (((EcshShrineState *)sub)->unk26 == 0) {
                        (*gScreenTransitionInterface)->start(0x1e, 1);
                        ((EcshShrineState *)sub)->unk8 = lbl_803E4FE8;
                        ((EcshShrineState *)sub)->unk24 = 7;
                        Sfx_PlayFromObject(obj, 0x16f);
                        sub[0x2f] = 10;
                    } else if (((EcshShrineState *)sub)->unk26 == 1) {
                        if (sub[0x2f] == 3) {
                            gv = randomGetRange(0, 5);
                            sub[0x2e] = gv;
                            sub[0x2f] = 4;
                            ((EcshShrineState *)sub)->unk24 = 9;
                            ((EcshShrineState *)sub)->unk8 = lbl_803E4FEC;
                            ((EcshShrineState *)sub)->unk4 = lbl_803E4FB0;
                            ((EcshShrineState *)sub)->unk22 = 7;
                            ((EcshShrineState *)sub)->unk26 = -1;
                            Sfx_PlayFromObject(obj, 0x170);
                            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
                        } else if (sub[0x2f] == 4) {
                            gv = randomGetRange(0, 5);
                            sub[0x2e] = gv;
                            sub[0x2f] = 5;
                            ((EcshShrineState *)sub)->unk24 = 9;
                            ((EcshShrineState *)sub)->unk8 = lbl_803E4FEC;
                            ((EcshShrineState *)sub)->unk4 = lbl_803E4FB0;
                            ((EcshShrineState *)sub)->unk22 = 9;
                            ((EcshShrineState *)sub)->unk26 = -1;
                            Sfx_PlayFromObject(obj, 0x170);
                            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
                        } else {
                            ((EcshShrineState *)sub)->unk8 = lbl_803E4FE8;
                            (*gScreenTransitionInterface)->start(0x1e, 1);
                            sub[0x2f] = 6;
                            ((EcshShrineState *)sub)->unk24 = 3;
                            ((EcshShrineState *)sub)->unk26 = 0;
                            ((EcshShrineState *)sub)->unk24 = 7;
                            Sfx_PlayFromObject(obj, 0x7e);
                            Sfx_PlayFromObject(obj, 0x16f);
                        }
                    } else {
                        *(f32 *)(sub + 0xc) = *(f32 *)(sub + 0xc) - timeDelta;
                        if (*(f32 *)(sub + 0xc) <= lbl_803E4FCC) {
                            sub[0x2f] = 10;
                            (*gScreenTransitionInterface)->start(0x1e, 1);
                            ((EcshShrineState *)sub)->unk8 = lbl_803E4FE8;
                            ((EcshShrineState *)sub)->unk24 = 7;
                            Sfx_PlayFromObject(obj, 0x16f);
                        }
                    }
                    break;
                }
            }
            break;
        case 10:
            GameBit_Set(0xa6f, 1);
            sub[0x2f] = 8;
            break;
        case 6:
            GameBit_Set(0xb9d, 0);
            audioStopByMask(3);
            if (objGetAnimStateFlags(player, 8) != 0) {
                GameBit_Set(0x129, 1);
                sub[0x2f] = 7;
            } else {
                sub[0x2f] = 7;
                (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            }
            break;
        case 7:
            GameBit_Set(0x129, 0);
            sub[0x2f] = 8;
            break;
        case 8:
            sub[0x2f] = 0;
            ((EcshShrineState *)sub)->unk4 = z;
            ((EcshShrineState *)sub)->unk20 = 0;
            ((EcshShrineState *)sub)->unk22 = 0;
            ((EcshShrineState *)sub)->unk24 = 0;
            ((EcshShrineState *)sub)->unk26 = -1;
            sub[0x2e] = 0;
            sub[0x30] = 0;
            ((EcshShrineState *)sub)->unk8 = lbl_803E4FF0;
            GameBit_Set(0x129, 1);
            GameBit_Set(0xb9d, 0);
            GameBit_Set(0xa6d, 0);
            GameBit_Set(0xa6f, 0);
            GameBit_Set(0xa70, 0);
            GameBit_Set(0x143, 0);
            sub[0x30] = 0;
            ((EcshShrineState *)sub)->unk26 = -1;
            break;
        }
    }
}
#pragma opt_strength_reduction reset


/*
 * --INFO--
 *
 * Function: FUN_801c6e04
 * EN v1.0 Address: 0x801C6E04
 * EN v1.0 Size: 704b
 * EN v1.1 Address: 0x801C7408
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c6e04(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
  uint uVar1;
  int *piVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  short *psVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_9 + 0x26);
  psVar4 = *(short **)(param_9 + 0x5c);
  if ((*(int *)(param_9 + 0x7c) == '\0') && (uVar1 = FUN_80017690((int)psVar4[2]), uVar1 != 0)) {
    piVar2 = (int *)FUN_80006b14(0x82);
    (*(code *)(*piVar2 + 4))(param_9,0,0,1,0xffffffff,0);
    in_r8 = 0;
    in_r9 = *piVar2;
    (*(code *)(in_r9 + 4))(param_9,1,0,1,0xffffffff);
    param_1 = FUN_80006824((uint)param_9,SFXwp_mflop7_c);
    FUN_80006b0c((undefined *)piVar2);
    psVar4[1] = 1;
    *(undefined4 *)(param_9 + 0x7c) = 1;
  }
  if (psVar4[1] != 0) {
    *psVar4 = *psVar4 - psVar4[1] * (ushort)DAT_803dc070;
  }
  uVar1 = FUN_80017ae8();
  if (((uVar1 & 0xff) != 0) && (*psVar4 < 1)) {
    puVar3 = (undefined2 *)FUN_80017830(0x38,0xe);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar5 + 8);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar5 + 0xc);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar5 + 0x10);
    *puVar3 = 0x11;
    *(undefined4 *)(puVar3 + 10) = 0xffffffff;
    *(undefined *)(puVar3 + 2) = *(undefined *)(iVar5 + 4);
    *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar5 + 5);
    *(undefined *)(puVar3 + 3) = *(undefined *)(iVar5 + 6);
    *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar5 + 7);
    *(undefined *)((int)puVar3 + 0x27) = 3;
    *(undefined *)(puVar3 + 0x14) = 0;
    puVar3[0xc] = psVar4[2] + (short)*(char *)(iVar5 + 0x1f);
    puVar3[0x18] = 0xffff;
    *(char *)(puVar3 + 0x15) = (char)((ushort)*param_9 >> 8);
    *(undefined *)((int)puVar3 + 0x2b) = 2;
    puVar3[0x10] = 0;
    puVar3[0xf] = 0;
    puVar3[0x11] = 0xffff;
    *(undefined *)((int)puVar3 + 0x29) = 0xff;
    *(undefined *)(puVar3 + 0x17) = 0xff;
    puVar3[0x12] = 0;
    puVar3[0x16] = 0;
    puVar3[0x1a] = 0xffff;
    puVar3[0xd] = 0;
    *(char *)(puVar3 + 0x19) = (char)psVar4[4];
    iVar5 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                         *(undefined *)(param_9 + 0x56),0xffffffff,*(uint **)(param_9 + 0x18),in_r8,
                         in_r9,in_r10);
    if (iVar5 != 0) {
      *(undefined *)(*(int *)(iVar5 + 0xb8) + 0x404) = 0x20;
    }
    *psVar4 = 100;
    psVar4[1] = 0;
  }
  return;
}



/* Trivial 4b 0-arg blr leaves. */
void ecsh_shrine_release(void) {}
void ecsh_shrine_initialise(void) {}
void ecsh_creator_free(void) {}
void ecsh_creator_hitDetect(void) {}
void ecsh_creator_release(void) {}
void ecsh_creator_initialise(void) {}
void gpsh_shrine_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int ecsh_creator_getExtraSize(void) { return 0xa; }
int ecsh_creator_getObjectTypeId(void) { return 0x0; }
int gpsh_shrine_getExtraSize(void) { return 0x18; }
int gpsh_shrine_getObjectTypeId(void) { return 0x0; }

extern void ModelLightStruct_free(void *light);
extern void gameTimerStop(void);
extern void modelLightStruct_setEnabled(void *light, int enabled, f32 scale);
extern void objRenderFn_8003b8f4(f32);
extern void objParticleFn_80099d84(void *obj, f32 scale, int type, f32 extraScale, void *light);
extern f32 lbl_803E5038;

void gpsh_shrine_free(int *obj)
{
    void **state = ((GameObject *)obj)->extra;
    void *light = state[0];

    if (light != NULL) {
        ModelLightStruct_free(light);
        state[0] = NULL;
    }
    gameTimerStop();
    ObjGroup_RemoveObject(obj, 0xb);
    Music_Trigger(0xd8, 0);
    Music_Trigger(0xd9, 0);
    Music_Trigger(8, 0);
    Music_Trigger(0xb, 0);
    GameBit_Set(0xefa, 0);
    GameBit_Set(0xcbb, GameBit_Get(0xc91) == 0);
}

void gpsh_shrine_render(void *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    void **state = ((GameObject *)obj)->extra;

    if (visible == 0) {
        void *light = state[0];
        if (light != NULL) {
            modelLightStruct_setEnabled(light, 0, lbl_803E5038);
        }
    } else {
        void *light = state[0];
        if (light != NULL) {
            modelLightStruct_setEnabled(light, 1, lbl_803E5038);
        }
        ((void (*)(void *, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E5038);
        objParticleFn_80099d84(obj, lbl_803E5038, 7, *(f32 *)&lbl_803E5038, state[0]);
    }
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4FF8;
void ecsh_creator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4FF8); }

void ecsh_creator_init(s16 *obj, s8 *def) {
    s16 *inner = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->anim.rotX = (s16)((s32)def[0x1e] << 8);
    ((GameObject *)obj)->unkF8 = 0;
    inner[0] = 100;
    inner[1] = 0;
    *(u8 *)((char *)obj + 0x37) = 0xff;
    ((GameObject *)obj)->anim.alpha = 0xff;
    inner[2] = *(s16 *)(def + 0x18);
    inner[4] = 2;
    inner[4] += (u8)def[0x20];
}

extern void fn_80296518(int *player, int a, int b);
extern int fn_801C5CE4(void *objArg, int unused, void *eventListArg);
extern int objCreateLight(int a, int b);
extern int lbl_803DDBC0;
extern s16 *lbl_803DDBC4;

typedef struct EcshShrineByte15 {
    u8 flag : 1;
    u8 rest : 7;
} EcshShrineByte15;

int gpsh_shrine_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate) {
    u8 *sub;
    int *player;
    int i;
    u8 ev;
    void *light;

    sub = ((GameObject *)obj)->extra;
    player = Obj_GetPlayerObject();
    animUpdate->activeHitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++) {
        ev = animUpdate->eventIds[i];
        if (ev != 0) {
            switch (ev) {
            case 3:
                ((EcshShrineByte15 *)(sub + 0x15))->flag = 1;
                break;
            case 7:
                fn_80296518(player, 0x80, 1);
                GameBit_Set(0x12b, 1);
                GameBit_Set(0xc85, 1);
                (*gMapEventInterface)->setMode(0xb, 5);
                break;
            case 14:
                ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                light = *(void **)sub;
                if (light != NULL) {
                    modelLightStruct_setEnabled(light, 0, lbl_803E5038);
                }
                break;
            case 15:
                ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
                light = *(void **)sub;
                if (light != NULL) {
                    modelLightStruct_setEnabled(light, 0, lbl_803E5038);
                }
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}

void ecsh_shrine_init(s16 *obj, s8 *def) {
    int *sub = ((GameObject *)obj)->extra;
    u8 gv;
    lbl_803DDBC0 = 0;
    lbl_803DDBC4 = 0;
    *obj = (s16)((s32)def[0x18] << 8);
    ((EcshShrineState *)sub)->unk2F = 0;
    ((EcshShrineState *)sub)->unk30 = 0;
    ((EcshShrineState *)sub)->unk4 = lbl_803E4FCC;
    ((EcshShrineState *)sub)->unk20 = 0;
    ((EcshShrineState *)sub)->unk22 = 0;
    ((EcshShrineState *)sub)->unk24 = 0;
    ((EcshShrineState *)sub)->unk26 = -1;
    ((EcshShrineState *)sub)->unk2E = 0;
    ((EcshShrineState *)sub)->unk34 = 0;
    ((GameObject *)obj)->animEventCallback = (void *)fn_801C5CE4;
    ObjMsg_AllocQueue(obj, 4);
    GameBit_Set(0xba5, 1);
    GameBit_Set(0x129, 1);
    GameBit_Set(0x143, 0);
    ((EcshShrineState *)sub)->unk18 = 0xc;
    ((EcshShrineState *)sub)->unk1C = 0x1e;
    ((EcshShrineState *)sub)->unk8 = lbl_803E4FD0;
    ((EcshShrineState *)sub)->unk1A = 0;
    ((EcshShrineState *)sub)->unk1E = 0;
    gv = GameBit_Get(0x58b);
    ((EcshShrineState *)sub)->unk32 = gv;
    lbl_803DDBC4 = obj;
    ObjGroup_AddObject(obj, 0xb);
    ((GameObject *)obj)->unkF4 = 1;
    if (*(void **)sub == NULL) {
        *(int *)sub = objCreateLight(0, 1);
    }
    GameBit_Set(0xefa, 1);
}

extern u8 *mmAlloc(int size, int tag, int p);
extern int Obj_SetupObject(u8 *def, int a, int b, int c, int d);
extern u8 Obj_IsLoadingLocked(void);
extern u8 framesThisStep;

void ecsh_creator_update(s16 *obj) {
    u8 *def;
    s16 *sub;
    void *res;
    u8 *p;
    int ret;

    def = *(u8 **)&((GameObject *)obj)->anim.placementData;
    sub = ((GameObject *)obj)->extra;
    if (((GameObject *)obj)->unkF8 == 0 && (u32)GameBit_Get(sub[2]) != 0) {
        res = Resource_Acquire(0x82, 1);
        (*(void (**)(s16 *, int, int, int, int, int))(*(int *)res + 4))(obj, 0, 0, 1, -1, 0);
        (*(void (**)(s16 *, int, int, int, int, int))(*(int *)res + 4))(obj, 1, 0, 1, -1, 0);
        Sfx_PlayFromObject(obj, 0x16d);
        Resource_Release(res);
        sub[1] = 1;
        ((GameObject *)obj)->unkF8 = 1;
    }
    if (sub[1] != 0) {
        *sub = *sub - sub[1] * framesThisStep;
    }
    if (Obj_IsLoadingLocked() != 0 && *sub <= 0) {
        p = mmAlloc(0x38, 0xe, 0);
        *(f32 *)(p + 8) = ((ObjPlacement *)def)->posX;
        *(f32 *)(p + 0xc) = ((ObjPlacement *)def)->posY;
        *(f32 *)(p + 0x10) = ((ObjPlacement *)def)->posZ;
        *(s16 *)p = 0x11;
        *(int *)(p + 0x14) = -1;
        p[4] = def[4];
        p[5] = def[5];
        p[6] = def[6];
        p[7] = def[7];
        p[0x27] = 3;
        p[0x28] = 0;
        *(s16 *)(p + 0x18) = sub[2] + *(s8 *)(def + 0x1f);
        *(s16 *)(p + 0x30) = -1;
        *(s8 *)(p + 0x2a) = (s8)(*obj >> 8);
        p[0x2b] = 2;
        *(s16 *)(p + 0x20) = 0;
        *(s16 *)(p + 0x1e) = 0;
        *(s16 *)(p + 0x22) = -1;
        p[0x29] = 0xff;
        *(s8 *)(p + 0x2e) = -1;
        *(s16 *)(p + 0x24) = 0;
        *(s16 *)(p + 0x2c) = 0;
        *(u16 *)(p + 0x34) = 0xFFFF;
        *(s16 *)(p + 0x1a) = 0;
        *(u8 *)(p + 0x32) = sub[4];
        ret = Obj_SetupObject(p, 5, ((GameObject *)obj)->anim.mapEventSlot, -1, *(int *)&((GameObject *)obj)->anim.parent);
        if ((u32)ret != 0) {
            *(u8 *)(*(int *)&((GameObject *)ret)->extra + 0x404) = 0x20;
        }
        *sub = 100;
        sub[1] = 0;
    }
}

extern int getAngle(f32 dx, f32 dz);
extern f32 Vec_xzDistance(f32 *a, f32 *b);
extern f32 lbl_803E5000;
extern f32 lbl_803E5004;
extern f32 lbl_803E5008;
extern f32 lbl_803E500C;
extern f32 lbl_803E5010;
extern f32 lbl_803E5014;
extern f32 lbl_803E5018;
extern f32 lbl_803E501C;
extern f32 lbl_803E5020;
extern f32 lbl_803E5024;
extern f32 lbl_803E5028;
extern f32 mathSinf(f32 angle);

void fn_801C70F0(s16 *obj) {
    u8 buf[32];
    u8 *def;
    u8 *sub;
    int *player;
    int diff;
    f32 c1;
    f32 c2;
    f32 dist;

    def = *(u8 **)&((GameObject *)obj)->anim.placementData;
    sub = ((GameObject *)obj)->extra;
    player = Obj_GetPlayerObject();
    if ((((GameObject *)obj)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0) {
        *obj = 0;
        ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)def)->posY;
    } else {
        *(s16 *)(sub + 0xc) = (s16)(*(s16 *)(sub + 0xc) + (int)(lbl_803E5000 * timeDelta));
        *(s16 *)(sub + 0xe) = (s16)(*(s16 *)(sub + 0xe) + (int)(lbl_803E5004 * timeDelta));
        *(s16 *)(sub + 0x10) = (s16)(*(s16 *)(sub + 0x10) + (int)(lbl_803E5008 * timeDelta));
        ((GameObject *)obj)->anim.localPosY =
            lbl_803E500C + (((ObjPlacement *)def)->posY
                            + mathSinf((lbl_803E5010 * (f32)*(s16 *)(sub + 0xc)) / lbl_803E5014));
        c1 = mathSinf((lbl_803E5010 * (f32)*(s16 *)(sub + 0xe)) / lbl_803E5014);
        c2 = mathSinf((lbl_803E5010 * (f32)*(s16 *)(sub + 0xc)) / lbl_803E5014);
        c2 = c2 + c1;
        ((GameObject *)obj)->anim.rotZ = lbl_803E5018 * c2;
        c1 = mathSinf((lbl_803E5010 * (f32)*(s16 *)(sub + 0x10)) / lbl_803E5014);
        c2 = mathSinf((lbl_803E5010 * (f32)*(s16 *)(sub + 0xc)) / lbl_803E5014);
        c2 = c2 + c1;
        ((GameObject *)obj)->anim.rotY = lbl_803E5018 * c2;
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E501C, timeDelta, (ObjAnimEventList *)buf);
        if (player != NULL) {
            diff = (getAngle(((f32 *)obj)[6] - ((f32 *)player)[6],
                             ((f32 *)obj)[8] - ((f32 *)player)[8]) & 0xffff)
                 - (*obj & 0xffff);
            if (diff > 0x8000) {
                diff = diff - 0xffff;
            }
            if (diff < -0x8000) {
                diff = diff + 0xffff;
            }
            *obj = (s16)(*(s16 *)(int)obj + (int)(((f32)diff * timeDelta) / lbl_803E5020));
            dist = Vec_xzDistance((f32 *)((int)obj + 0x18), (f32 *)((int)player + 0x18));
            if (dist <= lbl_803E5024) {
                ((GameObject *)obj)->anim.alpha = (u8)(int)(lbl_803E5028 * (dist / lbl_803E5024));
            } else {
                ((GameObject *)obj)->anim.alpha = 0xff;
            }
        }
    }
}
