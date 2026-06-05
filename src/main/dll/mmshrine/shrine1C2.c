#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/mmshrine/shrine1C2.h"

#define SFXwp_mflop7_c 0x16d
#define SFXwp_roboalarm 0x16f
#define SFXwp_fox_kick1 0x170

#pragma peephole off
#pragma scheduling off
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
extern undefined4 FUN_801c5f28();
extern undefined4 FUN_801c61f4();
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
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd72c;
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
extern int *gGameUIInterface;
extern int *gObjectTriggerInterface;
extern int *gScreenTransitionInterface;
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
    s16 sc;
    f32 z;
    f32 fv;

    ps = (EcshPuzzleState *)lbl_80326208;
    sub = *(u8 **)((char *)obj + 0xb8);
    player = Obj_GetPlayerObject();
    *(int *)&t[0] = lbl_803E8470;
    *(int *)&t[1] = lbl_803E8474;
    if (sub[0x32] == 0) {
        gv = GameBit_Get(0x58b);
        sub[0x32] = gv;
        if (sub[0x32] != 0) {
            (*(void (**)(int, int, int, int))(*(int *)gGameUIInterface + 0x38))(0x285, 0x14, 0x8c, 1);
        }
    }
    if (*(int *)((char *)obj + 0xf4) != 0) {
        *(int *)((char *)obj + 0xf4) = *(int *)((char *)obj + 0xf4) - 1;
        if (*(int *)((char *)obj + 0xf4) == 0) {
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
    if (*(f32 *)(sub + 8) > (z = lbl_803E4FCC)) {
        *(f32 *)(sub + 8) = *(f32 *)(sub + 8) - timeDelta;
        if (*(f32 *)(sub + 8) <= z) {
            *(f32 *)(sub + 8) = z;
        }
    } else {
        switch (sub[0x2f]) {
        case 0:
            *(s16 *)((char *)obj + 6) &= ~0x4000;
            fv = *(f32 *)(sub + 0x10) - timeDelta;
            *(f32 *)(sub + 0x10) = fv;
            if (fv <= z) {
                Sfx_PlayFromObject(obj, 0x343);
                *(f32 *)(sub + 0x10) = (f32)(int)randomGetRange(500, 1000);
            }
            if ((*(u8 *)((char *)obj + 0xaf) & 1) != 0) {
                sub[0x2f] = 1;
                GameBit_Set(0x129, 0);
                (*(void (**)(int, s16 *, int))(*(int *)gObjectTriggerInterface + 0x48))(0, obj, -1);
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
                *(f32 *)(sub + 8) = lbl_803E4FD0;
                *(s16 *)(sub + 0x24) = 6;
                Sfx_PlayFromObject(obj, 0x16f);
                *(f32 *)(sub + 4) = lbl_803E4FCC;
                GameBit_Set(0xb9d, 1);
                (*(void (**)(int, int))(*(int *)gScreenTransitionInterface + 0xc))(0x78, 1);
            }
            *(s16 *)((char *)obj + 6) |= 0x4000;
            break;
        case 2:
            sub[0x2f] = 3;
            *(f32 *)(sub + 8) = lbl_803E4FD4;
            *(s16 *)(sub + 0x24) = 8;
            *(f32 *)(sub + 4) = lbl_803E4FD8;
            *(s16 *)(sub + 0x22) = 5;
            gv = randomGetRange(0, 5);
            sub[0x2e] = gv;
            (*(void (**)(int, s16 *, int))(*(int *)gObjectTriggerInterface + 0x48))(2, obj, -1);
            break;
        case 3:
        case 4:
        case 5:
            if (*(f32 *)(sub + 4) > lbl_803E4FCC) {
                if (*(s16 *)(sub + 0x24) == 1 && sub[0x31] == 0
                    && *(f32 *)(sub + 4) < *(f32 *)(sub + 0x14)) {
                    if ((int)randomGetRange(0, 10) > 7) {
                        Sfx_PlayFromObject(obj, 0x345);
                    }
                    sub[0x31] = 1;
                }
                *(f32 *)(sub + 4) = *(f32 *)(sub + 4) - timeDelta;
                if (*(f32 *)(sub + 4) < lbl_803E4FCC) {
                    *(f32 *)(sub + 4) = lbl_803E4FCC;
                }
            } else {
                switch (*(s16 *)(sub + 0x24)) {
                case 8:
                    *(s16 *)(sub + 0x24) = 2;
                    *(f32 *)(sub + 4) = lbl_803E4FD8;
                    *(f32 *)(sub + 8) = lbl_803E4FDC;
                    break;
                case 9:
                    *(s16 *)(sub + 0x24) = 8;
                    *(f32 *)(sub + 4) = lbl_803E4FD8;
                    *(f32 *)(sub + 8) = lbl_803E4FDC;
                    break;
                case 7:
                    *(s16 *)(sub + 0x24) = 3;
                    *(f32 *)(sub + 4) = lbl_803E4FD8;
                    *(f32 *)(sub + 8) = lbl_803E4FDC;
                    break;
                case 2:
                    *(s16 *)(sub + 0x22) -= 1;
                    if (*(s16 *)(sub + 0x22) < 1) {
                        Sfx_PlayFromObject(0, 0x3a8);
                        *(s16 *)(sub + 0x24) = 5;
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
                        *(s16 *)(sub + 0x24) = 0;
                        *(f32 *)(sub + 4) = lbl_803E4FE0;
                        if (sub[0x2f] == 3) {
                            pick = randomGetRange(0, 1);
                        } else if (sub[0x2f] == 4) {
                            pick = randomGetRange(0, 5);
                        } else {
                            pick = randomGetRange(0, 7);
                        }
                        if (pick == 0) {
                            ps->cur[0] += 1;
                            if (ps->cur[0] > 5) {
                                ps->cur[0] = 0;
                            }
                            ps->cur[1] += 1;
                            if (ps->cur[1] > 5) {
                                ps->cur[1] = 0;
                            }
                            ps->cur[2] += 1;
                            if (ps->cur[2] > 5) {
                                ps->cur[2] = 0;
                            }
                            ps->cur[3] += 1;
                            if (ps->cur[3] > 5) {
                                ps->cur[3] = 0;
                            }
                            ps->cur[4] += 1;
                            if (ps->cur[4] > 5) {
                                ps->cur[4] = 0;
                            }
                            ps->cur[5] += 1;
                            if (ps->cur[5] > 5) {
                                ps->cur[5] = 0;
                            }
                        } else if (pick == 1) {
                            ps->cur[0] -= 1;
                            if (ps->cur[0] < 0) {
                                ps->cur[0] = 5;
                            }
                            ps->cur[1] -= 1;
                            if (ps->cur[1] < 0) {
                                ps->cur[1] = 5;
                            }
                            ps->cur[2] -= 1;
                            if (ps->cur[2] < 0) {
                                ps->cur[2] = 5;
                            }
                            ps->cur[3] -= 1;
                            if (ps->cur[3] < 0) {
                                ps->cur[3] = 5;
                            }
                            ps->cur[4] -= 1;
                            if (ps->cur[4] < 0) {
                                ps->cur[4] = 5;
                            }
                            ps->cur[5] -= 1;
                            if (ps->cur[5] < 0) {
                                ps->cur[5] = 5;
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
                    *(s16 *)(sub + 0x24) = 1;
                    *(f32 *)(sub + 4) = lbl_803E4FE4;
                    break;
                case 1:
                    *(s16 *)(sub + 0x24) = 4;
                    *(f32 *)(sub + 4) = lbl_803E4FCC;
                    break;
                case 4:
                    *(s16 *)(sub + 0x24) = 2;
                    *(f32 *)(sub + 4) = lbl_803E4FCC;
                    break;
                case 5:
                    Sfx_KeepAliveLoopedObjectSound(0, 0x3a8);
                    if (*(s16 *)(sub + 0x26) == 0) {
                        (*(void (**)(int, int))(*(int *)gScreenTransitionInterface + 8))(0x1e, 1);
                        *(f32 *)(sub + 8) = lbl_803E4FE8;
                        *(s16 *)(sub + 0x24) = 7;
                        Sfx_PlayFromObject(obj, 0x16f);
                        sub[0x2f] = 10;
                    } else if (*(s16 *)(sub + 0x26) == 1) {
                        if (sub[0x2f] == 3) {
                            gv = randomGetRange(0, 5);
                            sub[0x2e] = gv;
                            sub[0x2f] = 4;
                            *(s16 *)(sub + 0x24) = 9;
                            *(f32 *)(sub + 8) = lbl_803E4FEC;
                            *(f32 *)(sub + 4) = lbl_803E4FB0;
                            *(s16 *)(sub + 0x22) = 7;
                            *(s16 *)(sub + 0x26) = -1;
                            Sfx_PlayFromObject(obj, 0x170);
                            (*(void (**)(int, s16 *, int))(*(int *)gObjectTriggerInterface + 0x48))(2, obj, -1);
                        } else if (sub[0x2f] == 4) {
                            gv = randomGetRange(0, 5);
                            sub[0x2e] = gv;
                            sub[0x2f] = 5;
                            *(s16 *)(sub + 0x24) = 9;
                            *(f32 *)(sub + 8) = lbl_803E4FEC;
                            *(f32 *)(sub + 4) = lbl_803E4FB0;
                            *(s16 *)(sub + 0x22) = 9;
                            *(s16 *)(sub + 0x26) = -1;
                            Sfx_PlayFromObject(obj, 0x170);
                            (*(void (**)(int, s16 *, int))(*(int *)gObjectTriggerInterface + 0x48))(2, obj, -1);
                        } else {
                            *(f32 *)(sub + 8) = lbl_803E4FE8;
                            (*(void (**)(int, int))(*(int *)gScreenTransitionInterface + 8))(0x1e, 1);
                            sub[0x2f] = 6;
                            *(s16 *)(sub + 0x24) = 3;
                            *(s16 *)(sub + 0x26) = 0;
                            *(s16 *)(sub + 0x24) = 7;
                            Sfx_PlayFromObject(obj, 0x7e);
                            Sfx_PlayFromObject(obj, 0x16f);
                        }
                    } else {
                        *(f32 *)(sub + 0xc) = *(f32 *)(sub + 0xc) - timeDelta;
                        if (*(f32 *)(sub + 0xc) <= lbl_803E4FCC) {
                            sub[0x2f] = 10;
                            (*(void (**)(int, int))(*(int *)gScreenTransitionInterface + 8))(0x1e, 1);
                            *(f32 *)(sub + 8) = lbl_803E4FE8;
                            *(s16 *)(sub + 0x24) = 7;
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
                (*(void (**)(int, s16 *, int))(*(int *)gObjectTriggerInterface + 0x48))(1, obj, -1);
            }
            break;
        case 7:
            GameBit_Set(0x129, 0);
            sub[0x2f] = 8;
            break;
        case 8:
            sub[0x2f] = 0;
            *(f32 *)(sub + 4) = z;
            *(s16 *)(sub + 0x20) = 0;
            *(s16 *)(sub + 0x22) = 0;
            *(s16 *)(sub + 0x24) = 0;
            *(s16 *)(sub + 0x26) = -1;
            sub[0x2e] = 0;
            sub[0x30] = 0;
            *(f32 *)(sub + 8) = lbl_803E4FF0;
            GameBit_Set(0x129, 1);
            GameBit_Set(0xb9d, 0);
            GameBit_Set(0xa6d, 0);
            GameBit_Set(0xa6f, 0);
            GameBit_Set(0xa70, 0);
            GameBit_Set(0x143, 0);
            sub[0x30] = 0;
            *(s16 *)(sub + 0x26) = -1;
            break;
        }
    }
}

/*
 * --INFO--
 *
 * Function: FUN_801c6dd8
 * EN v1.0 Address: 0x801C6DD8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C728C
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c6dd8(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801c6ddc
 * EN v1.0 Address: 0x801C6DDC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801C73D4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c6ddc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

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

/*
 * --INFO--
 *
 * Function: FUN_801c70c4
 * EN v1.0 Address: 0x801C70C4
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x801C76A4
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c70c4(ushort *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined8 local_30;
  
  iVar4 = *(int *)(param_1 + 0x26);
  iVar3 = *(int *)(param_1 + 0x5c);
  iVar1 = FUN_80017a98();
  if ((param_1[3] & 0x4000) == '\0') {
    *(short *)(iVar3 + 0xc) =
         *(short *)(iVar3 + 0xc) + (short)(int)(lbl_803E5C98 * lbl_803DC074);
    *(short *)(iVar3 + 0xe) =
         *(short *)(iVar3 + 0xe) + (short)(int)(lbl_803E5C9C * lbl_803DC074);
    *(short *)(iVar3 + 0x10) =
         *(short *)(iVar3 + 0x10) + (short)(int)(lbl_803E5CA0 * lbl_803DC074);
    dVar5 = (double)FUN_80293f90();
    *(float *)(param_1 + 8) = lbl_803E5CA4 + (float)((double)*(float *)(iVar4 + 0xc) + dVar5);
    dVar5 = (double)FUN_80293f90();
    dVar6 = (double)FUN_80293f90();
    param_1[2] = (ushort)(int)(lbl_803E5CB0 * (float)(dVar6 + dVar5));
    dVar5 = (double)FUN_80293f90();
    dVar6 = (double)FUN_80293f90();
    param_1[1] = (ushort)(int)(lbl_803E5CB0 * (float)(dVar6 + dVar5));
    FUN_8002fc3c((double)lbl_803E5CB4,(double)lbl_803DC074);
    if (iVar1 != 0) {
      uVar2 = FUN_80017730();
      uVar2 = (uVar2 & 0xffff) - (uint)*param_1;
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      *param_1 = *param_1 +
                 (short)(int)(((float)(local_30 - DOUBLE_803e5cc8) * lbl_803DC074) /
                             lbl_803E5CB8);
      dVar5 = (double)FUN_80017710((float *)(param_1 + 0xc),(float *)(iVar1 + 0x18));
      if ((double)lbl_803E5CBC < dVar5) {
        *(undefined *)(param_1 + 0x1b) = 0xff;
      }
      else {
        *(char *)(param_1 + 0x1b) =
             (char)(int)(lbl_803E5CC0 * (float)(dVar5 / (double)lbl_803E5CBC));
      }
    }
  }
  else {
    *param_1 = 0;
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar4 + 0xc);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c7390
 * EN v1.0 Address: 0x801C7390
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x801C79F8
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c7390(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  
  iVar2 = FUN_8028683c();
  piVar5 = *(int **)(iVar2 + 0xb8);
  iVar3 = FUN_80017a98();
  *(undefined2 *)(param_3 + 0x70) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    bVar1 = *(byte *)(param_3 + iVar4 + 0x81);
    if (bVar1 != 0) {
      if (bVar1 == 7) {
        FUN_80294ccc(iVar3,0x80,1);
        FUN_80017698(299,1);
        FUN_80017698(0xc85,1);
        (*(code *)(*DAT_803dd72c + 0x44))(0xb,5);
      }
      else if (bVar1 < 7) {
        if (bVar1 == 3) {
          *(byte *)((int)piVar5 + 0x15) = *(byte *)((int)piVar5 + 0x15) & 0x7f | 0x80;
        }
      }
      else if (bVar1 == 0xf) {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) & 0xbfff;
        if (*piVar5 != 0) {
          FUN_800175cc((double)lbl_803E5CD0,*piVar5,'\0');
        }
      }
      else if ((bVar1 < 0xf) && (0xd < bVar1)) {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        if (*piVar5 != 0) {
          FUN_800175cc((double)lbl_803E5CD0,*piVar5,'\0');
        }
      }
    }
    *(undefined *)(param_3 + iVar4 + 0x81) = 0;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c74f0
 * EN v1.0 Address: 0x801C74F0
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x801C7B6C
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c74f0(int param_1)
{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
    *puVar2 = 0;
  }
  FUN_80006b4c();
  ObjGroup_RemoveObject(param_1,0xb);
  FUN_800067c0((int *)0xd8,0);
  FUN_800067c0((int *)0xd9,0);
  FUN_800067c0((int *)0x8,0);
  FUN_800067c0((int *)0xb,0);
  FUN_80017698(0xefa,0);
  uVar1 = FUN_80017690(0xc91);
  uVar1 = countLeadingZeros(uVar1);
  FUN_80017698(0xcbb,uVar1 >> 5);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c75a4
 * EN v1.0 Address: 0x801C75A4
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801C7C1C
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c75a4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  int *piVar2;
  
  iVar1 = FUN_8028683c();
  piVar2 = *(int **)(iVar1 + 0xb8);
  if (visible == 0) {
    if (*piVar2 != 0) {
      FUN_800175cc((double)lbl_803E5CD0,*piVar2,'\0');
    }
  }
  else {
    if (*piVar2 != 0) {
      FUN_800175cc((double)lbl_803E5CD0,*piVar2,'\x01');
    }
    FUN_8003b818(iVar1);
    FUN_8008111c((double)lbl_803E5CD0,(double)lbl_803E5CD0,iVar1,7,(int *)*piVar2);
  }
  FUN_80286888();
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
extern void Music_Trigger(int id, int restart);
extern void GameBit_Set(int bit, int value);
extern int GameBit_Get(int bit);
extern void modelLightStruct_setEnabled(void *light, int enabled, f32 scale);
extern void objRenderFn_8003b8f4(f32);
extern void objParticleFn_80099d84(void *obj, int type, void *light, f32 scale, f32 extraScale);
extern f32 lbl_803E5038;

#pragma scheduling off
#pragma peephole off
void gpsh_shrine_free(int *obj)
{
    void **state = *(void ***)((char *)obj + 0xb8);
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
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void gpsh_shrine_render(void *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    void **state = *(void ***)((char *)obj + 0xb8);

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
        objParticleFn_80099d84(obj, 7, state[0], lbl_803E5038, lbl_803E5038);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4FF8;
#pragma peephole off
void ecsh_creator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4FF8); }
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void ecsh_creator_init(s16 *obj, s8 *def) {
    s16 *inner = *(s16 **)((char *)obj + 0xb8);
    obj[0] = (s16)((s32)def[0x1e] << 8);
    *(int *)((char *)obj + 0xf8) = 0;
    inner[0] = 100;
    inner[1] = 0;
    *(u8 *)((char *)obj + 0x37) = 0xff;
    *(u8 *)((char *)obj + 0x36) = 0xff;
    inner[2] = *(s16 *)(def + 0x18);
    inner[4] = 2;
    inner[4] = inner[4] + (u8)def[0x20];
}
#pragma peephole reset
#pragma scheduling reset

extern int *Obj_GetPlayerObject(void);
extern void fn_80296518(int *player, int a, int b);
extern int *gMapEventInterface;
extern int fn_801C5CE4(void *objArg, int unused, void *eventListArg);
extern int objCreateLight(int a, int b);
extern int lbl_803DDBC0;
extern s16 *lbl_803DDBC4;
extern f32 lbl_803E4FCC;
extern f32 lbl_803E4FD0;

typedef struct EcshShrineByte15 {
    u8 flag : 1;
    u8 rest : 7;
} EcshShrineByte15;

int gpsh_shrine_SeqFn(int *obj, int arg1, u8 *seq) {
    u8 *sub;
    int *player;
    int i;
    int idx;
    u8 ev;
    void *light;

    sub = *(u8 **)((char *)obj + 0xb8);
    player = Obj_GetPlayerObject();
    *(s16 *)((char *)seq + 0x70) = -1;
    seq[0x56] = 0;
    for (i = 0; i < seq[0x8b]; i++) {
        idx = i + 0x81;
        ev = seq[idx];
        if (ev != 0) {
            switch (ev) {
            case 3:
                ((EcshShrineByte15 *)(sub + 0x15))->flag = 1;
                break;
            case 7:
                fn_80296518(player, 0x80, 1);
                GameBit_Set(0x12b, 1);
                GameBit_Set(0xc85, 1);
                (*(void (**)(int, int))(*(int *)gMapEventInterface + 0x44))(0xb, 5);
                break;
            case 14:
                *(s16 *)((char *)obj + 6) |= 0x4000;
                light = *(void **)sub;
                if (light != NULL) {
                    modelLightStruct_setEnabled(light, 0, lbl_803E5038);
                }
                break;
            case 15:
                *(s16 *)((char *)obj + 6) &= ~0x4000;
                light = *(void **)sub;
                if (light != NULL) {
                    modelLightStruct_setEnabled(light, 0, lbl_803E5038);
                }
                break;
            }
        }
        seq[idx] = 0;
    }
    return 0;
}

void ecsh_shrine_init(s16 *obj, s8 *def) {
    int *sub = *(int **)((char *)obj + 0xb8);
    u8 gv;
    lbl_803DDBC0 = 0;
    lbl_803DDBC4 = 0;
    *obj = (s16)((s32)def[0x18] << 8);
    *(u8 *)((char *)sub + 0x2f) = 0;
    *(u8 *)((char *)sub + 0x30) = 0;
    *(f32 *)((char *)sub + 4) = lbl_803E4FCC;
    *(s16 *)((char *)sub + 0x20) = 0;
    *(s16 *)((char *)sub + 0x22) = 0;
    *(s16 *)((char *)sub + 0x24) = 0;
    *(s16 *)((char *)sub + 0x26) = -1;
    *(u8 *)((char *)sub + 0x2e) = 0;
    *(int *)((char *)sub + 0x34) = 0;
    *(void **)((char *)obj + 0xbc) = (void *)fn_801C5CE4;
    ObjMsg_AllocQueue(obj, 4);
    GameBit_Set(0xba5, 1);
    GameBit_Set(0x129, 1);
    GameBit_Set(0x143, 0);
    *(s16 *)((char *)sub + 0x18) = 0xc;
    *(s16 *)((char *)sub + 0x1c) = 0x1e;
    *(f32 *)((char *)sub + 8) = lbl_803E4FD0;
    *(s16 *)((char *)sub + 0x1a) = 0;
    *(s16 *)((char *)sub + 0x1e) = 0;
    gv = GameBit_Get(0x58b);
    *(u8 *)((char *)sub + 0x32) = gv;
    lbl_803DDBC4 = obj;
    ObjGroup_AddObject(obj, 0xb);
    *(int *)((char *)obj + 0xf4) = 1;
    if (*(void **)sub == NULL) {
        *(int *)sub = objCreateLight(0, 1);
    }
    GameBit_Set(0xefa, 1);
}

extern int *Resource_Acquire(int id, int b);
extern void Resource_Release(int *res);
extern void Sfx_PlayFromObject(s16 *obj, int sfxId);
extern u8 *mmAlloc(int size, int tag, int p);
extern int Obj_SetupObject(u8 *def, int a, int b, int c, int d);
extern u8 Obj_IsLoadingLocked(void);
extern u8 framesThisStep;

void ecsh_creator_update(s16 *obj) {
    u8 *def;
    s16 *sub;
    int *res;
    u8 *p;
    int ret;

    def = *(u8 **)((char *)obj + 0x4c);
    sub = *(s16 **)((char *)obj + 0xb8);
    if (*(int *)((char *)obj + 0xf8) == 0 && GameBit_Get(sub[2]) != 0) {
        res = Resource_Acquire(0x82, 1);
        (*(void (**)(s16 *, int, int, int, int, int))(*(int *)res + 4))(obj, 0, 0, 1, -1, 0);
        (*(void (**)(s16 *, int, int, int, int, int))(*(int *)res + 4))(obj, 1, 0, 1, -1, 0);
        Sfx_PlayFromObject(obj, 0x16d);
        Resource_Release(res);
        sub[1] = 1;
        *(int *)((char *)obj + 0xf8) = 1;
    }
    if (sub[1] != 0) {
        *sub = *sub - sub[1] * framesThisStep;
    }
    if (Obj_IsLoadingLocked() != 0 && *sub < 1) {
        p = mmAlloc(0x38, 0xe, 0);
        *(f32 *)(p + 8) = *(f32 *)(def + 8);
        *(f32 *)(p + 0xc) = *(f32 *)(def + 0xc);
        *(f32 *)(p + 0x10) = *(f32 *)(def + 0x10);
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
        ret = Obj_SetupObject(p, 5, *(s8 *)((char *)obj + 0xac), -1, *(int *)((char *)obj + 0x30));
        if (ret != 0) {
            *(u8 *)(*(int *)(ret + 0xb8) + 0x404) = 0x20;
        }
        *sub = 100;
        sub[1] = 0;
    }
}

extern void ObjAnim_AdvanceCurrentMove(s16 *obj, f32 a, f32 b, u8 *buf);
extern int getAngle(f32 dx, f32 dz);
extern f32 Vec_xzDistance(f32 *a, f32 *b);
extern f32 timeDelta;
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
extern f32 fn_80293E80(f32 angle);

void fn_801C70F0(s16 *obj) {
    u8 buf[32];
    u8 *def;
    u8 *sub;
    int *player;
    int diff;
    f32 c1;
    f32 dist;

    def = *(u8 **)((char *)obj + 0x4c);
    sub = *(u8 **)((char *)obj + 0xb8);
    player = Obj_GetPlayerObject();
    if ((*(s16 *)((char *)obj + 6) & 0x4000) != 0) {
        *obj = 0;
        *(f32 *)((char *)obj + 0x10) = *(f32 *)(def + 0xc);
    } else {
        *(s16 *)(sub + 0xc) = (s16)(*(s16 *)(sub + 0xc) + (int)(lbl_803E5000 * timeDelta));
        *(s16 *)(sub + 0xe) = (s16)(*(s16 *)(sub + 0xe) + (int)(lbl_803E5004 * timeDelta));
        *(s16 *)(sub + 0x10) = (s16)(*(s16 *)(sub + 0x10) + (int)(lbl_803E5008 * timeDelta));
        *(f32 *)((char *)obj + 0x10) =
            lbl_803E500C + (*(f32 *)(def + 0xc)
                            + fn_80293E80((lbl_803E5010 * (f32)*(s16 *)(sub + 0xc)) / lbl_803E5014));
        c1 = fn_80293E80((lbl_803E5010 * (f32)*(s16 *)(sub + 0xe)) / lbl_803E5014);
        obj[2] = (int)(lbl_803E5018
                       * (fn_80293E80((lbl_803E5010 * (f32)*(s16 *)(sub + 0xc)) / lbl_803E5014) + c1));
        c1 = fn_80293E80((lbl_803E5010 * (f32)*(s16 *)(sub + 0x10)) / lbl_803E5014);
        obj[1] = (int)(lbl_803E5018
                       * (fn_80293E80((lbl_803E5010 * (f32)*(s16 *)(sub + 0xc)) / lbl_803E5014) + c1));
        ObjAnim_AdvanceCurrentMove(obj, lbl_803E501C, timeDelta, buf);
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
            *obj = (s16)(*obj + (int)(((f32)diff * timeDelta) / lbl_803E5020));
            dist = Vec_xzDistance((f32 *)((char *)obj + 0x18), (f32 *)((char *)player + 0x18));
            if (dist <= lbl_803E5024) {
                *(u8 *)((char *)obj + 0x36) = (u8)(int)(lbl_803E5028 * (dist / lbl_803E5024));
            } else {
                *(u8 *)((char *)obj + 0x36) = 0xff;
            }
        }
    }
}
