#include "ghidra_import.h"
#include "main/dll/cfperch.h"

#define SFXmn_dimexp01 0x6b
#define SFXmn_dimprup6 0x6c
#define SFXfend_rob_wave 0x313

#define SMALLBASKET_LINKED_ID_BASE 0x40000
#define SMALLBASKET_ROB_WAVE_DIRECT_ID 0x66
#define SMALLBASKET_ROB_WAVE_ID_65D0 0x65d0
#define SMALLBASKET_ROB_WAVE_ID_65D2 0x65d2
#define SMALLBASKET_ROB_WAVE_ID_65D5 0x65d5
#define SMALLBASKET_ROB_WAVE_ID_65D6 0x65d6
#define SMALLBASKET_ROB_WAVE_ID_65D7 0x65d7
#define GAMEBIT_SFX_MUTE 0xa71

extern undefined8 FUN_80006824();
extern uint FUN_80006ba0();
extern undefined4 FUN_80006ba8();
extern uint FUN_80006c00();
extern double FUN_80017708();
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 FUN_80081120();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_80181b50();
extern undefined4 FUN_801816f8();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();
extern uint FUN_80294bec();
extern byte FUN_80294c20();
extern uint FUN_80294ce8();
extern uint FUN_80294cf0();
extern uint FUN_80294db4();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803de740;
extern f64 DOUBLE_803e4600;
extern f64 DOUBLE_803e4638;
extern f32 lbl_803DC074;
extern f32 lbl_803E45C8;
extern f32 lbl_803E45D0;
extern f32 lbl_803E45E8;
extern f32 lbl_803E45F0;
extern f32 lbl_803E460C;
extern f32 lbl_803E4610;
extern f32 lbl_803E4614;
extern f32 lbl_803E4618;
extern f32 lbl_803E461C;
extern f32 lbl_803E4620;
extern f32 lbl_803E4624;
extern f32 lbl_803E4628;
extern f32 lbl_803E462C;
extern f32 lbl_803E4630;

extern void* Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32* a, f32* b);
extern int GameBit_Get(int id);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern f32 lbl_803E39AC;
extern f64 lbl_803E39B0;
extern f32 lbl_803E39B8;
extern f32 lbl_803E39BC;
extern f32 lbl_803E39C0;
extern f32 lbl_803E39C4;
extern f64 lbl_803E39C8;

#pragma scheduling off
#pragma peephole off
f32 fn_80183204(int obj)
{
    u8* state = *(u8**)(obj + 0xb8);
    return lbl_803E39AC - (f32)(u32)state[0x13] / (f32)(u32)state[0x28];
}
#pragma peephole reset
#pragma scheduling reset

extern void ObjGroup_AddObject(int obj, int group);
extern void* Resource_Acquire(int id, int mode);
extern void* lbl_803DDAC0;

#pragma scheduling off
#pragma peephole off
void smallbasket_init(int obj, int def)
{
    int state;
    s16 v1c;
    s16 mode;

    state = *(int*)(obj + 0xb8);
    ObjHits_DisableObject(obj);
    ObjGroup_AddObject(obj, 0x10);

    v1c = *(s16*)(def + 0x1c);
    if (v1c == 0) {
        *(int*)(state + 0x18) = 0;
    } else {
        *(int*)(state + 0x18) = v1c * 0x3c;
    }

    lbl_803DDAC0 = Resource_Acquire(0x5b, 1);
    *(s16*)(state + 0xe) = (s16)(randomGetRange(0, 0x64) + 0x12c);
    *(u8*)(state + 0x1f) = (u8)*(s16*)(def + 0x1a);
    *(s16*)obj = (s16)(*(s8*)(def + 0x18) << 8);
    *(s16*)(state + 0x1c) = *(s16*)(def + 0x1e);
    *(s16*)(state + 0xc) = *(s16*)(def + 0x20);
    if (*(s16*)(state + 0xc) == 0) {
        *(s16*)(state + 0xc) = 0x14;
    }
    *(s16*)(state + 0x12) = 0x320;
    *(u16*)(obj + 0xb0) |= 0x2000;
    *(u8*)(state + 0x1e) = *(u8*)(def + 0x19);
    *(f32*)(obj + 0x80) = *(f32*)(obj + 0xc);
    *(f32*)(obj + 0x84) = *(f32*)(obj + 0x10);
    *(f32*)(obj + 0x80) = *(f32*)(obj + 0x14);

    if ((u32)GameBit_Get(*(s16*)(state + 0x1c)) != 0) {
        *(int*)(state + 0x14) = 1;
        ObjHits_DisableObject(obj);
    }

    mode = *(s16*)(obj + 0x46);
    if (mode == 0x3cf) {
        *(s16*)(state + 0x10) = 0x60;
    } else if (mode == 0x662) {
        *(u8*)(state + 0x20) = 1;
        *(s16*)(state + 0x10) = 0x37d;
    } else {
        *(s16*)(state + 0x10) = 0x4a;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80183250(int obj, int def)
{
    int state31;
    int player;
    f32 oldVel;
    int sum;
    u32 adj;
    u32 v;
    f32 limit;

    state31 = *(int *)(obj + 0x4c);
    player = (int)Obj_GetPlayerObject();
    if ((*(u16 *)(*(int *)(obj + 0x30) + 0xb0) & 0x1000) != 0) {
        *(f32 *)(obj + 0xc) = *(f32 *)(def + 0x24);
        *(f32 *)(obj + 0x24) = lbl_803E39B8;
    } else {
        oldVel = *(f32 *)(obj + 0x24);
        sum = *(s16 *)(*(int *)(obj + 0x30) + 0x4) + *(u16 *)(def + 0x20);
        *(f32 *)(obj + 0x24) = -(f32)sum / *(f32 *)(def + 0x1c);
        if ((oldVel <= (limit = lbl_803E39B8) && *(f32 *)(obj + 0x24) >= limit) ||
            (oldVel >= lbl_803E39B8 && *(f32 *)(obj + 0x24) <= lbl_803E39B8)) {
            v = *(u32 *)(state31 + 0x14);
            adj = v - SMALLBASKET_LINKED_ID_BASE;
            if ((adj == SMALLBASKET_ROB_WAVE_ID_65D7) ||
                ((adj - SMALLBASKET_ROB_WAVE_ID_65D5) <=
                 (SMALLBASKET_ROB_WAVE_ID_65D6 - SMALLBASKET_ROB_WAVE_ID_65D5)) ||
                (v == SMALLBASKET_ROB_WAVE_DIRECT_ID) || (adj == SMALLBASKET_ROB_WAVE_ID_65D0) ||
                (adj == SMALLBASKET_ROB_WAVE_ID_65D2)) {
                if (Vec_distance((f32 *)(player + 0x18), (f32 *)(obj + 0x18)) < lbl_803E39BC) {
                    if ((u32)GameBit_Get(GAMEBIT_SFX_MUTE) == 0) {
                        Sfx_PlayFromObject(obj, SFXfend_rob_wave);
                    }
                }
            }
        }
        *(f32 *)(obj + 0xc) = *(f32 *)(obj + 0xc) + *(f32 *)(obj + 0x24);
        if (*(f32 *)(obj + 0xc) > (limit = lbl_803E39C0 + *(f32 *)(def + 0x24))) {
            *(f32 *)(obj + 0xc) = limit;
        } else {
            limit = *(f32 *)(def + 0x24) - lbl_803E39C4;
            if (*(f32 *)(obj + 0xc) < limit) {
                *(f32 *)(obj + 0xc) = limit;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void ObjHits_ClearHitVolumes(int obj);
extern void ObjHits_SetHitVolumeSlot(int obj, int volumeIdx, int hitType, int extra);
extern void ObjHits_SyncObjectPositionIfDirty(int obj);
extern u32 buttonGetDisabled(int pad);
extern u32 getButtonsJustPressed(int pad);
extern void buttonDisable(int pad, int mask);
extern int ObjTrigger_IsSet(int obj);
extern int playerIsDisguised(int player);
extern u32 playerGetStateFlag310(int player);
extern void setAButtonIcon(int icon);
extern int fn_80295BF0(int player);
extern int fn_8029669C(int player);
extern int fn_802966B4(int player);
extern void mathFn_80021ac8(void *p, void *v);
extern void ObjMsg_SendToObject(int target, int msg, int obj, u32 value);
extern void fn_801816F8(int obj, int player, int state);
extern void fn_801814D0(int obj, int player, int state);
extern void fn_801821FC(int obj);
extern void objLightFn_8009a1dc(int obj, f32 scale, void *pos, int mode, int param);
extern f32 getXZDistance(f32 *a, f32 *b);
extern u8 framesThisStep;
extern f32 timeDelta;
extern int *gSHthorntailAnimationInterface;
extern int *gMapEventInterface;
extern f32 lbl_803E3930;
extern f32 lbl_803E3934;
extern f32 lbl_803E3938;
extern f32 lbl_803E3950;
extern f32 lbl_803E3958;
extern f64 lbl_803E3968;
extern f32 lbl_803E3974;
extern f32 lbl_803E3978;
extern f32 lbl_803E397C;
extern f32 lbl_803E3980;
extern f32 lbl_803E3984;
extern f32 lbl_803E3988;
extern f32 lbl_803E398C;
extern f32 lbl_803E3990;
extern f32 lbl_803E3994;
extern f32 lbl_803E3998;
extern f64 lbl_803E39A0;

typedef struct {
    s16 h0;
    s16 h1;
    s16 h2;
    f32 fx;
    f32 fy;
    f32 fz;
    f32 fw;
} BasketMathArgs;

/*
 * --INFO--
 *
 * Function: smallbasket_update
 * EN v1.0 Address: 0x801826E8
 * EN v1.0 Size: 2476b
 */
#pragma scheduling off
#pragma peephole off
void smallbasket_update(int obj)
{
    int player;
    int def;
    int state;
    int playerState;
    int flag;
    s8 c;
    u8 k;
    int level;
    f32 zf;
    f32 animSpeed;
    BasketMathArgs blk;

    player = (int)Obj_GetPlayerObject();
    def = *(int *)(obj + 0x4c);
    animSpeed = lbl_803E3950;
    (**(void (**)(f32 *))(*gSHthorntailAnimationInterface + 0x18))(&animSpeed);
    state = *(int *)(obj + 0xb8);
    if ((**(int (**)(int))(*gMapEventInterface + 0x68))(*(int *)(def + 0x14)) == 0) {
        return;
    }
    playerState = *(int *)(player + 0xb8);
    if (*(s16 *)(state + 0x12) <= 0) {
        *(s16 *)(state + 0x12) = 800;
        *(s16 *)(state + 0xa) = 1;
        *(u8 *)(state + 0x9) = 0;
        *(u8 *)(obj + 0xaf) |= 8;
        fn_801816F8(obj, player, state);
        zf = lbl_803E3938;
        *(f32 *)(obj + 0x24) = zf;
        *(f32 *)(obj + 0x2c) = zf;
    }
    if (*(int *)(state + 0x14) != 0) {
        flag = 0;
        *(u8 *)(obj + 0x36) = flag;
        *(int *)(state + 0x14) -= (s16)(int)(timeDelta * animSpeed);
        if (*(int *)(state + 0x14) <= 0) {
            if ((Vec_distance((f32 *)(obj + 0x18), (f32 *)((int)Obj_GetPlayerObject() + 0x18)) > lbl_803E3930) &&
                (*(s16 *)(state + 0x1c) == -1)) {
                flag = 1;
            }
            if (flag == 0) {
                *(int *)(state + 0x14) = 1;
            } else {
                *(int *)(state + 0x14) = 0;
                *(s16 *)(state + 0xa) = 0;
                ObjHits_EnableObject(obj);
                ObjHits_SyncObjectPositionIfDirty(obj);
                *(u8 *)(obj + 0xaf) &= ~0x8;
                *(s16 *)(obj + 0x6) &= ~0x4000;
            }
        }
    } else {
        if (*(s8 *)(state + 0x5) != 2) {
            level = (int)(lbl_803E3978 * timeDelta + (f32)(u32)*(u8 *)(obj + 0x36));
            if (level > 0xff) {
                level = 0xff;
            }
            *(u8 *)(obj + 0x36) = level;
        }
        if (*(s16 *)(state + 0xa) != 0) {
            ObjHits_DisableObject(obj);
            *(s16 *)(state + 0xa) -= framesThisStep;
            if (*(s16 *)(state + 0xa) <= 0) {
                if (*(int *)(state + 0x18) != 0) {
                    *(int *)(state + 0x14) = *(int *)(state + 0x18);
                } else {
                    *(int *)(state + 0x14) = 1;
                }
                (**(void (**)(int, f32))(*gMapEventInterface + 0x64))(
                    *(int *)(def + 0x14), (f32)*(int *)(state + 0x18));
                *(f32 *)(obj + 0xc) = *(f32 *)(def + 0x8);
                *(f32 *)(obj + 0x10) = *(f32 *)(def + 0xc);
                *(f32 *)(obj + 0x14) = *(f32 *)(def + 0x10);
                *(f32 *)(obj + 0x80) = *(f32 *)(def + 0x8);
                *(f32 *)(obj + 0x84) = *(f32 *)(def + 0xc);
                *(f32 *)(obj + 0x88) = *(f32 *)(def + 0x10);
                zf = lbl_803E3938;
                *(f32 *)(obj + 0x24) = zf;
                *(f32 *)(obj + 0x28) = zf;
                *(f32 *)(obj + 0x2c) = zf;
            }
            if (*(s16 *)(state + 0xa) <= 0x32) {
                return;
            }
        }
        if (*(s8 *)(state + 0x9) != 1) {
            if (*(s8 *)(state + 0x5) == 0) {
                flag = 0;
                if (((buttonGetDisabled(0) & 0x100) == 0) && (*(int *)(obj + 0xf8) == 0) &&
                    (ObjTrigger_IsSet(obj) != 0)) {
                    *(s16 *)(state + 0x0) = -0x8000;
                    *(s16 *)(state + 0x2) = 0;
                    ObjHits_DisableObject(obj);
                    flag = 1;
                }
                *(s8 *)(state + 0x5) = flag;
                if (*(s8 *)(state + 0x5) != 0) {
                    *(u8 *)(state + 0x6) = 1;
                }
                if (*(int *)(obj + 0xf8) == 0) {
                    ObjHits_EnableObject(obj);
                    if ((*(u8 *)(state + 0x20) != 0) && (playerIsDisguised(player) == 0)) {
                        *(u8 *)(obj + 0xaf) |= 0x10;
                    } else {
                        *(u8 *)(obj + 0xaf) &= ~0x10;
                    }
                }
                *(f32 *)(obj + 0x80) = *(f32 *)(obj + 0xc);
                *(f32 *)(obj + 0x84) = *(f32 *)(obj + 0x14);
                *(f32 *)(obj + 0x88) = *(f32 *)(obj + 0x14);
            } else {
                ObjHits_DisableObject(obj);
                *(u8 *)(obj + 0xaf) |= 8;
                if ((playerGetStateFlag310(player) & 0x4000) != 0) {
                    setAButtonIcon(5);
                } else {
                    setAButtonIcon(4);
                }
                if ((getButtonsJustPressed(0) & 0x100) != 0) {
                    if (fn_80295BF0(player) != 0) {
                        *(u8 *)(state + 0x6) = 0;
                        buttonDisable(0, 0x100);
                    } else {
                        Sfx_PlayFromObject(0, 0x10a);
                    }
                }
                if (*(int *)(obj + 0xf8) == 1) {
                    *(u8 *)(state + 0x5) = 2;
                }
                if (((*(s8 *)(state + 0x5) == 2) && (*(int *)(obj + 0xf8) == 0)) ||
                    ((*(u8 *)(state + 0x20) != 0) && (playerIsDisguised(player) == 0))) {
                    if (fn_8029669C(player) != 0) {
                        *(u8 *)(state + 0x5) = 0;
                        *(u8 *)(state + 0x9) = 1;
                        *(f32 *)(obj + 0x28) = lbl_803E397C * *(f32 *)(playerState + 0x298) + lbl_803E3958;
                        *(f32 *)(obj + 0x2c) = lbl_803E3980 * *(f32 *)(playerState + 0x298) + lbl_803E3974;
                        blk.fy = lbl_803E3938;
                        blk.fz = lbl_803E3938;
                        blk.fw = lbl_803E3938;
                        blk.fx = lbl_803E3950;
                        blk.h2 = 0;
                        blk.h1 = 0;
                        blk.h0 = *(s16 *)player;
                        if (*(void **)(player + 0x30) != NULL) {
                            blk.h0 = blk.h0 + **(s16 **)(player + 0x30);
                        }
                        mathFn_80021ac8(&blk, (void *)(obj + 0x24));
                        Sfx_PlayFromObject(obj, 0x6b);
                    } else if (fn_802966B4(player) != 0) {
                        *(u8 *)(state + 0x5) = 0;
                        *(u8 *)(state + 0x9) = 2;
                        zf = lbl_803E3938;
                        *(f32 *)(obj + 0x24) = zf;
                        *(f32 *)(obj + 0x28) = zf;
                        *(f32 *)(obj + 0x2c) = zf;
                        ObjHits_EnableObject(obj);
                        *(u8 *)(obj + 0xaf) &= ~0x8;
                        ObjHits_ClearHitVolumes(obj);
                    } else {
                        *(u8 *)(state + 0x5) = 0;
                        *(u8 *)(state + 0x9) = 1;
                        *(f32 *)(obj + 0x28) = lbl_803E3988 * *(f32 *)(playerState + 0x298) + lbl_803E3984;
                        *(f32 *)(obj + 0x2c) = lbl_803E3990 * *(f32 *)(playerState + 0x298) + lbl_803E398C;
                        blk.fy = lbl_803E3938;
                        blk.fz = lbl_803E3938;
                        blk.fw = lbl_803E3938;
                        blk.fx = lbl_803E3950;
                        blk.h2 = 0;
                        blk.h1 = 0;
                        blk.h0 = *(s16 *)player;
                        mathFn_80021ac8(&blk, (void *)(obj + 0x24));
                        Sfx_PlayFromObject(obj, 0x6b);
                        *(u8 *)(state + 0x6) = 0;
                        *(u8 *)(obj + 0xaf) |= 8;
                    }
                }
                if (*(s8 *)(state + 0x6) != 0) {
                    *(s16 *)(state + 0xa) = 0;
                    *(int *)(state + 0x14) = 0;
                    ObjMsg_SendToObject(player, 0x100010, obj,
                                        (*(s16 *)(state + 0x2) << 16) | ((u16)*(s16 *)(state + 0x0)));
                }
            }
        } else if (*(s8 *)(state + 0x9) != 0) {
            *(s16 *)(state + 0x12) -= framesThisStep;
            if (*(s8 *)(state + 0x9) == 1) {
                ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
                if (*(f32 *)(obj + 0x28) > lbl_803E3994) {
                    *(f32 *)(obj + 0x28) = lbl_803E3998 * timeDelta + *(f32 *)(obj + 0x28);
                }
                ObjHits_EnableObject(obj);
            }
            *(f32 *)(obj + 0xc) = *(f32 *)(obj + 0x24) * timeDelta + *(f32 *)(obj + 0xc);
            *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x28) * timeDelta + *(f32 *)(obj + 0x10);
            *(f32 *)(obj + 0x14) = *(f32 *)(obj + 0x2c) * timeDelta + *(f32 *)(obj + 0x14);
            fn_801821FC(obj);
            c = *(s8 *)(*(int *)(obj + 0x54) + 0xad);
            if ((c != 0) && (*(s8 *)(state + 0x9) == 1)) {
                blk.fy = *(f32 *)(obj + 0xc);
                blk.fz = *(f32 *)(obj + 0x10);
                blk.fw = *(f32 *)(obj + 0x14);
                objLightFn_8009a1dc(obj, lbl_803E3934, &blk, 1, 0);
                (**(void (**)(int, int, int, int, int, int))(*(int *)lbl_803DDAC0 + 0x4))(
                    obj, 1, 0, 2, -1, 0);
                Sfx_PlayFromObject(obj, (u16)*(s16 *)(state + 0x10));
                *(s16 *)(state + 0xa) = 0x32;
                *(u8 *)(state + 0x9) = 0;
                *(u8 *)(obj + 0xaf) |= 8;
                fn_801816F8(obj, player, state);
                zf = lbl_803E3938;
                *(f32 *)(obj + 0x24) = zf;
                *(f32 *)(obj + 0x2c) = zf;
                ObjHits_ClearHitVolumes(obj);
            } else if ((c != 0) && (*(s8 *)(state + 0x9) == 2)) {
                zf = lbl_803E3938;
                *(f32 *)(obj + 0x24) = zf;
                *(f32 *)(obj + 0x2c) = zf;
                *(s16 *)(state + 0xa) = 500;
                *(u8 *)(state + 0x9) = 0;
                *(int *)(obj + 0xf8) = 0;
                ObjHits_EnableObject(obj);
                *(u8 *)(obj + 0xaf) &= ~0x8;
                ObjHits_ClearHitVolumes(obj);
            }
        }
        *(s16 *)(state + 0xe) -= framesThisStep;
        if (*(s8 *)(state + 0x5) != 0) {
            if (getXZDistance((f32 *)(obj + 0x18), (f32 *)(def + 0x8)) >=
                (f32)(*(s16 *)(state + 0xc) * *(s16 *)(state + 0xc))) {
                zf = lbl_803E3938;
                *(f32 *)(obj + 0x24) = zf;
                *(f32 *)(obj + 0x2c) = zf;
                *(s16 *)(state + 0xa) = 500;
                *(u8 *)(state + 0x9) = 0;
                *(int *)(obj + 0xf8) = 0;
                ObjHits_EnableObject(obj);
                *(u8 *)(obj + 0xaf) &= ~0x8;
                ObjHits_ClearHitVolumes(obj);
            }
        } else {
            fn_801814D0(obj, player, state);
        }
        if ((*(s16 *)(state + 0xe) <= 0) && (*(s8 *)(state + 0x5) != 0)) {
            k = *(u8 *)(state + 0x1e);
            if ((k == 5) || (k == 6)) {
                Sfx_PlayFromObject(obj, 0x6c);
                *(s16 *)(state + 0xe) = (s16)(randomGetRange(0, 100) + 0x12c);
            } else if (((u8)(k - 1) <= 1) || (k == 3)) {
                Sfx_PlayFromObject(obj, 0x6d);
                *(s16 *)(state + 0xe) = (s16)(randomGetRange(0, 100) + 0x12c);
            }
        }
        if (*(int *)(obj + 0xf8) == 0) {
            *(s16 *)(obj + 0x6) &= ~0x4000;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
