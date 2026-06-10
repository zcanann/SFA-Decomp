#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/cfperch_state.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/cfperch.h"
#include "main/mapEventTypes.h"
#include "main/objanim_internal.h"
#include "main/objfx.h"
#include "main/objhits_types.h"
#include "main/resource.h"

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

f32 fn_80183204(int obj)
{
    u8* state = ((GameObject *)obj)->extra;
    return lbl_803E39AC - (f32)(u32)state[0x13] / (f32)(u32)state[0x28];
}

extern void ObjGroup_AddObject(int obj, int group);
extern void* lbl_803DDAC0;

void smallbasket_init(int obj, int def)
{
    int state;
    s16 v1c;
    s16 mode;

    state = *(int *)&((GameObject *)obj)->extra;
    ObjHits_DisableObject(obj);
    ObjGroup_AddObject(obj, 0x10);

    v1c = *(s16*)(def + 0x1c);
    if (v1c == 0) {
        ((CfperchState *)state)->unk18 = 0;
    } else {
        ((CfperchState *)state)->unk18 = v1c * 0x3c;
    }

    lbl_803DDAC0 = Resource_Acquire(0x5b, 1);
    ((CfperchState *)state)->randomTimer = (s16)(randomGetRange(0, 0x64) + 0x12c);
    ((CfperchState *)state)->unk1F = (u8)*(s16*)(def + 0x1a);
    *(s16*)obj = (s16)(*(s8*)(def + 0x18) << 8);
    ((CfperchState *)state)->enableGameBit = *(s16*)(def + 0x1e);
    ((CfperchState *)state)->unkC = *(s16*)(def + 0x20);
    if (((CfperchState *)state)->unkC == 0) {
        ((CfperchState *)state)->unkC = 0x14;
    }
    ((CfperchState *)state)->unk12 = 0x320;
    ((GameObject *)obj)->objectFlags |= 0x2000;
    ((CfperchState *)state)->unk1E = *(u8*)(def + 0x19);
    ((GameObject *)obj)->anim.previousLocalPosX = ((GameObject *)obj)->anim.localPosX;
    ((GameObject *)obj)->anim.previousLocalPosY = ((GameObject *)obj)->anim.localPosY;
    ((GameObject *)obj)->anim.previousLocalPosX = ((GameObject *)obj)->anim.localPosZ;

    if ((u32)GameBit_Get(((CfperchState *)state)->enableGameBit) != 0) {
        ((CfperchState *)state)->unk14 = 1;
        ObjHits_DisableObject(obj);
    }

    mode = ((GameObject *)obj)->anim.seqId;
    if (mode == 0x3cf) {
        ((CfperchState *)state)->unk10 = 0x60;
    } else if (mode == 0x662) {
        ((CfperchState *)state)->unk20 = 1;
        ((CfperchState *)state)->unk10 = 0x37d;
    } else {
        ((CfperchState *)state)->unk10 = 0x4a;
    }
}

void fn_80183250(int obj, int def)
{
    int state31;
    int player;
    f32 oldVel;
    int sum;
    u32 adj;
    u32 v;
    f32 limit;

    state31 = *(int *)&((GameObject *)obj)->anim.placementData;
    player = (int)Obj_GetPlayerObject();
    if ((*(u16 *)(*(int *)&((GameObject *)obj)->anim.parent + 0xb0) & 0x1000) != 0) {
        ((GameObject *)obj)->anim.localPosX = *(f32 *)(def + 0x24);
        ((GameObject *)obj)->anim.velocityX = 0.0f;
    } else {
        oldVel = ((GameObject *)obj)->anim.velocityX;
        sum = *(s16 *)(*(int *)&((GameObject *)obj)->anim.parent + 0x4) + *(u16 *)(def + 0x20);
        ((GameObject *)obj)->anim.velocityX = -(f32)sum / *(f32 *)(def + 0x1c);
        if ((oldVel <= 0.0f && ((GameObject *)obj)->anim.velocityX >= 0.0f) ||
            (oldVel >= 0.0f && ((GameObject *)obj)->anim.velocityX <= 0.0f)) {
            v = *(u32 *)(state31 + 0x14);
            adj = v - SMALLBASKET_LINKED_ID_BASE;
            if ((adj == SMALLBASKET_ROB_WAVE_ID_65D7) ||
                ((adj - SMALLBASKET_ROB_WAVE_ID_65D5) <=
                 (SMALLBASKET_ROB_WAVE_ID_65D6 - SMALLBASKET_ROB_WAVE_ID_65D5)) ||
                (v == SMALLBASKET_ROB_WAVE_DIRECT_ID) || (adj == SMALLBASKET_ROB_WAVE_ID_65D0) ||
                (adj == SMALLBASKET_ROB_WAVE_ID_65D2)) {
                if (Vec_distance(&((GameObject *)player)->anim.worldPosX, &((GameObject *)obj)->anim.worldPosX) < lbl_803E39BC) {
                    if ((u32)GameBit_Get(GAMEBIT_SFX_MUTE) == 0) {
                        Sfx_PlayFromObject(obj, SFXfend_rob_wave);
                    }
                }
            }
        }
        ((GameObject *)obj)->anim.localPosX = ((GameObject *)obj)->anim.localPosX + ((GameObject *)obj)->anim.velocityX;
        if (((GameObject *)obj)->anim.localPosX > (limit = lbl_803E39C0 + *(f32 *)(def + 0x24))) {
            ((GameObject *)obj)->anim.localPosX = limit;
        } else {
            limit = *(f32 *)(def + 0x24) - lbl_803E39C4;
            if (((GameObject *)obj)->anim.localPosX < limit) {
                ((GameObject *)obj)->anim.localPosX = limit;
            }
        }
    }
}

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
extern void vecRotateZXY(void *p, void *v);
extern void ObjMsg_SendToObject(int target, int msg, int obj, u32 value);
extern void fn_801816F8(int obj, int player, int state);
extern void fn_801814D0(int obj, int player, int state);
extern void fn_801821FC(int obj);
extern f32 getXZDistance(f32 *a, f32 *b);
extern u8 framesThisStep;
extern f32 timeDelta;
extern int *gSHthorntailAnimationInterface;
extern MapEventInterface **gMapEventInterface;
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
    def = *(int *)&((GameObject *)obj)->anim.placementData;
    animSpeed = lbl_803E3950;
    (**(void (**)(f32 *))(*gSHthorntailAnimationInterface + 0x18))(&animSpeed);
    state = *(int *)&((GameObject *)obj)->extra;
    if ((*gMapEventInterface)->isTimedEventActive(((ObjPlacement *)def)->mapId) == 0) {
        return;
    }
    playerState = *(int *)(player + 0xb8);
    if (((CfperchState *)state)->unk12 <= 0) {
        ((CfperchState *)state)->unk12 = 800;
        ((CfperchState *)state)->unkA = 1;
        ((CfperchState *)state)->unk9 = 0;
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        fn_801816F8(obj, player, state);
        zf = lbl_803E3938;
        ((GameObject *)obj)->anim.velocityX = zf;
        ((GameObject *)obj)->anim.velocityZ = zf;
    }
    if (((CfperchState *)state)->unk14 != 0) {
        flag = 0;
        ((GameObject *)obj)->anim.alpha = flag;
        ((CfperchState *)state)->unk14 -= (s16)(int)(timeDelta * animSpeed);
        if (((CfperchState *)state)->unk14 <= 0) {
            if ((Vec_distance(&((GameObject *)obj)->anim.worldPosX, (f32 *)((int)Obj_GetPlayerObject() + 0x18)) > lbl_803E3930) &&
                (((CfperchState *)state)->enableGameBit == -1)) {
                flag = 1;
            }
            if (flag == 0) {
                ((CfperchState *)state)->unk14 = 1;
            } else {
                ((CfperchState *)state)->unk14 = 0;
                ((CfperchState *)state)->unkA = 0;
                ObjHits_EnableObject(obj);
                ObjHits_SyncObjectPositionIfDirty(obj);
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x8;
                ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            }
        }
    } else {
        if (((CfperchState *)state)->unk5 != 2) {
            level = (int)(lbl_803E3978 * timeDelta + (f32)(u32)((GameObject *)obj)->anim.alpha);
            if (level > 0xff) {
                level = 0xff;
            }
            ((GameObject *)obj)->anim.alpha = level;
        }
        if (((CfperchState *)state)->unkA != 0) {
            ObjHits_DisableObject(obj);
            ((CfperchState *)state)->unkA -= framesThisStep;
            if (((CfperchState *)state)->unkA <= 0) {
                if (((CfperchState *)state)->unk18 != 0) {
                    ((CfperchState *)state)->unk14 = ((CfperchState *)state)->unk18;
                } else {
                    ((CfperchState *)state)->unk14 = 1;
                }
                (*gMapEventInterface)->startTimedEvent(((ObjPlacement *)def)->mapId, (f32)((CfperchState *)state)->unk18);
                ((GameObject *)obj)->anim.localPosX = ((ObjPlacement *)def)->posX;
                ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)def)->posY;
                ((GameObject *)obj)->anim.localPosZ = ((ObjPlacement *)def)->posZ;
                ((GameObject *)obj)->anim.previousLocalPosX = ((ObjPlacement *)def)->posX;
                ((GameObject *)obj)->anim.previousLocalPosY = ((ObjPlacement *)def)->posY;
                ((GameObject *)obj)->anim.previousLocalPosZ = ((ObjPlacement *)def)->posZ;
                zf = lbl_803E3938;
                ((GameObject *)obj)->anim.velocityX = zf;
                ((GameObject *)obj)->anim.velocityY = zf;
                ((GameObject *)obj)->anim.velocityZ = zf;
            }
            if (((CfperchState *)state)->unkA <= 0x32) {
                return;
            }
        }
        if (*(s8 *)(state + 0x9) != 1) {
            if (((CfperchState *)state)->unk5 == 0) {
                flag = 0;
                if (((buttonGetDisabled(0) & 0x100) == 0) && (((GameObject *)obj)->unkF8 == 0) &&
                    (ObjTrigger_IsSet(obj) != 0)) {
                    ((CfperchState *)state)->unk0 = -0x8000;
                    ((CfperchState *)state)->unk2 = 0;
                    ObjHits_DisableObject(obj);
                    flag = 1;
                }
                ((CfperchState *)state)->unk5 = flag;
                if (((CfperchState *)state)->unk5 != 0) {
                    ((CfperchState *)state)->unk6 = 1;
                }
                if (((GameObject *)obj)->unkF8 == 0) {
                    ObjHits_EnableObject(obj);
                    if ((((CfperchState *)state)->unk20 != 0) && (playerIsDisguised(player) == 0)) {
                        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x10;
                    } else {
                        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x10;
                    }
                }
                ((GameObject *)obj)->anim.previousLocalPosX = ((GameObject *)obj)->anim.localPosX;
                ((GameObject *)obj)->anim.previousLocalPosY = ((GameObject *)obj)->anim.localPosZ;
                ((GameObject *)obj)->anim.previousLocalPosZ = ((GameObject *)obj)->anim.localPosZ;
            } else {
                ObjHits_DisableObject(obj);
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                if ((playerGetStateFlag310(player) & 0x4000) != 0) {
                    setAButtonIcon(5);
                } else {
                    setAButtonIcon(4);
                }
                if ((getButtonsJustPressed(0) & 0x100) != 0) {
                    if (fn_80295BF0(player) != 0) {
                        ((CfperchState *)state)->unk6 = 0;
                        buttonDisable(0, 0x100);
                    } else {
                        Sfx_PlayFromObject(0, 0x10a);
                    }
                }
                if (((GameObject *)obj)->unkF8 == 1) {
                    *(u8 *)(state + 0x5) = 2;
                }
                if (((((CfperchState *)state)->unk5 == 2) && (((GameObject *)obj)->unkF8 == 0)) ||
                    ((((CfperchState *)state)->unk20 != 0) && (playerIsDisguised(player) == 0))) {
                    if (fn_8029669C(player) != 0) {
                        *(u8 *)(state + 0x5) = 0;
                        ((CfperchState *)state)->unk9 = 1;
                        ((GameObject *)obj)->anim.velocityY = lbl_803E397C * *(f32 *)(playerState + 0x298) + lbl_803E3958;
                        ((GameObject *)obj)->anim.velocityZ = lbl_803E3980 * *(f32 *)(playerState + 0x298) + lbl_803E3974;
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
                        vecRotateZXY(&blk, (void *)&((GameObject *)obj)->anim.velocityX);
                        Sfx_PlayFromObject(obj, 0x6b);
                    } else if (fn_802966B4(player) != 0) {
                        *(u8 *)(state + 0x5) = 0;
                        ((CfperchState *)state)->unk9 = 2;
                        zf = lbl_803E3938;
                        ((GameObject *)obj)->anim.velocityX = zf;
                        ((GameObject *)obj)->anim.velocityY = zf;
                        ((GameObject *)obj)->anim.velocityZ = zf;
                        ObjHits_EnableObject(obj);
                        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x8;
                        ObjHits_ClearHitVolumes(obj);
                    } else {
                        *(u8 *)(state + 0x5) = 0;
                        ((CfperchState *)state)->unk9 = 1;
                        ((GameObject *)obj)->anim.velocityY = lbl_803E3988 * *(f32 *)(playerState + 0x298) + lbl_803E3984;
                        ((GameObject *)obj)->anim.velocityZ = lbl_803E3990 * *(f32 *)(playerState + 0x298) + lbl_803E398C;
                        blk.fy = lbl_803E3938;
                        blk.fz = lbl_803E3938;
                        blk.fw = lbl_803E3938;
                        blk.fx = lbl_803E3950;
                        blk.h2 = 0;
                        blk.h1 = 0;
                        blk.h0 = *(s16 *)player;
                        vecRotateZXY(&blk, (void *)&((GameObject *)obj)->anim.velocityX);
                        Sfx_PlayFromObject(obj, 0x6b);
                        ((CfperchState *)state)->unk6 = 0;
                        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                    }
                }
                if (*(s8 *)(state + 0x6) != 0) {
                    ((CfperchState *)state)->unkA = 0;
                    ((CfperchState *)state)->unk14 = 0;
                    ObjMsg_SendToObject(player, 0x100010, obj,
                                        (((CfperchState *)state)->unk2 << 16) | ((u16)((CfperchState *)state)->unk0));
                }
            }
        } else if (*(s8 *)(state + 0x9) != 0) {
            ((CfperchState *)state)->unk12 -= framesThisStep;
            if (*(s8 *)(state + 0x9) == 1) {
                ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
                if (((GameObject *)obj)->anim.velocityY > lbl_803E3994) {
                    ((GameObject *)obj)->anim.velocityY = lbl_803E3998 * timeDelta + ((GameObject *)obj)->anim.velocityY;
                }
                ObjHits_EnableObject(obj);
            }
            ((GameObject *)obj)->anim.localPosX = ((GameObject *)obj)->anim.velocityX * timeDelta + ((GameObject *)obj)->anim.localPosX;
            ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
            ((GameObject *)obj)->anim.localPosZ = ((GameObject *)obj)->anim.velocityZ * timeDelta + ((GameObject *)obj)->anim.localPosZ;
            fn_801821FC(obj);
            c = (*(ObjHitsPriorityState **)(obj + 0x54))->contactFlags;
            if ((c != 0) && (*(s8 *)(state + 0x9) == 1)) {
                blk.fy = ((GameObject *)obj)->anim.localPosX;
                blk.fz = ((GameObject *)obj)->anim.localPosY;
                blk.fw = ((GameObject *)obj)->anim.localPosZ;
                objLightFn_8009a1dc((void *)obj, lbl_803E3934, &blk, 1, 0);
                (**(void (**)(int, int, int, int, int, int))(*(int *)lbl_803DDAC0 + 0x4))(
                    obj, 1, 0, 2, -1, 0);
                Sfx_PlayFromObject(obj, (u16)((CfperchState *)state)->unk10);
                ((CfperchState *)state)->unkA = 0x32;
                ((CfperchState *)state)->unk9 = 0;
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                fn_801816F8(obj, player, state);
                zf = lbl_803E3938;
                ((GameObject *)obj)->anim.velocityX = zf;
                ((GameObject *)obj)->anim.velocityZ = zf;
                ObjHits_ClearHitVolumes(obj);
            } else if ((c != 0) && (*(s8 *)(state + 0x9) == 2)) {
                zf = lbl_803E3938;
                ((GameObject *)obj)->anim.velocityX = zf;
                ((GameObject *)obj)->anim.velocityZ = zf;
                ((CfperchState *)state)->unkA = 500;
                ((CfperchState *)state)->unk9 = 0;
                ((GameObject *)obj)->unkF8 = 0;
                ObjHits_EnableObject(obj);
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x8;
                ObjHits_ClearHitVolumes(obj);
            }
        }
        ((CfperchState *)state)->randomTimer -= framesThisStep;
        if (((CfperchState *)state)->unk5 != 0) {
            if (getXZDistance(&((GameObject *)obj)->anim.worldPosX, (f32 *)(def + 0x8)) >=
                (f32)(((CfperchState *)state)->unkC * ((CfperchState *)state)->unkC)) {
                zf = lbl_803E3938;
                ((GameObject *)obj)->anim.velocityX = zf;
                ((GameObject *)obj)->anim.velocityZ = zf;
                ((CfperchState *)state)->unkA = 500;
                ((CfperchState *)state)->unk9 = 0;
                ((GameObject *)obj)->unkF8 = 0;
                ObjHits_EnableObject(obj);
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x8;
                ObjHits_ClearHitVolumes(obj);
            }
        } else {
            fn_801814D0(obj, player, state);
        }
        if ((((CfperchState *)state)->randomTimer <= 0) && (((CfperchState *)state)->unk5 != 0)) {
            k = ((CfperchState *)state)->unk1E;
            if ((k == 5) || (k == 6)) {
                Sfx_PlayFromObject(obj, 0x6c);
                ((CfperchState *)state)->randomTimer = (s16)(randomGetRange(0, 100) + 0x12c);
            } else if (((u8)(k - 1) <= 1) || (k == 3)) {
                Sfx_PlayFromObject(obj, 0x6d);
                ((CfperchState *)state)->randomTimer = (s16)(randomGetRange(0, 100) + 0x12c);
            }
        }
        if (((GameObject *)obj)->unkF8 == 0) {
            ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        }
    }
}
