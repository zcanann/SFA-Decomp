#include "main/dll_000A_expgfx.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEvent.h"
#include "main/objseq.h"
#include "main/dll/CF/CFBaby.h"

typedef struct InfopointPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
} InfopointPlacement;


typedef struct Dll109State
{
    u8 pad0[0xA - 0x0];
    u8 unkA;
    u8 padB[0x10 - 0xB];
} Dll109State;


typedef struct InfopointObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    u8 pad1A[0x1B - 0x1A];
    u8 unk1B;
    s16 unk1C;
    u8 unk1E;
    u8 unk1F;
} InfopointObjectDef;


typedef struct FallLaddersObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} FallLaddersObjectDef;


typedef struct FlammablevineObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} FlammablevineObjectDef;


typedef struct FlammablevinePlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} FlammablevinePlacement;


typedef struct LandedArwingPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} LandedArwingPlacement;


typedef struct LandedArwingUpdateHitReactionPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} LandedArwingUpdateHitReactionPlacement;


typedef struct LandedArwingUpdateDamageTexturePlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} LandedArwingUpdateDamageTexturePlacement;


typedef struct ColdwatercontrolState
{
    u8 pad0[0x8 - 0x0];
    u8 unk8;
    u8 unk9;
    u8 padA[0x10 - 0xA];
} ColdwatercontrolState;


typedef struct InfopointState
{
    u8 pad0[0x8 - 0x0];
    u8 unk8;
    u8 unk9;
    u8 padA[0x20 - 0xA];
} InfopointState;


typedef struct FlammablevineState
{
    u8 pad0[0x8 - 0x0];
    u8 unk8;
    u8 unk9;
    u8 padA[0x14 - 0xA];
} FlammablevineState;


extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined8 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjHits_RecordObjectHit();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject(int group, uint obj, float* maxDistance);
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjHits_PollPriorityHitEffectWithCooldown();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern int ObjTrigger_IsSet();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_800427c8();
extern undefined4 FUN_80042800();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80043030();
extern undefined4 FUN_80044404();
extern undefined4 FUN_80053c98();
extern void* Obj_GetPlayerObject(void);

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern EffectInterface** gPartfxInterface;
extern f32 FLOAT_803e4830;
extern f32 FLOAT_803e4840;
extern f32 FLOAT_803e4844;
extern f32 FLOAT_803e4848;


/*
 * --INFO--
 *
 * Function: FUN_80187664
 * EN v1.0 Address: 0x80187664
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x80187720
 * EN v1.1 Size: 196b
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
 * Function: infopoint_hitDetect
 * EN v1.0 Address: 0x8018843C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801884A0
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void infopoint_hitDetect(void);


/*
 * --INFO--
 *
 * Function: FUN_80189054
 * EN v1.0 Address: 0x80189054
 * EN v1.0 Size: 2620b
 * EN v1.1 Address: 0x80189218
 * EN v1.1 Size: 1552b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80189054(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , int param_11, int param_12, undefined4 param_13, undefined4 param_14, undefined4 param_15,
             undefined4 param_16)
{
    undefined4 uVar1;
    char cVar2;
    int iVar3;
    int iVar4;
    int iVar5;
    int iVar6;
    int iVar7;
    undefined8 extraout_f1;
    undefined8 extraout_f1_00;
    undefined8 extraout_f1_01;
    undefined8 extraout_f1_02;
    undefined8 extraout_f1_03;
    undefined8 uVar8;

    iVar6 = *(int*)&((GameObject*)param_9)->anim.placementData;
    iVar5 = *(int*)&((GameObject*)param_9)->extra;
    iVar7 = 0;
    iVar4 = param_11;
    do
    {
        if ((int)(uint) * (byte*)(param_11 + 0x8b) <= iVar7)
        {
            return 0;
        }
        switch (*(u8*)(param_11 + iVar7 + 0x81))
        {
        case 2:
        case 0x65:
            iVar4 = *(int*)(iVar6 + 0x14);
            if (iVar4 == 0x49f5a)
            {
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x26);
                iVar4 = 1;
                FUN_80042b9c(0, 0, 1);
                uVar1 = FUN_80044404(0x26);
                FUN_80042bec(uVar1, 0);
                uVar1 = FUN_80044404(0xb);
                FUN_80042bec(uVar1, 1);
            }
            else if (iVar4 < 0x49f5a)
            {
                if (iVar4 == 0x451b9)
                {
                    cVar2 = (*gMapEventInterface)->getMode(0xd);
                    param_1 = extraout_f1;
                    if (cVar2 == '\x02')
                    {
                        FUN_80041ff8(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0xb);
                        iVar4 = 1;
                        FUN_80042b9c(0, 0, 1);
                        uVar1 = FUN_80044404(0xb);
                        FUN_80042bec(uVar1, 0);
                    }
                    else
                    {
                        FUN_80041ff8(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                        iVar4 = 1;
                        FUN_80042b9c(0, 0, 1);
                        uVar1 = FUN_80044404(0x29);
                        FUN_80042bec(uVar1, 0);
                    }
                }
                else
                {
                    if ((0x451b8 < iVar4) || (iVar4 != 0x43775)) goto LAB_801893dc;
                    FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                    iVar4 = 1;
                    FUN_80042b9c(0, 0, 1);
                    uVar1 = FUN_80044404(0x29);
                    FUN_80042bec(uVar1, 0);
                }
            }
            else if (iVar4 == 0x4cd65)
            {
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x41);
                iVar4 = 1;
                FUN_80042b9c(0, 0, 1);
                uVar1 = FUN_80044404(0x41);
                FUN_80042bec(uVar1, 0);
                uVar1 = FUN_80044404(0xb);
                FUN_80042bec(uVar1, 1);
            }
            else
            {
            LAB_801893dc:
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                iVar4 = 1;
                FUN_80042b9c(0, 0, 1);
                uVar1 = FUN_80044404(0x29);
                FUN_80042bec(uVar1, 0);
            }
            break;
        case 3:
        case 100:
            iVar3 = *(int*)(iVar6 + 0x14);
            if (iVar3 == 0x49f5a)
            {
                iVar4 = 0;
                param_12 = (int)*gMapEventInterface;
                param_1 = (**(code**)(param_12 + 0x50))(0xb, 4);
            }
            else if (iVar3 < 0x49f5a)
            {
                if (iVar3 == 0x451b9)
                {
                    cVar2 = (*gMapEventInterface)->getMode(0xd);
                    param_1 = extraout_f1_00;
                    if (cVar2 == '\x02')
                    {
                        uVar8 = extraout_f1_00;
                        FUN_80042b9c(0, 0, 1);
                        FUN_80044404(0xd);
                        FUN_80043030(uVar8, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                        (*gMapEventInterface)->setAnimEvent(0xd, 10, 0);
                        (*gMapEventInterface)->setAnimEvent(0xd, 0xb, 0);
                        iVar4 = 0;
                        param_12 = (int)*gMapEventInterface;
                        param_1 = (**(code**)(param_12 + 0x50))(0xd, 0xe);
                    }
                }
                else if ((iVar3 < 0x451b9) && (iVar3 == 0x43775))
                {
                    iVar4 = 1;
                    FUN_80042b9c(0, 0, 1);
                    FUN_80044404(7);
                    param_1 = FUN_80043030(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                }
            }
            else if (iVar3 == 0x4cd65)
            {
                iVar4 = 1;
                FUN_80042b9c(0, 0, 1);
                FUN_80044404(0xb);
                param_1 = FUN_80043030(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
            }
            break;
        case 5:
            iVar3 = *(int*)(iVar6 + 0x14);
            if (iVar3 == 0x451b9)
            {
                cVar2 = (*gMapEventInterface)->getMode(0xd);
                param_1 = extraout_f1_01;
                if (cVar2 == '\x02')
                {
                    param_1 = FUN_80042800();
                }
            }
            else if (iVar3 < 0x451b9)
            {
                if (iVar3 == 0x43775)
                {
                LAB_801895a4:
                    param_1 = FUN_80042800();
                }
            }
            else if (iVar3 == 0x49f5a) goto LAB_801895a4;
            break;
        case 6:
            iVar3 = *(int*)(iVar6 + 0x14);
            if (iVar3 == 0x451b9)
            {
                cVar2 = (*gMapEventInterface)->getMode(0xd);
                param_1 = extraout_f1_02;
                if (cVar2 == '\x02')
                {
                    param_1 = FUN_800427c8();
                }
            }
            else if (iVar3 < 0x451b9)
            {
                if (iVar3 == 0x43775)
                {
                LAB_80189614:
                    param_1 = FUN_800427c8();
                }
            }
            else if (iVar3 == 0x49f5a) goto LAB_80189614;
            break;
        case 7:
        case 0x66:
            iVar3 = *(int*)(iVar6 + 0x14);
            if (iVar3 == 0x49f5a)
            {
                param_1 = FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x32,
                                       '\0', iVar4, param_12, param_13, param_14, param_15, param_16);
            }
            else if (iVar3 < 0x49f5a)
            {
                if ((iVar3 == 0x451b9) &&
                    (cVar2 = (*gMapEventInterface)->getMode(0xd), param_1 = extraout_f1_03,
                        cVar2 == '\x02'))
                {
                    iVar4 = (int)*gMapEventInterface;
                    uVar8 = (**(code**)(iVar4 + 0x44))(0xb, 5);
                    param_1 = FUN_80053c98(uVar8, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x4e,
                                           '\0', iVar4, param_12, param_13, param_14, param_15, param_16);
                }
            }
            else if (iVar3 == 0x4cd65)
            {
                FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x7f, '\0', iVar4
                             , param_12, param_13, param_14, param_15, param_16);
                iVar4 = (int)*gMapEventInterface;
                param_1 = (**(code**)(iVar4 + 0x44))(0x41, 2);
            }
            break;
        case 10:
            *(u8*)(iVar5 + 0x1a) = 1;
            break;
        case 0xb:
            *(u8*)(iVar5 + 0x1a) = 0;
            break;
        case 0xc:
            *(float*)(iVar5 + 4) = FLOAT_803e4830;
            break;
        case 0xd:
            *(float*)(iVar5 + 4) = FLOAT_803e4840;
            break;
        case 0xe:
            *(float*)(iVar5 + 4) = FLOAT_803e4844;
            break;
        case 0xf:
            *(float*)(iVar5 + 4) = FLOAT_803e4848;
            break;
        case 0x10:
            *(float*)(iVar5 + 8) = FLOAT_803e4830;
            break;
        case 0x11:
            *(float*)(iVar5 + 8) = FLOAT_803e4840;
            break;
        case 0x12:
            *(float*)(iVar5 + 8) = FLOAT_803e4844;
            break;
        case 0x13:
            *(float*)(iVar5 + 8) = FLOAT_803e4848;
            break;
        case 0x14:
            *(float*)(iVar5 + 0xc) = FLOAT_803e4830;
            break;
        case 0x15:
            *(float*)(iVar5 + 0xc) = FLOAT_803e4840;
            break;
        case 0x16:
            *(float*)(iVar5 + 0xc) = FLOAT_803e4844;
            break;
        case 0x17:
            *(float*)(iVar5 + 0xc) = FLOAT_803e4848;
            break;
        case 0x18:
            iVar3 = *(int*)(iVar5 + 0x10);
            if (iVar3 != 0)
            {
                *(ushort*)(iVar3 + 6) = *(ushort*)(iVar3 + 6) & 0xbfff;
            }
            break;
        case 0x19:
            iVar3 = *(int*)(iVar5 + 0x10);
            if (iVar3 != 0)
            {
                *(ushort*)(iVar3 + 6) = *(ushort*)(iVar3 + 6) | 0x4000;
            }
        }
        iVar7 = iVar7 + 1;
    }
    while (true);
}


/* Trivial 4b 0-arg blr leaves. */
void flammablevine_release(void);

void flammablevine_initialise(void);

void dll_109_hitDetect_nop(void);

void dll_109_release_nop(void);

void dll_109_initialise_nop(void);

void Fall_Ladders_render(void);

void Fall_Ladders_hitDetect(void);

void Fall_Ladders_release(void);

void Fall_Ladders_initialise(void);

void infopoint_free(void);

void infopoint_release(void);

void infopoint_initialise(void);

void decoration11a_free(void)
{
}

void decoration11a_update(void)
{
}

/* 8b "li r3, N; blr" returners. */
int flammablevine_getExtraSize(void);
int flammablevine_getObjectTypeId(void);
int dll_109_getExtraSize_ret_16(void);
int dll_109_getObjectTypeId(void);
int Fall_Ladders_SeqFn(void);
int Fall_Ladders_getExtraSize(void);
int Fall_Ladders_getObjectTypeId(void);
int coldwatercontrol_getExtraSize(void);
int infopoint_getExtraSize(void);
int infopoint_getObjectTypeId(void);
int decoration11a_getExtraSize(void) { return 0x1c; }
int landed_arwing_getExtraSize(void);

typedef struct FallLaddersState
{
    f32 restYOffset;
    s16 lowerGameBit;
    s16 upperGameBit;
    u8 motionState;
    u8 playStartSound;
    s16 delay;
} FallLaddersState;

typedef struct CarryableBreakRespawnState
{
    u8 pad0[0xa];
    u8 state;
    u8 padB;
    f32 timer;
} CarryableBreakRespawnState;

extern int* gCarryableInterface;
extern f32 timeDelta;
extern f32 lbl_803E3B44;
extern f32 lbl_803E3B48;
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int type);
extern int Obj_SetupObject(int setup, int arg1, int arg2, int arg3, int arg4);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int ViewFrustum_IsSphereVisible(f32* pos, f32 radius);

/* Carryable impact state machine that spawns break particles, hides, then respawns. */
#pragma scheduling off
#pragma peephole off
void carryable_break_respawn_update(int obj);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3AF8;
extern f32 lbl_803E3AFC;
extern f32 lbl_803E3B00;
extern f32 lbl_803E3B04;
extern f32 lbl_803E3B08;
extern f32 lbl_803E3B0C;
extern f32 lbl_803E3B10;
extern f32 lbl_803E3B14;
extern f32 lbl_803E3B18;
extern f32 lbl_803E3B1C;
extern f32 lbl_803E3B20;
extern f32 lbl_803E3B24;
extern f32 lbl_803E3B28;
extern f32 lbl_803E3B2C;
extern f32 lbl_803E3B30;
extern f32 lbl_803E3B34;
extern void objRenderFn_8003b8f4(f32);
extern void Obj_RemoveFromUpdateList(int obj);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern void fn_80098B18(int obj, f32 scale, int type, int a, int b, int c);
extern int cMenuGetSelectedItem(void);
extern void* getTrickyObject(void);
extern f32 lbl_803E3B70;
extern f32 lbl_803E3B78;

void flammablevine_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void infopoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void decoration11a_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3B78);
}

/* ObjGroup_RemoveObject(x, N) wrappers. */
void flammablevine_free(int x);

void flammablevine_hitDetect(int obj);

void flammablevine_init(int obj, int def);

void flammablevine_update(int obj);

/* Fall_Ladders_free: expgfx interface freeObject callback. */
#pragma scheduling on
#pragma peephole on
void Fall_Ladders_free(int obj);

/* coldwatercontrol_init: set float field + OR flag bits. */
extern f32 lbl_803E3B68;
extern f32 lbl_803E3B6C;
extern int fn_80295C40(int obj);
#pragma scheduling off
#pragma peephole off
void coldwatercontrol_update(int obj);

#pragma scheduling on
void coldwatercontrol_init(int obj);

/* landed_arwing_free: free child object + detach link. */
extern void Obj_FreeObject(int obj);
#pragma scheduling off
void landed_arwing_free(int obj);

/* landed_arwing_render: visible-guarded render with extra call. */
extern f32 lbl_803E3BA4;
extern void landed_arwing_renderPathEffects(int obj);

void landed_arwing_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

typedef struct LandedArwingFxPoint
{
    f32 scale;
    u8 pathPoint;
    u8 arg5;
    u8 arg6;
    u8 pad;
} LandedArwingFxPoint;

typedef struct LandedArwingFxScratch
{
    u8 effectPos[12];
    f32 x;
    f32 y;
    f32 z;
} LandedArwingFxScratch;

typedef struct CFLandedArwingState
{
    f32 unk0;
    f32 path7Fx;
    f32 path8Fx;
    f32 path6Fx;
    int childObject;
    s16 unk14;
    u8 sequenceState;
    u8 unk17;
    u8 unk18;
    u8 unk19;
    u8 enablePathFx;
    u8 unk1B;
    u8 hitStarted;
    u8 hitFlags;
    u8 unk1E;
    u8 spawnCount;
    u8 hitCooldown[4];
} CFLandedArwingState;

typedef struct LandedArwingHitFlagBits
{
    u8 damaged : 1;
    u8 impactHandled : 1;
    u8 gameBit24Set : 1;
    u8 reactionDone : 1;
    u8 rest : 4;
} LandedArwingHitFlagBits;

extern LandedArwingFxPoint lbl_80321A28[];
extern f32 lbl_803E3B98;
extern f32 lbl_803E3B9C;
extern void objfx_spawnMaskedHitEffect(int obj, f32 scale, int arg4, int arg5, int arg6, void* pos);
extern void objfx_spawnLightPulse(int obj, f32 scale, int arg4, int arg5, int arg6, f32 value, void* pos);

void landed_arwing_renderPathEffects(int obj);

extern void loadMapAndParent(int mapId);
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int dirIdx, int locked);
extern void mapUnload(int dirIdx, int flags);
extern void setLoadedFileFlags_blocks1(void);
extern void clearLoadedFileFlags_blocks1(void);
extern void warpToMap(int mapId, int arg);
extern void unlockLevel(int a, int b, int c);
extern f32 lbl_803E3BA8;
extern f32 lbl_803E3BAC;
extern f32 lbl_803E3BB0;

#define MAP_EVENT_STATUS(mapId) (*gMapEventInterface)->getMode((mapId))
#define MAP_EVENT_SET(mapId, value) (*gMapEventInterface)->setMode((mapId), (value))
#define MAP_EVENT_OP(mapId, arg, value) (*gMapEventInterface)->setAnimEvent((mapId), (arg), (value))

int Landed_Arwing_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

extern void fn_8022F270(int obj, int arg);
extern void fn_8022F27C(int obj);
extern int fn_802972A8(int obj);
extern u8 fn_8012DDA4(void);
extern void cutSceneFn_8011dd30(void);
extern f32 lbl_803E3BA0;

void landed_arwing_update(int obj);

/* infopoint_update: if low bit on 0xaf, disable button + vtable[0x48]. */
extern void buttonDisable(int p1, int mask);

void infopoint_update(int obj);

/* landed_arwing_init: flag bits, counter, conditional unlock, set callback. */
void landed_arwing_init(int obj, int param);

extern f32 lbl_803E3BB8;
extern f32 lbl_803E3BBC;
extern f32 lbl_803E3BC0;
extern f32 lbl_803E3BC4;
extern int* objFindTexture(int obj, int textureIndex, int materialIndex);

/* landed arwing hit/animation step: handles impact reactions and spawned debris. */
void landed_arwing_updateHitReaction(int obj, CFLandedArwingState* state);

/* landed arwing material flags: mirrors game bits into the damaged texture state. */
void landed_arwing_updateDamageTexture(int obj, CFLandedArwingState* state);

void dll_109_init(int obj, u8* p);

#pragma dont_inline on
#pragma peephole on
void decoration11a_expandBoundsWithVertex(f32* vertex, f32* maxOut, f32* minOut)
{
    f32 v;
    v = vertex[0];
    if (v > maxOut[0]) maxOut[0] = v;
    else if (v < minOut[0]) minOut[0] = v;
    v = vertex[1];
    if (v > maxOut[1]) maxOut[1] = v;
    else if (v < minOut[1]) minOut[1] = v;
    v = vertex[2];
    if (v > maxOut[2]) maxOut[2] = v;
    else if (v < minOut[2]) minOut[2] = v;
}
#pragma dont_inline reset

#pragma peephole off
int InfoPoint_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
#pragma peephole reset

#pragma scheduling on
void dll_109_free(int obj);

extern f32 lbl_803E3B40;
#pragma scheduling off
#pragma peephole off
void dll_109_render(int obj, int p1, int p2, int p3, int p4, s8 visible);

extern void Obj_SetActiveModelIndex(int* obj, int idx);
extern f32 lbl_803E3B50;
extern f32 lbl_803E3B54;
extern f32 lbl_803E3B58;
extern f32 lbl_803E3B5C;

void Fall_Ladders_update(int obj);

void Fall_Ladders_init(int* obj, s8* def);

extern int textureLoadAsset(int id);
extern int* gameTextGet(int id);
extern int lbl_803219A0[];
extern int lbl_80321990[];

void infopoint_init(int* obj, u8* def);

extern f32 lbl_803E3B7C;
extern f32 lbl_803E3B88;
extern f32 Vec_distance(f32 * a, f32 * b);
extern void objWorldToLocalPos(f32* out, int obj, f32* pos);
extern void Model_GetVertexPosition(int* model, int idx, f32* out);
extern void PSVECScale(f32* dst, f32* src, f32 s);
extern f32 PSVECMag(f32 * v);

void decoration11a_hitDetect(int obj)
{
    s16 modelId;
    f32* state;
    int count;
    int* objects;
    f32 radius;
    f32 localPos[3];
    f32 bMax;
    f32 sum;
    f32 delta;
    f32 term;

    modelId = ((GameObject*)obj)->anim.seqId;
    if (modelId == 0x7a1)
    {
        goto check_decor_objects;
    }
    if (modelId == 0x7a2)
    {
        goto check_decor_objects;
    }
    if (modelId != 0x7a3)
    {
        return;
    }

check_decor_objects:
    state = ((GameObject*)obj)->extra;
    objects = ObjGroup_GetObjects(2, &count);
    while (count != 0)
    {
        if (Vec_distance((f32*)(*objects + 0x18), (f32*)(obj + 0x18)) < state[6])
        {
            if (*(void**)(*objects + 0x54) != NULL)
            {
                radius = (f32) * (s16*)(*(int*)(*objects + 0x54) + 0x5a);
                objWorldToLocalPos(localPos, obj, (f32*)(*objects + 0xc));

                sum = lbl_803E3B7C;

                {
                f32 bMin;
                f32 px;
                bMin = state[3];
                bMax = state[0];
                sum += ((px = localPos[0]) < bMin) ? (px - bMin) * (px - bMin)
                     : (px > bMax) ? (px - bMax) * (px - bMax)
                     : lbl_803E3B7C;
                }

                {
                f32 bMax;
                f32 bMin;
                bMin = state[4];
                bMax = state[1];
                if (localPos[1] < bMin)
                {
                    delta = localPos[1] - bMin;
                    term = delta * delta;
                }
                else if (localPos[1] > bMax)
                {
                    delta = localPos[1] - bMax;
                    term = delta * delta;
                }
                else
                {
                    term = *(f32*)&lbl_803E3B7C;
                }
                sum += term;
                }

                {
                f32 bMax;
                f32 bMin;
                bMin = state[5];
                bMax = state[2];
                if (localPos[2] < bMin)
                {
                    delta = localPos[2] - bMin;
                    term = delta * delta;
                }
                else if (localPos[2] > bMax)
                {
                    delta = localPos[2] - bMax;
                    term = delta * delta;
                }
                else
                {
                    term = *(f32*)&lbl_803E3B7C;
                }
                sum += term;
                }

                if (sum < radius * radius)
                {
                    (*(ObjHitsPriorityState**)(*objects + 0x54))->lastHitObject = obj;
                    (*(ObjHitsPriorityState**)(*objects + 0x54))->contactFlags = 1;
                }
            }
        }
        count--;
        objects++;
    }
}

void decoration11a_init(int* obj, u8* def)
{
    ((GameObject*)obj)->anim.rotZ = (s16)((s32)def[24] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32)def[25] << 8);
    *(s16*)obj = (s16)((s32)def[26] << 8);
    if (def[27] != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)
        def[27] / lbl_803E3B88;
        if (((GameObject*)obj)->anim.rootMotionScale == lbl_803E3B7C)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3B78;
        }
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * *(f32*)(*(int*)&((
            GameObject*)obj)->anim.modelInstance + 4);
    }
    {
        s16 model = ((GameObject*)obj)->anim.seqId;
        if (model == 1953)
        {
            goto calc_decor_bounds;
        }
        if (model == 1954)
        {
            goto calc_decor_bounds;
        }
        if (model == 1955)
        {
        calc_decor_bounds:
            {
                int i;
                int* m;
                f32* state;
                f32 tmp[3];
                f32 magB;
                f32 maxMag;

                state = ((GameObject*)obj)->extra;
                m = **(int***)(*(int*)&((GameObject*)obj)->anim.banks);
                Model_GetVertexPosition(m, 0, state);
                Model_GetVertexPosition(m, 0, state + 3);
                for (i = 1; i < *(u16*)((char*)m + 0xe4); i++)
                {
                    Model_GetVertexPosition(m, i, tmp);
                    decoration11a_expandBoundsWithVertex(tmp, state, state + 3);
                }
                PSVECScale(state, state, ((GameObject*)obj)->anim.rootMotionScale);
                PSVECScale(state + 3, state + 3, ((GameObject*)obj)->anim.rootMotionScale);
                magB = PSVECMag(state + 3);
                if (PSVECMag(state) > magB)
                {
                    maxMag = PSVECMag(state);
                }
                else
                {
                    maxMag = PSVECMag(state + 3);
                }
                state[6] = maxMag;
            }
        }
    }
}
