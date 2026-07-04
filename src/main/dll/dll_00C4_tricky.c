#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/frustum.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "dolphin/mtx.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie/skeetla.h"
#include "main/dll/path_control_interface.h"
#include "main/mapEventTypes.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/audio/sfx_trigger_ids.h"

#define TRICKY_CONTROL_FLAG_BBOX_BLOCKS_SIGHT 0x00000008
#define TRICKY_CONTROL_FLAG_USE_SPECIAL_FLOOR_Y 0x08000000
#define TRICKY_CONTROL_FLAG_OFFSET_FLOOR_Y 0x20000000
#define TRICKY_CONTROL_FLAG_FLOOR_RESPONSE_MASK 0x28000002
#define TRICKY_SURFACE_FLAG_HAS_NEARBY_FLOOR 0x10
/* flags2DC status bits set by the floor-response pass (Tricky_applyFloorResponse /
 * Tricky_findNearbyFloorHeights) to record what floor correction ran this frame. */
#define TRICKY_STATE2DC_FLAG_FLOOR_OFFSET_APPLIED 0x08000000LL /* offset-floor-Y push applied */
#define TRICKY_STATE2DC_FLAG_FLOOR_SNAP_APPLIED 0x00100000LL   /* snap-to-floor velocity applied */
#define TRICKY_STATE2DC_FLAG_SPECIAL_FLOOR_FOUND 0x10000000LL  /* a nearby type-0xe special floor was found */
/* stateFlags movement-enable bits: each gates applying its matching per-frame
 * position delta (backstepDelta / verticalDelta / sidestepDelta) or the
 * rotate-toward-target interpolation in the per-frame update. */
#define TRICKY_STATE_FLAG_SIDESTEP 0x20        /* apply sidestepDelta lateral offset */
#define TRICKY_STATE_FLAG_BACKSTEP 0x40        /* apply backstepDelta offset */
#define TRICKY_STATE_FLAG_VERTICAL_MOVE 0x80   /* apply verticalDelta to localPosY */
#define TRICKY_STATE_FLAG_ROTATE 0x100         /* interpolate rotation toward unk5A target */
/* stateFlags flame-particle child bookkeeping: 0x800 marks the 7 flame children
 * as spawned; on teardown it is cleared and 0x1000 is set. */
#define TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE 0x800   /* 7 flame child objects are spawned */
#define TRICKY_STATE_FLAG_FLAME_CHILDREN_CLEANUP 0x1000 /* flame children torn down this cycle */
/* GameObject.objectFlags bit (distinct field from stateFlags above). */
#define TRICKY_OBJFLAG_PARENT_SLACK 0x1000
#define TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID 0x46406
#define TRICKY_HEIGHT_TRACK_GROUP 0x51
#define TRICKY_OBJGROUP 1
#define TRICKY_HEIGHT_TRACK_MODEL_SLOT 3
#define TRICKY_BBOX_HIT_SCRATCH_SIZE 84
/* ObjPlacement offsets read by the defeat handler to fire the baddie's
 * death gamebits. */
#define BADDIE_PLACEMENT_DEATH_GAMEBIT 0x18          /* s16: gamebit incremented on defeat */
#define BADDIE_PLACEMENT_CLEAR_ON_DEATH_GAMEBIT 0x1a /* s16: gamebit cleared on defeat */

typedef struct BaddieInstantiateWeaponPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
} BaddieInstantiateWeaponPlacement;

typedef struct TrickyDestroyState
{
    u8 pad0[0x700 - 0x0];
    s32 childObj; /* 0x700: child flame object handle (per-slot, walked by Tricky_destroy) */
    u8 pad704[0x708 - 0x704];
} TrickyDestroyState;

typedef struct TrickyInitFlags
{
    u8 initBit7 : 1;
    u8 bit6 : 1;
    u8 bit5 : 1;
    u8 bit4 : 1;
    u8 bit3 : 1;
    u8 bit2 : 1;
    u8 bit1 : 1;
    u8 bit0 : 1;
} TrickyInitFlags;

typedef struct TrickyStatusFlags58
{
    u8 bit7 : 1;
    u8 bit6 : 1;
    u8 heightTracking : 1;
    u8 bit4 : 1;
    u8 bit3 : 1;
    u8 bit2 : 1;
    u8 bit1 : 1;
    u8 bit0 : 1;
} TrickyStatusFlags58;

extern bool FUN_800067f0();
extern char FUN_80006a64();
extern u32 FUN_80006a68();
extern u32 FUN_80017690();
extern int randomGetRange(int lo, int hi);
extern void Sfx_RemoveLoopedObjectSound(int obj, int sfxId);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern int Sfx_PlayFromObject(int obj, int sfxId);
extern u32 Sfx_PlayFromObjectLimited(u32 obj, int sfxId, int limit);
extern int voxmaps_traceLine(void* from, void* to, int coordOut, u8* hit, int skipFirst);
extern void voxmaps_worldToGrid(Vec* world, void* grid);
extern void* ObjList_FindObjectById(int objId);
extern void* getTrickyObject(void);
extern int ObjGroup_FindNearestObject(int group, u32 obj, float* maxDistance);
extern void* ObjGroup_GetObjects();
extern u64 ObjGroup_RemoveObject();
extern void ObjGroup_AddObject(u32 obj, int group);
extern int Obj_GetActiveModel(int obj);
extern int Obj_GetPlayerObject(void);
extern u64 ObjLink_DetachChild();
extern u64 ObjLink_AttachChild();
extern void Obj_FreeObject(int obj);
extern int Obj_AllocObjectSetup();
extern int Obj_SetupObject(int setup, int b, int c, int d, int e);
extern u8 Obj_IsLoadingLocked(void);
extern u32 ObjPath_GetPointWorldPositionArray();
extern u32 ObjPath_GetPointWorldPosition();
extern u32 objAnimFn_80038f38();
extern u64 FUN_80039468();
extern void objAudioFn_800393f8(int param_1, void* param_2, int param_3, int param_4, int param_5,
                                int param_6);
extern f32 getXZDistance(f32* a, f32* b);
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern int objModelGetVecFn_800395d8(int obj, int target);
extern void freeAndNull(void* p);
extern void trickyVoxAllocFn_8004b5d4(void* out);
extern int FUN_800620e8();
extern u16 hitDetectFn_80065e50(f32 x, f32 y, f32 z, int obj, int* hits, int param_6, int param_7);
extern void objAudioFn_8006edcc(int obj, u16 param_4, int param_5, float* points, void* aux, f32 param_1, f32 param_2);
extern void objAudioFn_8006ef38(int obj, int joint, int pointCount, int pathPoints, int scratch, f32 scaleX,
                                f32 scaleY);
extern void doNothing_onTrickyFree(void);
extern void doNothing_onTrickyInit(void);
extern void walkgroupFindExitPointFn_800dc398(void);
extern int gameBitIncrement(int bit);
extern void objAnimFreeChildren(int a, int b, int* c);
extern void trickyImpress(int obj);
extern int trickyFoodFn_8014460c(int obj, int state);
extern void objAnimFn_8013a3f0(int obj, int animId, f32 blend, int flags);
extern int trickyFindNearestUsableBaddie(int p1, f32 maxRadius, int p2);
extern void fn_8013ADFC(int obj);
extern void Tricky_emitQueuedPathParticles(int obj, int state);
extern int trickyFn_8013b368();
extern void objSetAnimSpeedTo1(int obj);
extern f32 objFn_801948c0(int obj, int coord);
extern u32 FUN_80247eb8();
extern double SeekTwiceBeforeRead();
extern u64 FUN_8028683c();
extern u32 FUN_80286888();
extern int fn_80296240(int obj);
extern int fn_80296448(int obj);
extern void objParticleFn_80099d84(int obj, f32 scale, int type, f32 extraScale, int light);
extern int objBboxFn_800640cc(Vec* from, Vec* to, f32 radius, int mode, void* hit, int obj, int param_7,
                              int param_8, int param_9, int param_10);
extern float mathSinf(float x);
extern float mathCosf(float x);
extern u32 gTrickyVisibilityBitsInit[4];
extern char lbl_8031D2E8[];
extern char gTrickyPathPointCollision[];
extern char sInWaterMessage[];
extern char lbl_8031D478[];
extern u32 lbl_803E23C8;
extern char sSidekickCommandDebugTextBlock[];
extern u32 gTrickyHelperObject;
extern int gTrickyNearestObject;
extern u32 lbl_803DBC40;
extern u32 lbl_803DBC48;
extern f32 lbl_803DC074;
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern u16 lbl_803E23C0;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E8;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E24B8;
extern f32 lbl_803E2454;
extern f32 lbl_803E2458;
extern f32 lbl_803E247C;
extern f32 lbl_803E24F8;
extern f32 lbl_803E2524;
extern f32 lbl_803E253C;
extern f32 lbl_803E2540;
extern u32 lbl_803E2558;
extern u32 lbl_803E2560;
extern u32 lbl_803E2564;
extern u16 lbl_803E2568;
extern const f32 lbl_803E2574;
extern f32 lbl_803E2570;
extern f32 lbl_803E2578;
extern f32 lbl_803E257C;
extern f32 lbl_803E256C;
extern f32 lbl_803E2598;
extern f32 lbl_803E25A0;
extern f32 lbl_803E25A8;
extern f32 lbl_803E25AC;
extern const f32 enemySightRange;
extern const f32 lbl_803E25B4;
extern const f32 lbl_803E25B8;
extern f32 lbl_803E25BC;
extern f32 lbl_803E25C0;
extern f32 lbl_803E25C4;
extern f32 lbl_803E25C8;
extern f32 lbl_803E306C;
extern f32 lbl_803E30A0;
extern f32 lbl_803E30A4;
extern f32 lbl_803E30D0;
extern f32 lbl_803E3138;
extern f32 lbl_803E317C;
extern f32 lbl_803E31C4;
extern f32 lbl_803E3234;
extern f32 lbl_803E3244;

void FUN_80144e40(int obj, int state)
{
    float waterHeight;
    int scratch;
    bool cond;
    u32 swimCmdEnabled;
    int hit[3];

    ((TrickyState*)state)->unk720 = ((TrickyState*)state)->unk720 - lbl_803DC074;
    if (((TrickyState*)state)->unk720 < lbl_803E306C)
    {
        ((TrickyState*)state)->unk720 = lbl_803E306C;
    }
    scratch = ObjHits_GetPriorityHit(obj, hit, 0x0, 0x0);
    if (((scratch != 0) && (*(int*)(hit[0] + 0xc4) != 0)) &&
        (*(short*)(*(int*)(hit[0] + 0xc4) + 0x44) == 1))
    {
        waterHeight = ((TrickyState*)state)->unk720;
        if (lbl_803E306C < waterHeight)
        {
            ((TrickyState*)state)->unk720 = waterHeight + lbl_803E30D0;
            if (*(char*)(state + 10) != '\v')
            {
                if ((((TrickyState*)state)->stateFlags & 0x10) == 0)
                {
                    scratch = *(int*)&((GameObject*)obj)->extra;
                    if ((((*(u8*)(scratch + 0x58) >> 6 & 1) == 0) &&
                            ((0x2f < ((GameObject*)obj)->anim.currentMove || (((GameObject*)obj)->anim.
                                currentMove < 0x29)))) &&
                        (cond = FUN_800067f0(obj, 0x10), !cond))
                    {
                        FUN_80039468(obj, scratch + 0x3a8, 0x350, 0x500, 0xffffffff, 0);
                    }
                    *(u8*)(state + 10) = 10;
                    ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 0x10;
                }
                else if (((TrickyState*)state)->unk720 <= lbl_803E31C4)
                {
                    scratch = *(int*)&((GameObject*)obj)->extra;
                    if ((((*(u8*)(scratch + 0x58) >> 6 & 1) == 0) &&
                            ((0x2f < ((GameObject*)obj)->anim.currentMove || (((GameObject*)obj)->anim.
                                currentMove < 0x29)))) &&
                        (cond = FUN_800067f0(obj, 0x10), !cond))
                    {
                        FUN_80039468(obj, scratch + 0x3a8, 0x350, 0x500, 0xffffffff, 0);
                    }
                }
                else
                {
                    ((TrickyState*)state)->unk720 = ((TrickyState*)state)->unk720 * lbl_803E3138;
                    swimCmdEnabled = FUN_80017690(0x245);
                    if (swimCmdEnabled != 0)
                    {
                        if (lbl_803E306C == ((TrickyState*)state)->waterLevel)
                        {
                            cond = false;
                        }
                        else if (lbl_803E30A0 == ((TrickyState*)state)->eventTime)
                        {
                            cond = true;
                        }
                        else if (((TrickyState*)state)->currentTime - ((TrickyState*)state)->eventTime <= lbl_803E30A4)
                        {
                            cond = false;
                        }
                        else
                        {
                            cond = true;
                        }
                        if (!cond)
                        {
                            *(u8*)(state + 10) = 0xb;
                            return;
                        }
                    }
                    scratch = *(int*)&((GameObject*)obj)->extra;
                    if (((*(u8*)(scratch + 0x58) >> 6 & 1) == 0) &&
                        (((0x2f < ((GameObject*)obj)->anim.currentMove || (((GameObject*)obj)->anim.currentMove
                                < 0x29)) &&
                            (cond = FUN_800067f0(obj, 0x10), !cond))))
                    {
                        FUN_80039468(obj, scratch + 0x3a8, 0x350, 0x500, 0xffffffff, 0);
                    }
                }
            }
        }
        else
        {
            ((TrickyState*)state)->unk720 = waterHeight + lbl_803E317C;
            scratch = *(int*)&((GameObject*)obj)->extra;
            if ((((*(u8*)(scratch + 0x58) >> 6 & 1) == 0) &&
                    ((0x2f < ((GameObject*)obj)->anim.currentMove || (((GameObject*)obj)->anim.currentMove <
                        0x29)))) &&
                (cond = FUN_800067f0(obj, 0x10), !cond))
            {
                FUN_80039468(obj, scratch + 0x3a8, 0x34f, 0x500, 0xffffffff, 0);
            }
        }
    }
    return;
}

typedef struct
{
    u8 bit7 : 1;
    u8 bit6 : 1;
    u8 bit5 : 1;
    u8 rest : 5;
} TrickyByteFlags;

extern void Sfx_StopObjectChannel(int obj, int channel);
extern int Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern int ObjModel_ClearBlendChannels(int model);
extern void characterDoEyeAnims(int obj, void* p);
extern int fn_80138D7C(int obj, int state);
extern void Tricky_updateBlendChannelWeight(int obj, int state);

int tricky_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int state;
    int i;
    int slot;
    int j;
    int k;
    u8* p;
    int setup;
    bool playing;
    u8 blockFlags[120];

    state = *(int*)&((GameObject*)obj)->extra;
    if ((((TrickyState*)state)->stateFlags & 0x200) == 0)
    {
        ObjHits_DisableObject(obj);
        Sfx_StopObjectChannel(obj, 0x7f);
        if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE) != 0)
        {
            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & ~(u64)TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE;
            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | TRICKY_STATE_FLAG_FLAME_CHILDREN_CLEANUP;
            for (k = 0, slot = state; k < 7; slot = slot + 4, k = k + 1)
            {
                objSetAnimSpeedTo1(*(int*)(slot + 0x700));
            }
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
            slot = *(int*)&((GameObject*)obj)->extra;
            if ((((TrickyByteFlags*)(slot + 0x58))->bit6 == 0) &&
                (((((GameObject*)obj)->anim.currentMove >= 0x30 || (((GameObject*)obj)->anim.currentMove < 0x29)) &&
                    (playing = Sfx_IsPlayingFromObjectChannel(obj, 0x10), !playing))))
            {
                objAudioFn_800393f8(obj, (void*)(slot + 0x3a8), 0x29d, 0, 0xffffffff, 0);
            }
        }
        Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trwhin1);
        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 0x200;
        if ((animUpdate->hitVolumePair & 3) == 0)
        {
            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 0x4000;
        }
        if (((TrickyByteFlags*)&((TrickyState*)state)->unk82E)->bit5 == 0)
        {
            ObjModel_ClearBlendChannels(Obj_GetActiveModel(obj));
            ((TrickyByteFlags*)&((TrickyState*)state)->unk82E)->bit6 = 0;
        }
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE) != 0)
            {
                ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & ~(u64)TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE;
                ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | TRICKY_STATE_FLAG_FLAME_CHILDREN_CLEANUP;
                for (j = 0, slot = state; j < 7; slot = slot + 4, j = j + 1)
                {
                    objSetAnimSpeedTo1(*(int*)(slot + 0x700));
                }
                Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
                slot = *(int*)&((GameObject*)obj)->extra;
                if ((((TrickyByteFlags*)(slot + 0x58))->bit6 == 0) &&
                    (((((GameObject*)obj)->anim.currentMove >= 0x30 || (((GameObject*)obj)->anim.currentMove < 0x29)) &&
                        (playing = Sfx_IsPlayingFromObjectChannel(obj, 0x10), !playing))))
                {
                    objAudioFn_800393f8(obj, (void*)(slot + 0x3a8), 0x29d, 0, 0xffffffff, 0);
                }
            }
            else if (Obj_IsLoadingLocked())
            {
                ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE;
                for (k = 0, p = (u8*)state; k < 7; p += 4, k = k + 1)
                {
                    setup = Obj_AllocObjectSetup(0x24, 0x4f0);
                    *(u8*)(setup + 4) = 2;
                    *(u8*)(setup + 5) = 1;
                    *(s16*)(setup + 0x1a) = k;
                    *(int*)(p + 0x700) = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                                            *(int*)&((GameObject*)obj)->anim.parent);
                }
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound(obj, SFXTRIG_trpopn_c);
            }
            break;
        case 2:
            GameBit_Set(0x186, 1);
            if ((GameBit_Get(0x186) != 0 && *(void**)&((TrickyState*)state)->unk7CC == NULL) && Obj_IsLoadingLocked())
            {
                mapBlockFn_80059c2c(blockFlags);
                if (blockFlags[0xd] != 0)
                {
                    setup = Obj_AllocObjectSetup(0x20, 0x244);
                }
                else
                {
                    setup = Obj_AllocObjectSetup(0x20, 0x254);
                }
                *(int*)&((TrickyState*)state)->unk7CC = Obj_SetupObject(
                    setup, 4, -1, -1, *(int*)&((GameObject*)obj)->anim.parent);
                ObjLink_AttachChild(obj, *(int*)&((TrickyState*)state)->unk7CC, 3);
            }
            break;
        case 3:
            **(u8**)&((TrickyState*)state)->progressPtr = ((TrickyState*)state)->unk82D;
            break;
        case 0x2b:
            ((GameObject*)obj)->anim.modelState->flags &= ~(u64)OBJ_MODEL_STATE_SHADOW_VISIBLE;
            break;
        case 0x2c:
            ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
            break;
        }
    }
    objAnimFreeChildren(obj, state, (int*)(state + 0x7a8)); /* raw: arrow form shifts bytes */
    objAnimFreeChildren(obj, state, (int*)(state + 0x7b0)); /* raw: arrow form shifts bytes */
    objAnimFreeChildren(obj, state, (int*)&((TrickyState*)state)->child);
    fn_80138D7C(obj, state);
    Tricky_updateBlendChannelWeight(obj, state);
    objAudioFn_8006ef38(obj, (int)&animUpdate->animEvents, 1, state + 0x7d8, state + 0xf8, lbl_803E23E8, *(f32*)&lbl_803E23E8);
    if ((((TrickyState*)state)->stateFlags & 1) != 0)
    {
        animUpdate->hitVolumePair &= ~0x40;
        characterDoEyeAnims(obj, (void*)(state + 0x378));
        return (*gObjectTriggerInterface)->func20((void*)obj, (u8*)animUpdate, 1, 0xf, 0x1e, 0, 0);
    }
    return 0;
}

void sideCommandEnable(int obj, int targetObj, int commandKind, int commandType)
{
    int commandCount;
    int commandEntry;
    int commandIndex;
    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    if (((TrickyState*)state)->unk798 == 10)
    {
        trickyReportError(sSidekickCommandDebugTextBlock);
        return;
    }
    ((TrickyState*)state)->unk0B = (u8)(((TrickyState*)state)->unk0B | (1 << commandType));
    commandIndex = 0;
    commandEntry = state;
    for (commandCount = (u32)((TrickyState*)state)->unk798; 0 < commandCount;
         commandCount = commandCount - 1)
    {
        if (*(u32*)(commandEntry + 0x748) == targetObj)
        {
            *(u8*)((state + 0x74e) + commandIndex * 8) = 3;
            return;
        }
        commandEntry = commandEntry + 8;
        commandIndex = commandIndex + 1;
    }
    *(int*)((state + 0x748) + (u32)((TrickyState*)state)->unk798 * 8) = targetObj;
    *(char*)((state + 0x74c) + (u32)((TrickyState*)state)->unk798 * 8) = commandKind;
    *(char*)((state + 0x74d) + (u32)((TrickyState*)state)->unk798 * 8) = commandType;
    *(u8*)((state + 0x74e) + (u32)((TrickyState*)state)->unk798 * 8) = 3;
    ((TrickyState*)state)->unk798++;
    return;
}

typedef struct PromptSlotByte
{
    u8 slotA : 2;
    u8 slotB : 2;
    u8 unk4 : 4;
} PromptSlotByte;

int Tricky_updateSideCommandPrompts(int obj)
{
    int objVal;
    int state;
    u32 commandMask;
    char cmdByte;
    u16 promptId;
    u8 cond;
    u8 promptA;
    u8 promptB;
    u8 promptC;
    u32 bitVal;
    int ref;
    int refB;
    int refC;
    u16* setup;
    u32 spawnedObj;
    u8 i;
    char flagsB[4];
    char flagsA[4];
    u32 promptTable[4];

    objVal = obj;
    state = *(int*)&((GameObject*)objVal)->extra;
    cond = false;
    promptA = false;
    promptB = false;
    promptC = false;
    promptTable[0] = lbl_803E23C8;
    bitVal = GameBit_Get(0x4e4);
    if (bitVal != 0)
    {
        if ((((TrickyState*)state)->stateFlags & 0x10) != 0)
        {
            ((TrickyState*)state)->unk0B = 0;
        }
        commandMask = ((TrickyState*)state)->unk0B | 9;
        if (((((TrickyState*)state)->unk08 == 8) || (((TrickyState*)state)->unk08 == 0xd)) ||
            ((((TrickyState*)state)->unk08 == 0xe && (((TrickyState*)state)->substate == 1))))
        {
            commandMask |= 0x10;
            promptA = true;
        }
        else
        {
            ref = trickyFindNearestUsableBaddie(((TrickyState*)state)->playerObj, lbl_803E2524, 1);
            if ((void*)ref != NULL)
            {
                promptA = true;
                promptC = true;
            }
        }
        if (((TrickyState*)state)->unk0B != 0)
        {
            for (i = 0; i < ((TrickyState*)state)->unk798; i++)
            {
                ref = state + i * 8;
                cmdByte = *(char*)(ref + 0x74c);
                if (cmdByte == '\0')
                {
                    if (*(short*)(*(int*)(ref + 0x748) + 0x46) == 0x6a)
                    {
                        promptB = true;
                    }
                    promptA = true;
                }
                else if (cmdByte == '\x01')
                {
                    cond = true;
                }
            }
        }
        if (((((TrickyState*)state)->stateFlags & 0x10) == 0) && (bitVal = GameBit_Get(0x3f8), bitVal != 0))
        {
            ref = Obj_GetPlayerObject();
            ref = fn_80296240(ref);
            if ((ref != 0) && (bitVal = GameBit_Get(0xd00), bitVal == 0))
            {
                if (fn_80296448(((TrickyState*)state)->playerObj) == 0)
                {
                    commandMask |= 0x20;
                }
            }
        }
        if (GameBit_Get(0xdd) == 0)
        {
            commandMask &= ~1;
        }
        if (GameBit_Get(0x9e) == 0)
        {
            commandMask &= ~4;
        }
        if (GameBit_Get(0x245) == 0)
        {
            commandMask &= ~0x10;
        }
        ((TrickyState*)state)->unk0B = 0;
        if ((cond) && ((((TrickyState*)state)->stateFlags & 0x200) == 0))
        {
            *(float*)(state + 0x7b4) = lbl_803E24F8;
            if ((((TrickyState*)state)->unk7B0 == NULL) && (Obj_IsLoadingLocked() != 0))
            {
                bitVal = randomGetRange(0, 1);
                promptId = *(u16*)((int)promptTable + bitVal * 2);
                ref = *(int*)&((GameObject*)objVal)->extra;
                if (((*(u8*)(ref + 0x58) >> 6 & 1) == 0u) &&
                    (((((GameObject*)objVal)->anim.currentMove >= 0x30 || (((GameObject*)objVal)->anim.currentMove < 0x29)) &&
                        !Sfx_IsPlayingFromObjectChannel(objVal, 0x10))))
                {
                    objAudioFn_800393f8(objVal, (void*)(ref + 0x3a8), promptId, 0x500, 0xffffffff, 0);
                }
                setup = (u16*)Obj_AllocObjectSetup(0x20, 0x17c);
                flagsB[0] = -1;
                flagsB[1] = -1;
                flagsB[2] = -1;
                if (((TrickyState*)state)->unk7A8 != NULL)
                {
                    flagsB[*(u8*)(state + 0x7bc) >> 6 & 3] = '\x01';
                }
                if (((TrickyState*)state)->unk7B0 != NULL)
                {
                    flagsB[*(u8*)(state + 0x7bc) >> 4 & 3] = '\x01';
                }
                if (((TrickyState*)state)->child != NULL)
                {
                    flagsB[*(u8*)(state + 0x7bc) >> 2 & 3] = '\x01';
                }
                if (flagsB[0] == -1)
                {
                    bitVal = 0;
                }
                else if (flagsB[1] == -1)
                {
                    bitVal = 1;
                }
                else if (flagsB[2] == -1)
                {
                    bitVal = 2;
                }
                else if (flagsB[3] == -1)
                {
                    bitVal = 3;
                }
                else
                {
                    bitVal = 0xffffffff;
                }
                ((PromptSlotByte*)(state + 0x7bc))->slotB = bitVal;
                spawnedObj = Obj_SetupObject((int)setup, 4, -1, 0xffffffff, *(int*)&((GameObject*)objVal)->anim.parent);
                *(u32*)(state + 0x7b0) = spawnedObj; /* raw: arrow form shifts bytes */
                ObjLink_AttachChild(objVal, (int)((TrickyState*)state)->unk7B0, *(u8*)(state + 0x7bc) >> 4 & 3);
            }
        }
        else if (((TrickyState*)state)->unk7B0 != NULL)
        {
            *(float*)(state + 0x7b4) = *(float*)(state + 0x7b4) - timeDelta;
            if ((double)*(float*)(state + 0x7b4) <= (double)lbl_803E23DC)
            {
                objAnimFreeChildren(objVal, state, (int*)(state + 0x7b0)); /* raw: arrow form shifts bytes */
            }
        }
        if ((promptA) && ((((TrickyState*)state)->stateFlags & 0x200) == 0))
        {
            *(float*)(state + 0x7ac) = lbl_803E24F8;
            if ((((TrickyState*)state)->unk7A8 == NULL) && (Obj_IsLoadingLocked() != 0))
            {
                if (randomGetRange(0, 3) == 0)
                {
                    if (promptB)
                    {
                        refB = *(int*)&((GameObject*)objVal)->extra;
                        if (((*(u8*)(refB + 0x58) >> 6 & 1) == 0u) &&
                            (((((GameObject*)objVal)->anim.currentMove >= 0x30 || (((GameObject*)objVal)->anim.currentMove < 0x29)) &&
                                !Sfx_IsPlayingFromObjectChannel(objVal, 0x10))))
                        {
                            objAudioFn_800393f8(objVal, (void*)(refB + 0x3a8), 0x359, 0x500, 0xffffffff, 0);
                        }
                    }
                    else if ((((promptC) &&
                                (refC = *(int*)&((GameObject*)objVal)->extra, (*(u8*)(refC + 0x58) >> 6 & 1) == 0u)) &&
                            ((((GameObject*)objVal)->anim.currentMove >= 0x30 || (((GameObject*)objVal)->anim.currentMove < 0x29)))) &&
                        !Sfx_IsPlayingFromObjectChannel(objVal, 0x10))
                    {
                        objAudioFn_800393f8(objVal, (void*)(refC + 0x3a8), 0x358, 0x500, 0xffffffff, 0);
                    }
                }
                setup = (u16*)Obj_AllocObjectSetup(0x20, 0x175);
                flagsA[0] = -1;
                flagsA[1] = -1;
                flagsA[2] = -1;
                if (((TrickyState*)state)->unk7A8 != NULL)
                {
                    flagsA[*(u8*)(state + 0x7bc) >> 6 & 3] = '\x01';
                }
                if (((TrickyState*)state)->unk7B0 != NULL)
                {
                    flagsA[*(u8*)(state + 0x7bc) >> 4 & 3] = '\x01';
                }
                if (((TrickyState*)state)->child != NULL)
                {
                    flagsA[*(u8*)(state + 0x7bc) >> 2 & 3] = '\x01';
                }
                if (flagsA[0] == -1)
                {
                    bitVal = 0;
                }
                else if (flagsA[1] == -1)
                {
                    bitVal = 1;
                }
                else if (flagsA[2] == -1)
                {
                    bitVal = 2;
                }
                else if (flagsA[3] == -1)
                {
                    bitVal = 3;
                }
                else
                {
                    bitVal = 0xffffffff;
                }
                ((PromptSlotByte*)(state + 0x7bc))->slotA = bitVal;
                spawnedObj = Obj_SetupObject((int)setup, 4, -1, 0xffffffff, *(int*)&((GameObject*)objVal)->anim.parent);
                *(u32*)(state + 0x7a8) = spawnedObj; /* raw: arrow form shifts bytes */
                ObjLink_AttachChild(objVal, (int)((TrickyState*)state)->unk7A8, *(u8*)(state + 0x7bc) >> 6 & 3);
            }
        }
        else if (((TrickyState*)state)->unk7A8 != NULL)
        {
            *(float*)(state + 0x7ac) = *(float*)(state + 0x7ac) - timeDelta;
            if ((double)*(float*)(state + 0x7ac) <= (double)lbl_803E23DC)
            {
                objAnimFreeChildren(objVal, state, (int*)(state + 0x7a8)); /* raw: arrow form shifts bytes */
            }
        }
        return commandMask;
    }
    return -1;
}

void Tricky_destroy(int obj, int shouldKeepFlameChildren)
{
    int i;
    int childSlot;
    bool playing;
    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[0]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[1]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[2]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[3]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[4]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[5]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[6]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[7]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[8]);
    ObjGroup_RemoveObject(obj, TRICKY_OBJGROUP);
    (*gExpgfxInterface)->freeSource((u32)obj);
    if ((shouldKeepFlameChildren == 0) && ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE) != 0))
    {
        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & ~(u64)TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE;
        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | TRICKY_STATE_FLAG_FLAME_CHILDREN_CLEANUP;
        i = 0;
        childSlot = state;
        do
        {
            objSetAnimSpeedTo1(((TrickyDestroyState*)childSlot)->childObj);
            childSlot = childSlot + 4;
            i = i + 1;
        }
        while (i < 7);
        Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
        childSlot = *(int*)&((GameObject*)obj)->extra;
        if (((*(u8*)(childSlot + 0x58) >> 6 & 1) == 0u) &&
            (((((GameObject*)obj)->anim.currentMove >= 0x30 || (((GameObject*)obj)->anim.currentMove < 0x29)) &&
                (playing = Sfx_IsPlayingFromObjectChannel(obj, 0x10), !playing))))
        {
            objAudioFn_800393f8(obj, (void*)(childSlot + 0x3a8), 0x29d, 0, 0xffffffff, 0);
        }
    }
    doNothing_onTrickyFree();
    objAnimFreeChildren(obj, state, (int*)(state + 0x7a8)); /* raw: arrow form shifts bytes */
    objAnimFreeChildren(obj, state, (int*)(state + 0x7b0)); /* raw: arrow form shifts bytes */
    objAnimFreeChildren(obj, state, (int*)&((TrickyState*)state)->child);
    if (*(void**)&((TrickyState*)state)->unk7CC != NULL)
    {
        ObjLink_DetachChild(obj, *(int*)&((TrickyState*)state)->unk7CC);
        Obj_FreeObject(*(int*)&((TrickyState*)state)->unk7CC);
    }
    if (((((TrickyState*)state)->statusFlags >> 7 & 1) != 0u) && (gTrickyHelperObject != 0))
    {
        Obj_FreeObject(gTrickyHelperObject);
        gTrickyHelperObject = 0;
    }
    return;
}

/* Tricky_update: 8672b - Tricky sidekick command state machine and per-frame update. */
typedef struct
{
    u8 slotA : 2;
    u8 slotB : 2;
    u8 slotC : 2;
    u8 slotD : 2;
} TrickySlotBits;

typedef struct
{
    void* pad[9];
    void (*handlers[1])(int obj, int state);
} TrickyHandlerTable;

typedef struct
{
    int a;
    int b;
    int c;
    int d;
    int e;
} TrickyCmdQuery;

typedef struct
{
    u16 a;
    u16 b;
} TrickySfxPair;

extern int gTrickyCmdQueryInit[];
extern TrickySfxPair lbl_803E23C4;
extern f32 lbl_803E2408;
extern f32 lbl_803E23EC;
extern f32 lbl_803E24C8;
extern f32 lbl_803E24D8;
extern f32 lbl_803E2538;
extern f32 lbl_803E2544;
extern f32 lbl_803E2548;
extern f32 lbl_803E254C;
extern f32 lbl_803E2550;
extern int trickySelectQueuedCommandTarget(int state, int type);
extern int trickyFoodFn_8013db3c(int obj, int state);
extern void memmove(void* dst, void* src, int n);
extern void fn_801B17F4(void);
extern void fn_801B6D40(void);
extern void fn_801FD4A8(void);
extern void fn_801B0784(void);
extern void drchimmey_countdownCallback(void);
extern void fn_801DA9CC(void);
extern void wcbeacon_aButtonCallback(void);
extern void fn_8003A168(int obj, void* p);
extern void fn_8003B228(int obj, void* p);

#define TRICKY_RESET_COMMAND(state) \
  *(u8 *)((state) + 8) = 1; \
  *(u8 *)((state) + 0xa) = 0; \
  z = lbl_803E23DC; \
  *(f32 *)((state) + 0x71c) = z; \
  *(f32 *)((state) + 0x720) = z; \
  *(u32 *)((state) + 0x54) = *(u32 *)((state) + 0x54) & ~0x10LL; \
  *(u32 *)((state) + 0x54) = *(u32 *)((state) + 0x54) & ~0x10000LL; \
  *(u32 *)((state) + 0x54) = *(u32 *)((state) + 0x54) & ~0x20000LL; \
  *(u32 *)((state) + 0x54) = *(u32 *)((state) + 0x54) & ~0x40000LL; \
  *(u8 *)((state) + 0xd) = 0xFF

#define TRICKY_VOICE(obj, st, sfx, vol) \
  st = *(int *)((obj) + 0xb8); \
  if ((((TrickyByteFlags *)(st + 0x58))->bit6 == 0) && \
     (((*(short *)((obj) + 0xa0) >= 0x30 || (*(short *)((obj) + 0xa0) < 0x29)) && \
      (playing = Sfx_IsPlayingFromObjectChannel((obj), 0x10), !playing)))) { \
    objAudioFn_800393f8((obj), (void *)(st + 0x3a8), (sfx), (vol), 0xffffffff, 0); \
  }

#define TRICKY_SPAWN_BUBBLE(obj, state) \
  if (*(void **)((state) + 0x7b8) == NULL) { \
    int setup_; \
    s8 used_[4]; \
    int slot_; \
    setup_ = Obj_AllocObjectSetup(0x20, 0x17b); \
    used_[0] = -1; \
    used_[1] = -1; \
    used_[2] = -1; \
    if (*(void **)((state) + 0x7a8) != NULL) { \
      used_[((TrickySlotBits *)((state) + 0x7bc))->slotA] = 1; \
    } \
    if (*(void **)((state) + 0x7b0) != NULL) { \
      used_[((TrickySlotBits *)((state) + 0x7bc))->slotB] = 1; \
    } \
    if (*(void **)((state) + 0x7b8) != NULL) { \
      used_[((TrickySlotBits *)((state) + 0x7bc))->slotC] = 1; \
    } \
    if (used_[0] == -1) { slot_ = 0; } \
    else if (used_[1] == -1) { slot_ = 1; } \
    else if (used_[2] == -1) { slot_ = 2; } \
    else if (used_[3] == -1) { slot_ = 3; } \
    else { slot_ = -1; } \
    ((TrickySlotBits *)((state) + 0x7bc))->slotC = slot_; \
    *(int *)((state) + 0x7b8) = Obj_SetupObject(setup_, 4, -1, -1, *(int *)((obj) + 0x30)); \
    ObjLink_AttachChild((obj), *(int *)((state) + 0x7b8), ((TrickySlotBits *)((state) + 0x7bc))->slotC); \
    z = lbl_803E23DC; \
    *(f32 *)((state) + 0x7c0) = z; \
    *(f32 *)((state) + 0x7c4) = z; \
    *(f32 *)((state) + 0x7c8) = z; \
  }

void Tricky_update(int obj)
{
    char* base;
    void (**handlerBase)(int obj, int state);
    int state;
    int found;
    int p;
    int cmd;
    int st;
    TrickyState* stState;
    bool playing;
    int i;
    int setup;
    int count;
    u32 f;
    int diff;
    int step;
    int played;
    int talking;
    int sfx2;
    u16 sfxId;
    u32 target;
    f32 z;
    s8 flagsByte;
    u8 blockFlags[120];
    TrickyCmdQuery cmdQuery;
    TrickySfxPair pair;

    base = lbl_8031D2E8;
    state = *(int*)&((GameObject*)obj)->extra;
    found = 0;
    cmdQuery = *(TrickyCmdQuery*)gTrickyCmdQueryInit;
    pair = lbl_803E23C4;
    walkgroupFindExitPointFn_800dc398();
    if (GameBit_Get(0x186) != 0 && *(void**)&((TrickyState*)state)->unk7CC == NULL && Obj_IsLoadingLocked())
    {
        mapBlockFn_80059c2c(blockFlags);
        if (blockFlags[0xd] != 0)
        {
            setup = Obj_AllocObjectSetup(0x20, 0x244);
        }
        else
        {
            setup = Obj_AllocObjectSetup(0x20, 0x254);
        }
        *(int*)&((TrickyState*)state)->unk7CC = Obj_SetupObject(setup, 4, -1, -1,
                                                                *(int*)&((GameObject*)obj)->anim.parent);
        ObjLink_AttachChild(obj, *(int*)&((TrickyState*)state)->unk7CC, 3);
    }
    if ((((TrickyState*)state)->stateFlags & 0x40000000) != 0)
    {
        p = *(int*)state;
        if (*(u8*)p == *(u8*)(p + 1))
        {
            TRICKY_VOICE(obj, st, 0x364, 0x500);
        }
        else
        {
            TRICKY_VOICE(obj, st, 0x363, 0x500);
        }
        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & ~0x40000000LL;
    }
    flagsByte = ((TrickyState*)state)->unk358;
    trickyDebugPrint(base + 0x894, flagsByte & 1, flagsByte & 2, flagsByte & 4, flagsByte & 8,
                     flagsByte & 0x10, flagsByte & 0x20, flagsByte & 0x40, flagsByte & 0x80);
    p = *(int*)state;
    trickyDebugPrint(base + 0x8b4, *(u8*)p, *(u8*)(p + 1));
    if ((((TrickyState*)state)->stateFlags & 0x200) != 0)
    {
        ObjHits_EnableObject(obj);
        if ((((TrickyState*)state)->stateFlags & 0x4000) == 0)
        {
            TRICKY_RESET_COMMAND(state);
            ((TrickyState*)state)->followPhase = 0;
            ((TrickyState*)state)->prevSpeed = z;
            ((TrickyState*)state)->speed = z;
            ((TrickyState*)state)->homePosX = ((GameObject*)obj)->anim.worldPosX;
            ((TrickyState*)state)->homePosY = ((GameObject*)obj)->anim.worldPosY;
            ((TrickyState*)state)->homePosZ = ((GameObject*)obj)->anim.worldPosZ;
            (*gPathControlInterface)->attachObject((void*)obj,
                                                   &((TrickyState*)state)->pathControlFlags);
            if (((GameObject*)obj)->anim.currentMove == 8 || ((GameObject*)obj)->anim.currentMove == 7)
            {
                ((TrickyState*)state)->waterLevel = lbl_803E2414;
                ((TrickyState*)state)->eventTime = lbl_803E2544;
            }
            else
            {
                ((TrickyState*)state)->waterLevel = lbl_803E23DC;
            }
        }
        *(s32*)&((TrickyState*)state)->stateFlags &= ~0x4201;
        if (((TrickyByteFlags*)&((TrickyState*)state)->unk82E)->bit5 != 0)
        {
            ((TrickyByteFlags*)&((TrickyState*)state)->unk82E)->bit5 = 0;
        }
        else
        {
            ((TrickyByteFlags*)&((TrickyState*)state)->unk82E)->bit7 = 1;
        }
    }
    if (*(void**)&((TrickyState*)state)->followObj != NULL &&
        (((GameObject*)((TrickyState*)state)->followObj)->objectFlags & OBJECT_OBJFLAG_FREED) != 0)
    {
        if ((((TrickyState*)state)->stateFlags & 0x10) != 0)
        {
            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & ~0x10LL;
            ((TrickyState*)state)->unk374 = 2;
            (*gPathControlInterface)->attachObject((void*)obj,
                                                   &((TrickyState*)state)->pathControlFlags);
            ((GameObject*)obj)->anim.localPosX = ((TrickyState*)state)->homePosX;
            ((GameObject*)obj)->anim.localPosY = ((TrickyState*)state)->homePosY;
            ((GameObject*)obj)->anim.localPosZ = ((TrickyState*)state)->homePosZ;
            ((GameObject*)obj)->anim.worldPosX = ((TrickyState*)state)->homePosX;
            ((GameObject*)obj)->anim.worldPosY = ((TrickyState*)state)->homePosY;
            ((GameObject*)obj)->anim.worldPosZ = ((TrickyState*)state)->homePosZ;
            ObjHits_SyncObjectPosition(obj);
            i = 0;
            ((TrickyState*)state)->followPhase = i;
            z = lbl_803E23DC;
            ((TrickyState*)state)->prevSpeed = z;
            ((TrickyState*)state)->speed = z;
            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 0x80000LL;
            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & ~(u64)0x2000;
            if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE) != 0)
            {
                ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & ~(u64)TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE;
                ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | TRICKY_STATE_FLAG_FLAME_CHILDREN_CLEANUP;
                p = state;
                do
                {
                    objSetAnimSpeedTo1(*(int*)(p + 0x700));
                    p = p + 4;
                    i = i + 1;
                }
                while (i < 7);
                Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
                TRICKY_VOICE(obj, st, 0x29d, 0);
            }
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trwhin1);
        }
        TRICKY_RESET_COMMAND(state);
        *(int*)&((TrickyState*)state)->followObj = 0;
    }
    if ((((TrickyState*)state)->stateFlags & 0x10) != 0 &&
        (*gGameUIInterface)->isEventReady(0xc1) != 0)
    {
        cmd = 0;
    }
    else
    {
        cmd = (*gGameUIInterface)->isOneOfItemsBeingUsed((s32*)&cmdQuery, 5);
    }
    p = state;
    count = ((TrickyState*)state)->unk798;
    for (i = 0; i < count; i++)
    {
        if (*(s8*)(p + 0x74d) == cmd)
        {
            found = 1;
            break;
        }
        p = p + 8;
    }
    if ((((TrickyState*)state)->stateFlags & 0x10) == 0 && trickyFoodFn_8013db3c(obj, state) == 2)
    {
        ((TrickyState*)state)->unk08 = 0x11;
    }
    else if (((TrickyState*)state)->unk08 == 8 && cmd == 4)
    {
        *(u8*)&((TrickyState*)state)->unk734 = *(u8*)&((TrickyState*)state)->unk734 ^ 1;
    }
    else if (((TrickyState*)state)->unk08 == 0xd && cmd == 4 && found == 0)
    {
        *(int*)&((TrickyState*)state)->unk728 = 1;
    }
    else if (((TrickyState*)state)->unk08 == 0xe && cmd == 4)
    {
        *(int*)&((TrickyState*)state)->unk728 = 1;
    }
    else if (cmd == 0)
    {
        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 0x30002LL;
    }
    else
    {
        f = ((TrickyState*)state)->stateFlags;
        if ((f & 0x10) == 0)
        {
            switch (cmd)
            {
            case 1:
                ((TrickyState*)state)->unkD = 1;
                trickySelectQueuedCommandTarget(state, 1);
                TRICKY_VOICE(obj, st, 0x13c, 0);
                switch (((GameObject*)((TrickyState*)state)->followObj)->anim.seqId)
                {
                case 0x1ca:
                    if (**(u8**)state < 4)
                    {
                        if (Obj_IsLoadingLocked())
                        {
                            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 4;
                            TRICKY_RESET_COMMAND(state);
                            TRICKY_SPAWN_BUBBLE(obj, state);
                        }
                    }
                    else
                    {
                        ((TrickyState*)state)->unk08 = 2;
                    }
                    break;
                case 0x160:
                    if (**(u8**)state < 4)
                    {
                        if (Obj_IsLoadingLocked())
                        {
                            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 4;
                            TRICKY_RESET_COMMAND(state);
                            TRICKY_SPAWN_BUBBLE(obj, state);
                        }
                    }
                    else
                    {
                        ((TrickyState*)state)->unk08 = 3;
                    }
                    break;
                case 0x6a:
                case 0x193:
                case 0x3fb:
                case 0x658:
                    ((TrickyState*)state)->unk08 = 9;
                    break;
                case 0x195:
                    if (**(u8**)state < 2)
                    {
                        if (Obj_IsLoadingLocked())
                        {
                            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 4;
                            TRICKY_RESET_COMMAND(state);
                            TRICKY_SPAWN_BUBBLE(obj, state);
                        }
                    }
                    else
                    {
                        ((TrickyState*)state)->unk08 = 0x10;
                    }
                    break;
                case 0x352:
                    if (**(u8**)state < 4)
                    {
                        if (Obj_IsLoadingLocked())
                        {
                            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 4;
                            TRICKY_RESET_COMMAND(state);
                            TRICKY_SPAWN_BUBBLE(obj, state);
                        }
                    }
                    else
                    {
                        ((TrickyState*)state)->unk08 = 2;
                    }
                    break;
                case 0x358:
                    ((TrickyState*)state)->unk08 = 0xe;
                    break;
                default:
                    TRICKY_RESET_COMMAND(state);
                    trickyReportError(base + 0x8c4);
                    break;
                }
                break;
            case 3:
                played = 0;
                if (((TrickyState*)state)->unkD == 3)
                {
                    p = state;
                    count = ((TrickyState*)state)->unk798;
                    for (i = 0; i < count; i++)
                    {
                        if (*(s8*)(p + 0x74d) == 3)
                        {
                            played = 1;
                        }
                        p = p + 8;
                    }
                }
                else
                {
                    played = 1;
                }
                if (played != 0)
                {
                    ((TrickyState*)state)->unkD = 3;
                    if (trickySelectQueuedCommandTarget(state, 3) != 0)
                    {
                        switch (((GameObject*)((TrickyState*)state)->followObj)->anim.seqId)
                        {
                        case 0x36:
                        case 0x104:
                        case 0x131:
                        case 0x19f:
                        case 0x26c:
                        case 0x475:
                        case 0x546:
                        case 0x7c3:
                            ((TrickyState*)state)->unk08 = 0xa;
                            ((TrickyState*)state)->unk740 = (f32)(int)
                            randomGetRange(0x1f4, 0x2ee);
                            break;
                        case 0x6f0:
                            ((TrickyState*)state)->unk08 = 0xe;
                            break;
                        default:
                            ((TrickyState*)state)->unk08 = 8;
                            break;
                        }
                    }
                    else
                    {
                        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 0x40000LL;
                    }
                }
                break;
            case 4:
                if (**(u8**)state < 4)
                {
                    if (Obj_IsLoadingLocked())
                    {
                        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 4;
                        TRICKY_RESET_COMMAND(state);
                        TRICKY_SPAWN_BUBBLE(obj, state);
                    }
                }
                else
                {
                    ((TrickyState*)state)->unkD = 4;
                    trickySelectQueuedCommandTarget(state, 4);
                    ((TrickyState*)state)->unk08 = 7;
                    switch (((GameObject*)((TrickyState*)state)->followObj)->anim.seqId)
                    {
                    case 0x1c9:
                        *(void**)&((TrickyState*)state)->unk724 = fn_801B17F4;
                        break;
                    case 0x718:
                        *(void**)&((TrickyState*)state)->unk724 = fn_801B6D40;
                        break;
                    case 0x551:
                        *(void**)&((TrickyState*)state)->unk724 = fn_801FD4A8;
                        break;
                    case 0x191:
                        *(void**)&((TrickyState*)state)->unk724 = fn_801B0784;
                        break;
                    case 0x470:
                        *(void**)&((TrickyState*)state)->unk724 = drchimmey_countdownCallback;
                        break;
                    case 0x102:
                    case 0x194:
                    case 0x542:
                    case 0x54c:
                    case 0x6f9:
                        *(void**)&((TrickyState*)state)->unk724 = 0;
                        break;
                    case 0x3c:
                        *(void**)&((TrickyState*)state)->unk724 = fn_801DA9CC;
                        break;
                    case 0x50f:
                        *(void**)&((TrickyState*)state)->unk724 = wcbeacon_aButtonCallback;
                        break;
                    default:
                        TRICKY_RESET_COMMAND(state);
                        trickyReportError(base + 0x8c4);
                        break;
                    }
                }
                break;
            case 5:
                if (Obj_IsLoadingLocked())
                {
                    ((TrickyState*)state)->unkD = 5;
                    setup = Obj_AllocObjectSetup(0x18, 0x112);
                    *(u8*)(setup + 7) = 0xff;
                    *(u8*)(setup + 4) = 2;
                    ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.worldPosX;
                    ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.worldPosY;
                    ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.worldPosZ;
                    *(int*)&((TrickyState*)state)->followObj = Obj_SetupObject(
                        setup, 5, -1, -1, *(int*)&((GameObject*)obj)->anim.parent);
                    target = (u32)&((GameObject*)((TrickyState*)state)->followObj)->anim.worldPosX;
                    if (*(u32*)&((TrickyState*)state)->targetPosPtr != target)
                    {
                        *(u32*)&((TrickyState*)state)->targetPosPtr = target;
                        *(s32*)&((TrickyState*)state)->stateFlags &= ~(u64)0x400;
                        ((TrickyState*)state)->unkD2 = 0;
                    }
                    ((TrickyState*)state)->substate = 0;
                    ((TrickyState*)state)->unk08 = 0xb;
                }
                break;
            default:
                if (((TrickyState*)state)->unk08 == 1 && ((TrickyState*)state)->unkD != 0 && (f & 0x20000) == 0)
                {
                    step = trickyFindNearestUsableBaddie(((TrickyState*)state)->playerObj, lbl_803E24D8, 0);
                    if ((void*)step != NULL)
                    {
                        *(int*)&((TrickyState*)state)->followObj = step;
                        if (*(u32*)&((TrickyState*)state)->targetPosPtr != (u32)(step + 0x18))
                        {
                            *(u32*)&((TrickyState*)state)->targetPosPtr = step + 0x18;
                            *(s32*)&((TrickyState*)state)->stateFlags &= ~(u64)0x400;
                            ((TrickyState*)state)->unkD2 = 0;
                        }
                        ((TrickyState*)state)->unk08 = 0xd;
                        ((TrickyState*)state)->substate = 0;
                        *(int*)&((TrickyState*)state)->unk728 = 0;
                    }
                }
                break;
            }
        }
        else if (cmd == 3)
        {
            ((TrickyState*)state)->stateFlags = f | 0x40000LL;
        }
    }
    f = ((TrickyState*)state)->stateFlags;
    if ((f & 0x10) == 0)
    {
        if ((f & 0x10000) != 0)
        {
            if ((f & 0x20000) != 0)
            {
                TRICKY_RESET_COMMAND(state);
                *(u8*)&((TrickyState*)state)->unkD = 0;
            }
            else
            {
                TRICKY_RESET_COMMAND(state);
            }
            ((TrickyState*)state)->unk71C = lbl_803E2548;
        }
        else if ((f & 0x40000) != 0)
        {
            *(int*)&((TrickyState*)state)->followObj = obj;
            ((TrickyState*)state)->unk08 = 0xf;
            ((TrickyState*)state)->unk740 = (f32)(int)
            randomGetRange(0x1f4, 0x2ee);
            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & ~0x40000LL;
            ((TrickyState*)state)->unkD = 3;
            if (*(u32*)&((TrickyState*)state)->targetPosPtr != (u32) & ((TrickyState*)state)->unk72C)
            {
                *(u32*)&((TrickyState*)state)->targetPosPtr = (u32) & ((TrickyState*)state)->unk72C;
                ((TrickyState*)state)->stateFlags &= ~0x400LL;
                ((TrickyState*)state)->unkD2 = 0;
            }
        }
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED;
    ((TrickyState*)state)->unk353 = 1;
    handlerBase = ((TrickyHandlerTable*)base)->handlers;
    handlerBase[((TrickyState*)state)->unk08](obj, state);
    ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & ~(u64)0x2;
    ((TrickyState*)state)->animTransitionTimer += timeDelta;
    if (((TrickyState*)state)->animTransitionTimer > lbl_803E247C)
    {
        if (((GameObject*)obj)->anim.currentMove != ((TrickyState*)state)->moveId)
        {
            if ((((TrickyState*)state)->pendingStateFlags & 0x1000000) != 0 && (((TrickyState*)state)->stateFlags &
                0x1000000) != 0)
            {
                ObjAnim_SetCurrentMove(obj, ((TrickyState*)state)->moveId, ((GameObject*)obj)->anim.currentMoveProgress,
                                       0);
            }
            else
            {
                ObjAnim_SetCurrentMove(obj, ((TrickyState*)state)->moveId, lbl_803E23DC, 0);
            }
            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & ~0x060001e0LL;
            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | ((TrickyState*)state)->
                pendingStateFlags;
            ((TrickyState*)state)->animTransitionTimer = lbl_803E23DC;
            ((TrickyState*)state)->moveProgress = ((TrickyState*)state)->moveProgressTarget;
        }
    }
    if ((((TrickyState*)state)->stateFlags & 0x2000000) != 0)
    {
        ((GameObject*)obj)->anim.localPosX += timeDelta * (((TrickyState*)state)->dirX * ((TrickyState*)state)->speed);
        ((GameObject*)obj)->anim.localPosZ += timeDelta * (((TrickyState*)state)->dirZ * ((TrickyState*)state)->speed);
        ObjAnim_SampleRootCurvePhase(((TrickyState*)state)->speed, (ObjAnimComponent*)obj, (float*)(state + 0x34));
    }
    if (((TrickyState*)state)->moveProgress == lbl_803E23DC)
    {
        ObjAnim_SetMoveProgress(((TrickyState*)state)->unk3C, (ObjAnimComponent*)obj);
    }
    if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, ((TrickyState*)state)->moveProgress, timeDelta,
                                                                    (void*)(state + 0x80c)) != 0)
    {
        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 0x8000000LL;
    }
    else
    {
        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & ~0x8000000LL;
    }
    if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_ROTATE) != 0)
    {
        diff = ((TrickyState*)state)->unk5A - (u16)((GameObject*)obj)->anim.rotX;
        if (diff > 0x8000)
        {
            diff -= 0xffff;
        }
        if (diff < -0x8000)
        {
            diff += 0xffff;
        }
        step = (int)((f32)((TrickyState*)state)->rotRate * ((TrickyState*)state)->rotStepScale);
        if ((diff >= 0 ? diff : -diff) >= 4)
        {
            if ((diff > 0 && step > 0) || (diff < 0 && step < 0))
            {
                if ((step >= 0 ? step : -step) > (diff >= 0 ? diff : -diff))
                {
                    *(s16*)obj = *(s16*)(int)(GameObject*)obj + diff;
                }
                else
                {
                    *(s16*)obj = *(s16*)(int)(GameObject*)obj + step;
                }
            }
            else
            {
                *(s16*)obj = *(s16*)(int)(GameObject*)obj + step;
            }
        }
        else
        {
            *(s16*)obj = *(s16*)(int)(GameObject*)obj + diff;
        }
    }
    if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_BACKSTEP) != 0)
    {
        ((GameObject*)obj)->anim.localPosX += ((TrickyState*)state)->backstepDelta * (((TrickyState*)state)->dirX * -((
            TrickyState*)state)->unk814);
        ((GameObject*)obj)->anim.localPosZ += ((TrickyState*)state)->backstepDelta * (((TrickyState*)state)->dirZ * -((
            TrickyState*)state)->unk814);
    }
    if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_VERTICAL_MOVE) != 0)
    {
        ((GameObject*)obj)->anim.localPosY += ((TrickyState*)state)->unk810 * ((TrickyState*)state)->verticalDelta;
    }
    if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_SIDESTEP) != 0)
    {
        ((GameObject*)obj)->anim.localPosX += ((TrickyState*)state)->sidestepDelta * (((TrickyState*)state)->dirZ * ((
            TrickyState*)state)->unk80C);
        ((GameObject*)obj)->anim.localPosZ += ((TrickyState*)state)->sidestepDelta * (((TrickyState*)state)->dirX * -((
            TrickyState*)state)->unk80C);
    }
    if (*(void**)&((TrickyState*)state)->followObj != NULL)
    {
        ((TrickyState*)state)->unk378 = 1;
        ((TrickyState*)state)->unk37C = ((GameObject*)((TrickyState*)state)->followObj)->anim.worldPosX;
        ((TrickyState*)state)->unk380 = ((GameObject*)((TrickyState*)state)->followObj)->anim.worldPosY;
        ((TrickyState*)state)->unk384 = ((GameObject*)((TrickyState*)state)->followObj)->anim.worldPosZ;
    }
    else
    {
        ((TrickyState*)state)->unk378 = 0;
    }
    if (((GameObject*)obj)->anim.currentMove == 0x2a)
    {
        fn_8003A168(obj, (void*)(state + 0x378));
        fn_8003B228(obj, (void*)(state + 0x378));
    }
    else
    {
        fn_8003A230(obj, (void*)(state + 0x378), lbl_803E23DC);
        characterDoEyeAnims(obj, (void*)(state + 0x378));
    }
    objAnimFn_80038f38(obj, state + 0x3a8);
    st = *(int*)&((GameObject*)obj)->extra;
    stState = (TrickyState*)st;
    p = (int)stState->targetPosPtr;
    stState->previousPathPoint = (f32*)p;
    if (stState->previousPathPoint != NULL)
    {
        stState->previousPathX = *(f32*)p;
        stState->previousPathY = *(f32*)(p + 4);
        stState->previousPathZ = *(f32*)(p + 8);
    }
    ((TrickyState*)state)->prevSpeed = ((TrickyState*)state)->speed;
    i = ((TrickyState*)state)->unk798 - 1;
    p = state + i * 8;
    for (; i >= 0; i--)
    {
        *(u8*)(p + 0x74e) -= 1;
        if (*(s8*)(p + 0x74e) == 0)
        {
            memmove((void*)(p + 0x748), (void*)(state + (i + 1) * 8 + 0x748),
                    (((TrickyState*)state)->unk798 - i - 1) * 8);
            ((TrickyState*)state)->unk798 -= 1;
        }
        p = p - 8;
    }
    if (getXZDistance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)((TrickyState*)state)->playerObj)->anim.worldPosX) >=
        lbl_803E2538 &&
        GameBit_Get(0x4e4) != 0)
    {
        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 0x10000LL;
    }
    ((TrickyState*)state)->unk79C -= timeDelta;
    if (((TrickyState*)state)->unk79C < lbl_803E23DC)
    {
        ((TrickyState*)state)->unk79C = lbl_803E23DC;
    }
    if ((((TrickyState*)state)->stateFlags & 4) != 0)
    {
        st = *(int*)&((GameObject*)obj)->extra;
        if (((TrickyByteFlags*)(st + 0x58))->bit6 != 0)
        {
            played = 0;
        }
        else if (((GameObject*)obj)->anim.currentMove < 0x30 && ((GameObject*)obj)->anim.currentMove >= 0x29)
        {
            played = 0;
        }
        else if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) != 0)
        {
            played = 0;
        }
        else
        {
            objAudioFn_800393f8(obj, (void*)(st + 0x3a8), 0x298, 0x500, 0xffffffff, 0);
            played = 1;
        }
        if (played != 0)
        {
            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & ~(u64)0x4;
        }
    }
    ((TrickyState*)state)->unk7A0f -= timeDelta;
    if (((TrickyState*)state)->unk7A0f < lbl_803E23DC)
    {
        ((TrickyState*)state)->unk7A0f = lbl_803E23DC;
    }
    if (((TrickyState*)state)->unk7A0f > lbl_803E23DC)
    {
        TRICKY_VOICE(obj, st, 0x29c, 0x100);
    }
    trickyUpdateCollisionAndPathState((u8*)obj);
    if ((((TrickyState*)state)->stateFlags & 0x80000000) != 0)
    {
        ((TrickyState*)state)->unk808 -= timeDelta;
        if (((TrickyState*)state)->unk808 <= lbl_803E23DC)
        {
            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & 0x7FFFFFFF;
            sfxId = ((u16*)&pair)[randomGetRange(0, 1)];
            TRICKY_VOICE(obj, st, sfxId, 0x500);
        }
    }
    fn_80138D7C(obj, state);
    Tricky_updateBlendChannelWeight(obj, state);
    if (((TrickyState*)state)->speed > lbl_803E254C)
    {
        objAudioFn_8006ef38(obj, state + 0x80c, 1, state + 0x7d8, state + 0xf8, ((TrickyState*)state)->speed,
                            lbl_803E23E8);
    }
    if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
    {
        talking = 0;
    }
    else if (lbl_803E2410 == ((TrickyState*)state)->eventTime)
    {
        talking = 1;
    }
    else if (((TrickyState*)state)->currentTime - ((TrickyState*)state)->eventTime > lbl_803E2414)
    {
        talking = 1;
    }
    else
    {
        talking = 0;
    }
    if (talking != 0)
    {
        p = state + 0x80c;
        sfx2 = 0;
        for (i = 0, count = *(s8*)(p + 0x1b); i < count; i++)
        {
            if (*(s8*)(p + i + 0x13) < 3 && *(s8*)(p + i + 0x13) >= 0)
            {
                sfx2 = 0x433;
            }
        }
        if (sfx2 != 0)
        {
            Sfx_PlayFromObject(obj, (u16)sfx2);
        }
    }
    ((TrickyState*)state)->prevLocalPosX = ((GameObject*)obj)->anim.previousLocalPosX;
    ((TrickyState*)state)->prevLocalPosY = ((GameObject*)obj)->anim.previousLocalPosY;
    ((TrickyState*)state)->prevLocalPosZ = ((GameObject*)obj)->anim.previousLocalPosZ;
    if (*(void**)&((TrickyState*)state)->child != NULL)
    {
        ((TrickyState*)state)->unk7C0 += timeDelta;
        ((TrickyState*)state)->unk7C4 += timeDelta;
        ((TrickyState*)state)->unk7C8 += timeDelta;
        if (((TrickyState*)state)->unk7C8 > lbl_803E24C8)
        {
            ((TrickyState*)state)->unk7C8 -= lbl_803E24C8;
        }
        if (((TrickyState*)state)->unk7C8 >= lbl_803E2408)
        {
            *(s16*)(*(int*)&((TrickyState*)state)->child + 6) = *(s16*)(*(int*)&((TrickyState*)state)->child + 6) |
                0x4000;
        }
        else
        {
            *(s16*)(*(int*)&((TrickyState*)state)->child + 6) = *(s16*)(*(int*)&((TrickyState*)state)->child + 6) & ~
                0x4000;
        }
        if (((TrickyState*)state)->unk7C4 > lbl_803E24D8)
        {
            if (((TrickyState*)state)->unk7C4 > lbl_803E2440)
            {
                ((TrickyState*)state)->unk7C4 -= lbl_803E2440;
            }
            *(s16*)(*(int*)&((TrickyState*)state)->child + 6) = *(s16*)(*(int*)&((TrickyState*)state)->child + 6) |
                0x4000;
        }
        if (((TrickyState*)state)->unk7C0 > lbl_803E2550)
        {
            if (GameBit_Get(0xc1) != 0)
            {
                TRICKY_VOICE(obj, st, 0x392, 0x500);
            }
            else
            {
                TRICKY_VOICE(obj, st, 0x298, 0x500);
            }
            ((TrickyState*)state)->unk7C0 -= lbl_803E2550;
        }
        ObjAnim_AdvanceCurrentMove(lbl_803E23EC, timeDelta, *(int*)&((TrickyState*)state)->child, 0);
    }
    if (*(void**)&((TrickyState*)state)->unk7B0 != NULL)
    {
        ObjAnim_AdvanceCurrentMove(lbl_803E23EC, timeDelta, *(int*)&((TrickyState*)state)->unk7B0, 0);
    }
    if (*(void**)&((TrickyState*)state)->unk7A8 != NULL)
    {
        ObjAnim_AdvanceCurrentMove(lbl_803E23EC, timeDelta, *(int*)&((TrickyState*)state)->unk7A8, 0);
    }
}

void Tricky_init(int obj)
{
    int state;
    int model;
    int pathState;
    u32 modelVariant;
    u16 startPath[4];

    state = *(int*)&((GameObject*)obj)->extra;
    startPath[0] = lbl_803E23C0;
    GameBit_Set(0x4e3, 0xff);
    if (GameBit_Get(0x25) != 0)
    {
        GameBit_Set(0x3f8, 1);
    }
    ((GameObject*)obj)->animEventCallback = tricky_SeqFn;
    ObjGroup_AddObject(obj, TRICKY_OBJGROUP);
    trickyVoxAllocFn_8004b5d4((void*)((TrickyState*)state)->voxBlocks[0]);
    trickyVoxAllocFn_8004b5d4((void*)((TrickyState*)state)->voxBlocks[1]);
    trickyVoxAllocFn_8004b5d4((void*)((TrickyState*)state)->voxBlocks[2]);
    trickyVoxAllocFn_8004b5d4((void*)((TrickyState*)state)->voxBlocks[3]);
    trickyVoxAllocFn_8004b5d4((void*)((TrickyState*)state)->voxBlocks[4]);
    trickyVoxAllocFn_8004b5d4((void*)((TrickyState*)state)->voxBlocks[5]);
    trickyVoxAllocFn_8004b5d4((void*)((TrickyState*)state)->voxBlocks[6]);
    trickyVoxAllocFn_8004b5d4((void*)((TrickyState*)state)->voxBlocks[7]);
    trickyVoxAllocFn_8004b5d4((void*)((TrickyState*)state)->voxBlocks[8]);
    ((TrickyState*)state)->progressPtr = (int)(*gMapEventInterface)->getTrickyEnergy();
    ((TrickyState*)state)->playerObj = Obj_GetPlayerObject();
    ((TrickyState*)state)->unk08 = 0;
    ((TrickyState*)state)->unk0B = 0;
    ((TrickyState*)state)->previousPathPoint = NULL;
    ((TrickyState*)state)->activeWalkGroup = 0;
    ((TrickyState*)state)->homePosX = ((GameObject*)obj)->anim.worldPosX;
    ((TrickyState*)state)->homePosY = ((GameObject*)obj)->anim.worldPosY;
    ((TrickyState*)state)->homePosZ = ((GameObject*)obj)->anim.worldPosZ;
    modelVariant = *(u8*)(((TrickyState*)state)->progressPtr + 2) / 10;
    modelVariant = modelVariant;
    ((TrickyState*)state)->modelVariant = modelVariant;
    model = Obj_GetActiveModel(obj);
    *(u8*)(*(int*)(model + 0x34) + 8) = ((TrickyState*)state)->modelVariant;
    pathState = (int)&((TrickyState*)state)->pathControlFlags;
    (*gPathControlInterface)->init((void*)pathState, 1, 0xa7, 1);
    (*gPathControlInterface)->setLocalPointCollision((void*)pathState, 1, gTrickyPathPointCollision,
                                                     &lbl_803DBC48, 2);
    (*gPathControlInterface)->setup((void*)pathState, 2, lbl_8031D2E8, &lbl_803DBC40, startPath);
    (*gPathControlInterface)->attachObject((void*)obj, (void*)pathState);
    doNothing_onTrickyInit();
    walkgroupFindExitPointFn_800dc398();
    ((TrickyState*)state)->unk374 = 2;
    ((TrickyInitFlags*)&((TrickyState*)state)->unk82E)->initBit7 = 1;
    ((TrickyState*)state)->unkD = -1;
}

void Tricky_resumeAfterCommand(int obj, int state)
{
    ObjHitsPriorityState* hitState;
    u8 moveId;

    ((TrickyState*)state)->actionId = 1;
    if (((((TrickyState*)state)->flags2DC & 0x1000) != 0) &&
        ((((TrickyState*)state)->flags2E0 & 0x1000) == 0))
    {
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN;
        moveId = ((TrickyState*)state)->moveId0;
        ((TrickyState*)state)->animPlaySpeed = lbl_803E256C / (lbl_803E2570 * ((TrickyState*)state)->moveSpeedScale0);
        ((TrickyState*)state)->flags323 = 1;
        ObjAnim_SetCurrentMove(obj, moveId, lbl_803E2574, 0x10);
        if (((GameObject*)obj)->anim.hitReactState != NULL)
        {
            hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            hitState->suppressOutgoingHits = 0;
        }
        ((TrickyState*)state)->flags2E8 = ((TrickyState*)state)->flags2E8 | 4;
        Sfx_PlayFromObjectLimited(obj, SFXTRIG_holorays16, 2);
        ObjHits_EnableObject(obj);
    }
    if ((((TrickyState*)state)->flags2DC & 0x40000000) != 0)
    {
        ((TrickyState*)state)->animPlaySpeed = lbl_803E2578;
        ((TrickyState*)state)->flags323 = 0;
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E2574, 0);
        if (((GameObject*)obj)->anim.hitReactState != NULL)
        {
            hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            hitState->suppressOutgoingHits = 0;
        }
        ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC & 0xffffef7f;
        ((TrickyState*)state)->flags2E8 = ((TrickyState*)state)->flags2E8 & ~(u64)0x4;
        ((TrickyState*)state)->currentMoveProgress = lbl_803E2574;
        ((GameObject*)obj)->anim.alpha = 0xff;
    }
    else
    {
        ((GameObject*)obj)->anim.alpha = (int)(lbl_803E257C * ((GameObject*)obj)->anim.currentMoveProgress);
        ((TrickyState*)state)->currentMoveProgress = ((GameObject*)obj)->anim.currentMoveProgress;
    }
}

void tricky_handleDefeat(int obj, int state)
{
    ObjHitsPriorityState* hitState;
    int setup;
    int alpha;
    void* tricky;
    int spawnBits;
    u8 moveId;

    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    ((TrickyState*)state)->actionId = 0;
    if (((((TrickyState*)state)->flags2DC & 0x800) != 0) &&
        ((((TrickyState*)state)->flags2E0 & 0x800) == 0))
    {
        tricky = (void*)getTrickyObject();
        if (tricky != NULL)
        {
            trickyImpress((int)tricky);
        }
        /* Skip the death gamebits when the baddie is sequence-driven so
         * scripted/cutscene deaths don't count. */
        if ((((TrickyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) == 0)
        {
            if (*(s16*)(setup + BADDIE_PLACEMENT_DEATH_GAMEBIT) != -1)
            {
                gameBitIncrement(*(s16*)(setup + BADDIE_PLACEMENT_DEATH_GAMEBIT));
            }
            if (*(s16*)(setup + BADDIE_PLACEMENT_CLEAR_ON_DEATH_GAMEBIT) != -1)
            {
                GameBit_Set(*(s16*)(setup + BADDIE_PLACEMENT_CLEAR_ON_DEATH_GAMEBIT), 0);
            }
        }
        ((TrickyState*)state)->actionTargetObj = 0;
        ObjHits_DisableObject(obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED;
        moveId = ((TrickyState*)state)->moveId1;
        ((TrickyState*)state)->animPlaySpeed = lbl_803E256C / (lbl_803E2570 * ((TrickyState*)state)->moveSpeedScale1);
        ((TrickyState*)state)->flags323 = 1;
        ObjAnim_SetCurrentMove(obj, moveId, lbl_803E2574, 0);
        if (*(void**)&((GameObject*)obj)->anim.hitReactState != NULL)
        {
            hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            hitState->suppressOutgoingHits = 0;
        }
        ((TrickyState*)state)->flags2E8 = ((TrickyState*)state)->flags2E8 | 1;
        Sfx_PlayFromObject(obj, SFXdoor_creak);
        if (randomGetRange(0, 100) > 50)
        {
            if ((((TrickyState*)state)->controlFlags & 0x100000) != 0)
            {
                collectibleFn_80149cec(obj, state, ((TrickyState*)state)->spawnBits, 0, 4);
            }
            else
            {
                spawnBits = *(s16*)(setup + 0x22) & 0xf00;
                if (spawnBits != 0)
                {
                    collectibleFn_80149cec(obj, state, spawnBits, 0, 1);
                }
                spawnBits = *(s16*)(setup + 0x22) & 0xf000;
                if (spawnBits != 0)
                {
                    collectibleFn_80149cec(obj, state, spawnBits, 0, 2);
                }
                spawnBits = *(s16*)(setup + 0x22) & 0xff;
                if (spawnBits != 0)
                {
                    collectibleFn_80149cec(obj, state, spawnBits, 0, 3);
                }
            }
        }
    }
    alpha = 0xff - (int)(lbl_803E257C * ((GameObject*)obj)->anim.currentMoveProgress);
    alpha = (alpha < 0) ? 0 : ((alpha > 0xff) ? 0xff : alpha);
    ((GameObject*)obj)->anim.alpha = alpha;
    ((TrickyState*)state)->currentMoveProgress =
        lbl_803E256C + (f32)(0xff - ((GameObject*)obj)->anim.alpha) / lbl_803E257C;
    if (((GameObject*)obj)->anim.alpha < 5)
    {
        /* Fire the death gamebits for the sequence-driven path (the
         * faded-out branch). */
        if ((((TrickyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            if (*(s16*)(setup + BADDIE_PLACEMENT_DEATH_GAMEBIT) != -1)
            {
                gameBitIncrement(*(s16*)(setup + BADDIE_PLACEMENT_DEATH_GAMEBIT));
            }
            if (*(s16*)(setup + BADDIE_PLACEMENT_CLEAR_ON_DEATH_GAMEBIT) != -1)
            {
                GameBit_Set(*(s16*)(setup + BADDIE_PLACEMENT_CLEAR_ON_DEATH_GAMEBIT), 0);
            }
        }
        ((TrickyState*)state)->currentMoveProgress = lbl_803E2574;
        ((TrickyState*)state)->flags2DC = 0;
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
        ((GameObject*)obj)->anim.alpha = 0;
        *(u32*)&((GameObject*)obj)->unkF4 = 1;
        if ((u32)((ObjPlacement*)setup)->mapId == 0xFFFFFFFF)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            if (*(s16*)(setup + 0x2c) != 0)
            {
                (*gMapEventInterface)->addTime(((ObjPlacement*)setup)->mapId,
                                                       lbl_803E2570 * (f32) * (s16*)(setup + 0x2c));
            }
            ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC & ~(u64)0x800;
            ((TrickyState*)state)->flags2E8 = ((TrickyState*)state)->flags2E8 & ~3LL;
        }
    }
}

struct TrickyCommandSpawnPair
{
    u32 a;
    u32 b;
};

int collectibleFn_80149cec(int obj, int state, int spawnBits, u32 useAltMode, u32 mode)
{
    u32 commandSpawnIds[2];
    struct TrickyRewardSpawnTail
    {
        u32 pair;
        u16 single;
    } rewardTail;
    f32 nearestDistance;
    u32 rewardSpawnIds0;
    int nearest;
    int parentSetup;
    int setup;
    int index;
    f32 savedX;
    f32 savedY;
    f32 savedZ;
    f32 v;

    (void)state;
    parentSetup = *(int*)&((GameObject*)obj)->anim.placementData;
    *(struct TrickyCommandSpawnPair*)commandSpawnIds = *(struct TrickyCommandSpawnPair*)&lbl_803E2558;
    rewardSpawnIds0 = lbl_803E2560;
    rewardTail.pair = lbl_803E2564;
    rewardTail.single = lbl_803E2568;
    if (spawnBits == 0)
    {
        return 0;
    }
    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }
    mode = (u8)mode;
    if (mode == 1)
    {
        index = ((spawnBits & 0xf00) >> 8) - 1;
        if (index > 3)
        {
            index = 3;
        }
        setup = Obj_AllocObjectSetup(0x30, *(u16*)((int)commandSpawnIds + index * 2));
    }
    else if (mode == 2)
    {
        index = ((spawnBits & 0xf000) >> 0xc) - 1;
        if (index > 1)
        {
            index = 1;
        }
        setup = Obj_AllocObjectSetup(0x30, *(u16*)((int)&rewardSpawnIds0 + index * 2));
    }
    else if (mode == 3)
    {
        switch (spawnBits)
        {
        case 1:
            setup = Obj_AllocObjectSetup(0x30, 0x2cd);
            break;
        case 3:
            setup = Obj_AllocObjectSetup(0x30, 0xb);
            break;
        case 4:
            setup = Obj_AllocObjectSetup(0x30, 0x2cd);
            break;
        case 5:
            savedX = ((GameObject*)obj)->anim.worldPosX;
            savedY = ((GameObject*)obj)->anim.worldPosY;
            savedZ = ((GameObject*)obj)->anim.worldPosZ;
            parentSetup = *(int*)&((GameObject*)obj)->anim.placementData;
            if ((void*)parentSetup != NULL)
            {
                ((GameObject*)obj)->anim.worldPosX = ((ObjPlacement*)parentSetup)->posX;
                ((GameObject*)obj)->anim.worldPosY = ((ObjPlacement*)parentSetup)->posY;
                ((GameObject*)obj)->anim.worldPosZ = ((ObjPlacement*)parentSetup)->posZ;
            }
            nearestDistance = lbl_803E25A8;
            gTrickyNearestObject = ObjGroup_FindNearestObject(4, obj, &nearestDistance);
            ((GameObject*)obj)->anim.worldPosX = savedX;
            ((GameObject*)obj)->anim.worldPosY = savedY;
            ((GameObject*)obj)->anim.worldPosZ = savedZ;
            if ((void*)gTrickyNearestObject != NULL)
            {
                v = ((GameObject*)obj)->anim.localPosX;
                ((GameObject*)gTrickyNearestObject)->anim.worldPosX = v;
                ((GameObject*)gTrickyNearestObject)->anim.localPosX = v;
                v = lbl_803E25AC + ((GameObject*)obj)->anim.localPosY;
                ((GameObject*)gTrickyNearestObject)->anim.worldPosY = v;
                ((GameObject*)gTrickyNearestObject)->anim.localPosY = v;
                v = ((GameObject*)obj)->anim.localPosZ;
                ((GameObject*)gTrickyNearestObject)->anim.worldPosZ = v;
                ((GameObject*)gTrickyNearestObject)->anim.localPosZ = v;
            }
            return gTrickyNearestObject;
        default:
            return 0;
        }
    }
    else if (mode == 4)
    {
        index = spawnBits;
        if (index > 3)
        {
            index = 3;
        }
        if (index <= 0)
        {
            return 0;
        }
        setup = Obj_AllocObjectSetup(0x30, ((u16*)((u8*)&rewardTail.pair - 2))[index]);
    }
    *(u8*)(setup + 0x1a) = 0x14;
    *(s16*)(setup + 0x2c) = -1;
    *(s16*)(setup + 0x1c) = -1;
    *(s16*)(setup + 0x24) = -1;
    ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
    ((ObjPlacement*)setup)->posY = lbl_803E2598 + ((GameObject*)obj)->anim.localPosY;
    ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
    if ((useAltMode & 0xff) != 0)
    {
        *(s16*)(setup + 0x2e) = 2;
    }
    else
    {
        *(s16*)(setup + 0x2e) = 1;
    }
    ((ObjPlacement*)setup)->color[0] = ((ObjPlacement*)parentSetup)->color[0];
    ((ObjPlacement*)setup)->color[2] = ((ObjPlacement*)parentSetup)->color[2];
    ((ObjPlacement*)setup)->color[1] = ((ObjPlacement*)parentSetup)->color[1];
    ((ObjPlacement*)setup)->color[3] = ((ObjPlacement*)parentSetup)->color[3];
    nearest = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                   *(int*)&((GameObject*)obj)->anim.parent);
    gTrickyNearestObject = nearest;
    if ((((GameObject*)nearest)->anim.seqId == 0x3cd) ||
        (((GameObject*)nearest)->anim.seqId == 0xb))
    {
        (*(void (**)(int, f32, f32, f32))(*(int*)(*(int*)&((GameObject*)nearest)->anim.dll) + 0x2c))
            (nearest, lbl_803E2574, lbl_803E256C, lbl_803E2574);
    }
    return gTrickyNearestObject;
}

/* baddie_updateWhileFrozen: 2796b - shared frozen-state update + per-baddie reaction dispatch. */
typedef struct
{
    s16 rot[3];
    f32 scale;
    Vec pos;
} FrozenFxParams;

typedef struct
{
    int c0;
    int c1;
    int c2;
    int c3;
} FrozenFxColors;

typedef struct
{
    u8 fadeCounter : 5;
    u8 low : 3;
} FrozenByte2F6;

struct VisBits16
{
    u32 w0;
    u32 w1;
    u32 w2;
    u32 w3;
};

extern f32 sqrtf(f32 x);
extern int getAngle(float y, float x);
void frozenEnemyFn_80149bb4(int* obj, u32 flags, f32 f, u16 val);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern int gTrickyFrozenFxColors[];
extern int* lbl_803DDA50;
extern f32 lbl_803E2588;
extern f32 lbl_803E258C;
extern f32 lbl_803E2590;
extern f32 lbl_803E2594;
extern f32 lbl_803E259C;
extern void fn_802972B4(int player, u32* outEffects, f32* outA, f32* outB, f32* outC, u16* outSfx);
extern void vecRotateZXY(int obj, void* vel);
extern int objCreateLight(int a, int b);
extern void Obj_SetModelColorFadeRecursive(int obj, int a, int b, int c, int d, int e);
extern void Obj_ResetModelColorState(int obj);
extern void Obj_StartModelFadeIn(int obj, int duration);
extern void fn_802961FC(u8* proj, int result);
extern int fn_801504F8(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector, f32 hDist,
                       f32 vDist);
extern void fn_80152004(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
extern void fn_80152440(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
extern void fn_80152B2C(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
extern void fn_80152FA8(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
extern void fn_80153790(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
extern void fn_80153CF8(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
extern void fn_801544E8(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
extern void rachnopUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                     int sector);
extern void wbUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
extern void baddieUpdateWhileFrozen_80155e10(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                             int sector);
extern void mutatedEbaUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                        int sector);
extern void crawler_nop(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
extern void crawler_handleReactionEvent(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                            int sector);
extern void hoodedZyckUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                        int sector);
extern void fn_8014FEF8(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
extern void crawler_onHit(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
extern void crawler_handleHitStateEvent(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                            int sector);

void baddie_updateWhileFrozen(int obj, u8* state, u8 fromHit)
{
    int player;
    int hit;
    int result;
    u16 sector;
    int diff;
    f32 hDist;
    f32 vDist;
    u8* proj;
    f32* dp;
    f32 zero;
    FrozenFxParams params;
    Vec hitPos;
    f32 delta[3];
    FrozenFxColors colors;
    int attacker;
    f32 fxA;
    f32 fxB;
    f32 fxC;
    int hitArg;
    u32 hitCount;
    u32 hitEffects;
    u16 impactSfx;

    player = Obj_GetPlayerObject();
    colors = *(FrozenFxColors*)gTrickyFrozenFxColors;
    result = 2;
    if ((((TrickyState*)state)->flags2DC & 0x1800) == 0)
    {
        if ((((TrickyState*)state)->controlFlags & 1) != 0)
        {
            ObjHits_EnableObject(obj);
        }
        else
        {
            ObjHits_DisableObject(obj);
        }
        hit = ObjHits_GetPriorityHitWithPosition(obj, &attacker, &hitArg, &hitCount, &hitPos.x, &hitPos.y, &hitPos.z);
        hitPos.x += playerMapOffsetX;
        hitPos.z += playerMapOffsetZ;
        ((TrickyState*)state)->freezeStunTimer -= timeDelta;
        if (hit == 0x1a)
        {
            if (((TrickyState*)state)->freezeStunTimer >= lbl_803E2574)
            {
                hit = 0;
            }
            else
            {
                ((TrickyState*)state)->freezeStunTimer = lbl_803E2588;
            }
        }
        ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC & ~0x30LL;
        ((TrickyState*)state)->freezeRecoverTimer -= timeDelta;
        if (((TrickyState*)state)->freezeRecoverTimer < *(f32*)&lbl_803E2574)
        {
            ((TrickyState*)state)->freezeRecoverTimer = lbl_803E2574;
        }
        fn_802972B4(player, &hitEffects, &fxA, &fxB, &fxC, &impactSfx);
        frozenEnemyFn_80149bb4((int*)state, hitEffects, fxA, impactSfx);
        if (hit != 0)
        {
            if (fromHit)
            {
                if (hit != 0x10)
                {
                    params.scale = lbl_803E258C;
                    (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x7fb, NULL,
                                                                 0x64, &params);
                    (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x7fc, NULL,
                                                                 0x32, NULL);
                    Obj_ResetModelColorState(obj);
                    *(u16*)&((TrickyState*)state)->eventTime = 0;
                    ((TrickyState*)state)->flags2E8 = ((TrickyState*)state)->flags2E8 & ~0x20LL;
                    ((TrickyState*)state)->flags2E8 = ((TrickyState*)state)->flags2E8 | 0x200;
                    Sfx_PlayFromObject(obj, SFXTRIG_barrel_bounce1);
                }
                else
                {
                    ((TrickyState*)state)->flags2E8 = ((TrickyState*)state)->flags2E8 | 0x10;
                }
            }
            else
            {
                if (hitEffects != 0)
                {
                    if (((GameObject*)attacker)->anim.classId == 1 || ((GameObject*)attacker)->anim.classId == 0x2d)
                    {
                        if ((((TrickyState*)state)->controlFlags & 0x200) != 0)
                        {
                            if (fxC >= lbl_803E2590 && fxC <= lbl_803E256C)
                            {
                                ((TrickyState*)state)->base = fxC;
                            }
                            zero = lbl_803E2574;
                            ((GameObject*)obj)->anim.velocityX = zero;
                            ((GameObject*)obj)->anim.velocityY = zero;
                            if ((((TrickyState*)state)->flags2DC & 0x40) != 0)
                            {
                                ((GameObject*)obj)->anim.velocityZ = lbl_803E2594 * fxB;
                            }
                            else
                            {
                                ((GameObject*)obj)->anim.velocityZ = fxB;
                            }
                            vecRotateZXY(obj, (void*)(obj + 0x24));
                        }
                    }
                }
                ((TrickyState*)state)->freezeRecoverTimer += lbl_803E2598 * (f32)(int)hitCount;
                if ((((TrickyState*)state)->flags2DC & 0x4000) != 0)
                {
                    ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC | 0x10;
                }
                if ((((TrickyState*)state)->flags2DC & 0x40) == 0)
                {
                    ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC | 0x4000;
                }
                ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC | 0x20;
                dp = delta;
                dp[0] = ((GameObject*)obj)->anim.worldPosX - hitPos.x;
                dp[1] = ((GameObject*)obj)->anim.worldPosY - hitPos.y;
                dp[2] = ((GameObject*)obj)->anim.worldPosZ - hitPos.z;
                diff = (u16)getAngle(-dp[0], -dp[2]) - (u16)((GameObject*)obj)->anim.rotX;
                if (diff > 0x8000)
                {
                    diff -= 0xffff;
                }
                if (diff < -0x8000)
                {
                    diff += 0xffff;
                }
                sector = (u32)(u16)
                diff >> 13;
                hDist = sqrtf(dp[0] * dp[0] + dp[2] * dp[2]);
                vDist = sqrtf(dp[1] * dp[1]);
                switch (((GameObject*)obj)->anim.seqId)
                {
                case 0x11:
                case 0x13a:
                case 0x5b7:
                case 0x5b8:
                case 0x5b9:
                case 0x5e1:
                case 0x7a6:
                    result = fn_801504F8(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector, hDist, vDist);
                    break;
                case 0xd8:
                case 0x281:
                    fn_80152004(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x613:
                    fn_80152440(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x642:
                    fn_80152B2C(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x3fe:
                case 0x7c6:
                    fn_80152FA8(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x58b:
                    fn_80153790(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x369:
                    fn_80153CF8(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x251:
                    fn_801544E8(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x25d:
                    rachnopUpdateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x4d7:
                    wbUpdateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x457:
                    baddieUpdateWhileFrozen_80155e10(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x458:
                    mutatedEbaUpdateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x851:
                    crawler_nop(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x842:
                case 0x84b:
                    crawler_handleReactionEvent(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x4ac:
                    hoodedZyckUpdateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x427:
                    fn_8014FEF8(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x6a2:
                case 0x6a3:
                case 0x6a4:
                case 0x6a5:
                    crawler_onHit(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x7c8:
                    crawler_handleHitStateEvent(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                default:
                    fn_8014FEF8(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                }
            }
        }
        else
        {
            if ((((TrickyState*)state)->flags2DC & 0x40000000) != 0)
            {
                ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC & ~0x4000LL;
            }
        }
        if ((((TrickyState*)state)->flags2E8 & 0x208) != 0)
        {
            params.pos.x = hitPos.x;
            params.pos.y = hitPos.y;
            params.pos.z = hitPos.z;
            if (*(void**)&((TrickyState*)state)->light == NULL)
            {
                ((TrickyState*)state)->light = objCreateLight(0, 1);
            }
            if ((((TrickyState*)state)->flags2E8 & 0x200) != 0)
            {
                objLightFn_8009a1dc((void*)obj, lbl_803E259C, &params, 1, (void*)((TrickyState*)state)->light);
            }
            else if ((((TrickyState*)state)->flags2F1 & 0x10) != 0)
            {
                objLightFn_8009a1dc((void*)obj, lbl_803E259C, &params, 3, (void*)((TrickyState*)state)->light);
            }
            else if ((((TrickyState*)state)->flags2F1 & 8) != 0)
            {
                objLightFn_8009a1dc((void*)obj, lbl_803E259C, &params, 2, (void*)((TrickyState*)state)->light);
            }
            else
            {
                objLightFn_8009a1dc((void*)obj, lbl_803E259C, &params, 1, (void*)((TrickyState*)state)->light);
            }
            Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
        }
        ((TrickyState*)state)->freezeEffectTimer -= timeDelta;
        if (((TrickyState*)state)->freezeEffectTimer < *(f32*)&lbl_803E2574)
        {
            ((TrickyState*)state)->freezeEffectTimer = lbl_803E2574;
        }
        if ((((TrickyState*)state)->flags2E8 & 0x10) != 0)
        {
            if (((TrickyState*)state)->freezeEffectTimer <= lbl_803E2574)
            {
                params.pos.x = hitPos.x;
                params.pos.y = hitPos.y;
                params.pos.z = hitPos.z;
                params.scale = lbl_803E256C;
                params.rot[2] = 0;
                params.rot[1] = 0;
                params.rot[0] = 0;
                if (lbl_803DDA50 != NULL)
                {
                    ((void (**)(int, int, void*, int, int, void*))*(int*)lbl_803DDA50)[1](
                        0, 1, &params, 0x401, -1, &colors);
                }
                ((TrickyState*)state)->freezeEffectTimer = lbl_803E25A0;
                if (*(void**)&((TrickyState*)state)->light == NULL)
                {
                    ((TrickyState*)state)->light = objCreateLight(0, 1);
                }
                objLightFn_8009a1dc((void*)obj, lbl_803E259C, &params, 4, (void*)((TrickyState*)state)->light);
            }
            proj = *(u8**)&((TrickyState*)state)->actionTargetObj;
            if (proj != NULL && ((GameObject*)proj)->anim.classId == 1)
            {
                fn_802961FC(proj, result);
            }
        }
        else if ((((TrickyState*)state)->flags2E8 & 0x20) != 0)
        {
            if (((FrozenByte2F6*)((TrickyState*)state)->pad2F6)->fadeCounter == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fox_kick2);
                ((FrozenByte2F6*)((TrickyState*)state)->pad2F6)->fadeCounter = 0x1f;
            }
            Obj_StartModelFadeIn(obj, 0x12c);
        }
        else
        {
            if (((FrozenByte2F6*)((TrickyState*)state)->pad2F6)->fadeCounter != 0)
            {
                ((FrozenByte2F6*)((TrickyState*)state)->pad2F6)->fadeCounter--;
            }
        }
        ((TrickyState*)state)->flags2E8 = ((TrickyState*)state)->flags2E8 & 0xfffffdc7;
    }
}

void baddieInstantiateWeapon(int obj, int state)
{
    int parentSetup;
    void* child;
    int setup;

    parentSetup = *(int*)&((GameObject*)obj)->anim.placementData;
    if ((*(s16*)&((TrickyState*)state)->currentTime != *(s16*)(state + 0x2b6)) &&
        (((GameObject*)obj)->anim.alpha != 0))
    {
        if (((GameObject*)obj)->childObjs[0] != NULL)
        {
            child = ((GameObject*)obj)->childObjs[0];
            ObjLink_DetachChild(obj, child);
            Obj_FreeObject((int)child);
        }
        if (Obj_IsLoadingLocked() != 0)
        {
            if (*(s16*)(state + 0x2b6) > 0)
            {
                setup = Obj_AllocObjectSetup(0x20, *(s16*)(state + 0x2b6));
                *(u8*)(setup + 5) = *(u8*)(setup + 5) | (((BaddieInstantiateWeaponPlacement*)parentSetup)->unk5 & 0x18);
                child = (void*)Obj_SetupObject(setup, 4, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                               *(int*)&((GameObject*)obj)->anim.parent);
                ObjLink_AttachChild(obj, child, 0);
                *(s16*)&((TrickyState*)state)->currentTime = *(s16*)(state + 0x2b6);
            }
        }
        else
        {
            *(s16*)&((TrickyState*)state)->currentTime = 0;
        }
    }
}

u8 baddieTargetFn_8014a150(int obj, int state, void* from, void* to)
{
    u8 traceHit[4];
    s16 toGrid[4];
    s16 fromGrid[4];
    Vec probe;
    Vec delta;
    u8 bboxHit[TRICKY_BBOX_HIT_SCRATCH_SIZE];
    s16 setupId;
    u8 visible;
    int keepGroundOffset;

    traceHit[0] = 0;
    visible = 0;
    if (((TrickyState*)state)->actionTargetObj != 0)
    {
        probe.x = *(f32*)((int)from + 0);
        probe.y = *(f32*)((int)from + 4);
        probe.z = *(f32*)((int)from + 8);
        keepGroundOffset = 1;
        setupId = ((GameObject*)obj)->anim.seqId;
        if (((((setupId != 0x613) && (setupId != 0x642)) && (setupId != 0x3fe)) &&
                ((setupId != 0x7c6) && (setupId != 0x7c8))) &&
            ((setupId != 0x251) && (setupId != 0x851)))
        {
            probe.y += lbl_803E25A0;
            keepGroundOffset = 0;
        }
        voxmaps_worldToGrid(&probe, fromGrid);
        probe.x = *(f32*)((int)to + 0);
        probe.y = lbl_803E25A0 + *(f32*)((int)to + 4);
        probe.z = *(f32*)((int)to + 8);
        voxmaps_worldToGrid(&probe, toGrid);
        PSVECSubtract((Vec*)from, &probe, &delta);
        if (PSVECMag(&delta) < enemySightRange)
        {
            if (*(u32*)&((GameObject*)obj)->anim.parent == 0)
            {
                visible = voxmaps_traceLine(toGrid, fromGrid, 0, traceHit, 0);
            }
            if ((keepGroundOffset == 0) && (traceHit[0] == 1))
            {
                visible = 1;
            }
        }
    }
    if ((visible != 0) && ((((TrickyState*)state)->controlFlags & TRICKY_CONTROL_FLAG_BBOX_BLOCKS_SIGHT) != 0))
    {
        if (objBboxFn_800640cc((Vec*)from, &probe, lbl_803E256C, 0, bboxHit, obj, ((TrickyState*)state)->unk261,
                               -1, 0, 0) != 0)
        {
            visible = 0;
        }
    }
    return visible;
}

void baddieFn_8014a304(int obj, int state, f32 radius)
{
    u8 traceHit[4];
    s16 probeGrid[4];
    s16 baseGrid[4];
    Vec probe;
    u32 visibilityBits[4];
    Vec delta;
    u8 bboxHit[TRICKY_BBOX_HIT_SCRATCH_SIZE];
    s16 baseAngle;
    u16 i;
    u8 visible;
    f32 angle;
    s16 setupId;

    *(struct VisBits16*)&visibilityBits[0] = *(struct VisBits16*)&gTrickyVisibilityBitsInit[0];
    probe.x = ((GameObject*)obj)->anim.localPosX;
    probe.y = lbl_803E25A0 + ((GameObject*)obj)->anim.localPosY;
    probe.z = ((GameObject*)obj)->anim.localPosZ;
    voxmaps_worldToGrid(&probe, baseGrid);
    if (*(u32*)&((GameObject*)obj)->anim.parent != 0)
    {
        baseAngle = *(s16*)obj + **(s16**)&((GameObject*)obj)->anim.parent;
    }
    else
    {
        baseAngle = *(s16*)obj;
    }
    for (i = 0; i < 4; i++)
    {
        angle = (lbl_803E25B4 * (f32)(s32)((s32)baseAngle + ((u32)(u16)i << 0xe))
        )
        /
        lbl_803E25B8;
        probe.x = ((GameObject*)obj)->anim.worldPosX - (radius * mathSinf(angle));
        probe.y = ((GameObject*)obj)->anim.worldPosY;
        probe.z = ((GameObject*)obj)->anim.worldPosZ - (radius * mathCosf(angle));
        setupId = ((GameObject*)obj)->anim.seqId;
        if (((((setupId != 0x613) && (setupId != 0x642)) && (setupId != 0x3fe)) &&
                ((setupId != 0x7c6) && (setupId != 0x7c8))) &&
            ((setupId != 0x251) && (setupId != 0x851)))
        {
            probe.y += lbl_803E25A0;
        }
        voxmaps_worldToGrid(&probe, probeGrid);
        PSVECSubtract((Vec*)(obj + 0x18), &probe, &delta);
        if (PSVECMag(&delta) < enemySightRange)
        {
            if (*(u32*)&((GameObject*)obj)->anim.parent != 0)
            {
                visible = 1;
            }
            else
            {
                visible = voxmaps_traceLine(probeGrid, baseGrid, 0, traceHit, 0);
                if (traceHit[0] == 1)
                {
                    visible = 1;
                }
            }
        }
        else
        {
            visible = 0;
        }
        if ((visible != 0) && ((((TrickyState*)state)->controlFlags & TRICKY_CONTROL_FLAG_BBOX_BLOCKS_SIGHT) != 0))
        {
            if (objBboxFn_800640cc((Vec*)(obj + 0x18), &probe, lbl_803E256C, 0, bboxHit, obj,
                                   ((TrickyState*)state)->unk261, -1, 0, 0) != 0)
            {
                visible = 0;
            }
        }
        if (visible != 0)
        {
            ((TrickyState*)state)->flags2DC |= visibilityBits[i];
        }
        else
        {
            ((TrickyState*)state)->flags2DC &= ~visibilityBits[i];
        }
    }
}

void Tricky_findNearbyFloorHeights(int obj, int state, f32* nearestFloorY, f32* nearestSpecialY);

void Tricky_applyFloorResponse(int obj, int state)
{
    f32 nearestFloorY;
    f32 nearestSpecialY;
    f32 points[6];
    u32 flags;
    f32 dy;

    ((TrickyState*)state)->flags2DC &= 0xf7efffff;
    flags = ((TrickyState*)state)->controlFlags;
    if ((flags & TRICKY_CONTROL_FLAG_FLOOR_RESPONSE_MASK) != 0)
    {
        Tricky_findNearbyFloorHeights(obj, state, &nearestFloorY, &nearestSpecialY);
        flags = ((TrickyState*)state)->controlFlags;
        if ((flags & TRICKY_CONTROL_FLAG_USE_SPECIAL_FLOOR_Y) != 0)
        {
            f32 sd = nearestSpecialY - ((GameObject*)obj)->anim.localPosY;
            ((GameObject*)obj)->anim.velocityY = sd * oneOverTimeDelta;
        }
        else if ((flags & TRICKY_CONTROL_FLAG_OFFSET_FLOOR_Y) != 0)
        {
            f32 dy = nearestFloorY - ((GameObject*)obj)->anim.localPosY;
            if ((dy > lbl_803E25BC) && (dy < lbl_803E25A0))
            {
                f32 od = lbl_803E25C0 + dy;
                ((GameObject*)obj)->anim.velocityY = od * oneOverTimeDelta;
                ((TrickyState*)state)->flags2DC |= TRICKY_STATE2DC_FLAG_FLOOR_OFFSET_APPLIED;
            }
        }
        else
        {
            f32 dy = nearestFloorY - ((GameObject*)obj)->anim.localPosY;
            if ((dy > lbl_803E25BC) && (dy < lbl_803E25A0))
            {
                ((GameObject*)obj)->anim.velocityY = dy * oneOverTimeDelta;
                ((TrickyState*)state)->flags2DC |= TRICKY_STATE2DC_FLAG_FLOOR_SNAP_APPLIED;
            }
        }
        if ((((TrickyState*)state)->controlFlags & TRICKY_CONTROL_FLAG_BBOX_BLOCKS_SIGHT) == 0)
        {
            ((TrickyState*)state)->physicsActive = 0;
        }
    }
    else
    {
        if ((flags & 0xc) != 0)
        {
            ((TrickyState*)state)->physicsActive = 1;
        }
        else
        {
            ((TrickyState*)state)->physicsActive = 0;
        }
    }

    (*gPathControlInterface)->update((void*)obj, (void*)(state + 4), timeDelta);
    if ((((TrickyState*)state)->controlFlags & 4) != 0)
    {
        (*gPathControlInterface)->apply((void*)obj, (void*)(state + 4));
    }
    (*gPathControlInterface)->advance((void*)obj, (void*)(state + 4), timeDelta);

    if (((*(s8*)&((TrickyState*)state)->physicsActive != 0) &&
            ((((TrickyState*)state)->controlFlags & TRICKY_CONTROL_FLAG_FLOOR_RESPONSE_MASK) == 0)) &&
        ((*(s8*)&((TrickyState*)state)->surfaceFlags & TRICKY_SURFACE_FLAG_HAS_NEARBY_FLOOR) != 0))
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E2574;
        ((TrickyState*)state)->flags2DC |= TRICKY_STATE2DC_FLAG_FLOOR_SNAP_APPLIED;
    }
    if ((((TrickyState*)state)->controlFlags & 0x00200000) != 0)
    {
        ObjPath_GetPointWorldPositionArray(obj, 2, 2, points);
        objAudioFn_8006edcc(obj, ((TrickyState*)state)->animEventMask, 7, points, (void*)(state + 4),
                            ((TrickyState*)state)->unk310, lbl_803E256C);
    }
}

void Tricky_findNearbyFloorHeights(int obj, int state, f32* nearestFloorY, f32* nearestSpecialY)
{
    int hitList[2];
    u16 hitCount;
    u16 i;
    f32* hit;
    f32 hitY;
    f32 zero;
    f32 nearestSpecialDelta;
    f32 nearestFloorDelta;
    f32 dy;
    f32 absDy;
    f32 defaultY;

    defaultY = lbl_803E25C4;
    *nearestFloorY = defaultY;
    *nearestSpecialY = defaultY;
    hitCount = (u16)hitDetectFn_80065e50(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                    ((GameObject*)obj)->anim.localPosZ, obj, hitList, 0, 0);
    *nearestFloorY = ((GameObject*)obj)->anim.localPosY;
    *nearestSpecialY = ((GameObject*)obj)->anim.localPosY;
    nearestSpecialDelta = nearestFloorDelta = lbl_803E25C8;
    i = 0;
    ((TrickyState*)state)->flags2DC &= ~TRICKY_STATE2DC_FLAG_SPECIAL_FLOOR_FOUND;
    zero = lbl_803E2574;
    ((TrickyState*)state)->nearestSpecialDeltaY = zero;
    *(s8*)&((TrickyState*)state)->surfaceFlags &= ~TRICKY_SURFACE_FLAG_HAS_NEARBY_FLOOR;
    for (; i < hitCount; i++)
    {
        hit = *(f32**)(hitList[0] + ((u32)i << 2));
        hitY = hit[0];
        dy = hitY - ((GameObject*)obj)->anim.localPosY;
        absDy = dy;
        if (dy < zero)
        {
            absDy = -dy;
        }
        if (*(s8*)(hit + 5) == 0xe)
        {
            if (absDy < nearestSpecialDelta)
            {
                ((TrickyState*)state)->nearestSpecialDeltaY = dy;
                *(s8*)&((TrickyState*)state)->surfaceFlags |= TRICKY_SURFACE_FLAG_HAS_NEARBY_FLOOR;
                nearestSpecialDelta = absDy;
                *nearestSpecialY = **(f32**)(hitList[0] + ((u32)i << 2));
                if (((TrickyState*)state)->nearestSpecialDeltaY > lbl_803E25A0)
                {
                    ((TrickyState*)state)->flags2DC |= (TRICKY_STATE2DC_FLAG_SPECIAL_FLOOR_FOUND | TRICKY_STATE2DC_FLAG_FLOOR_SNAP_APPLIED);
                }
            }
        }
        else if (absDy < nearestFloorDelta)
        {
            *nearestFloorY = hitY;
            *(s8*)&((TrickyState*)state)->surfaceFlags |= TRICKY_SURFACE_FLAG_HAS_NEARBY_FLOOR;
            nearestFloorDelta = absDy;
        }
    }
}

void Tricky_render(int obj, int p2, int p3, int p4, int p5, char doRender)
{
    u8 mode;
    int i;
    int pathState;
    int pathPoint;
    int pathInfo;
    int state;

    if (doRender != '\0')
    {
        state = *(int*)&((GameObject*)obj)->extra;
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E23E8);
        pathState = *(int*)&((GameObject*)obj)->extra;
        i = 0;
        pathPoint = pathState;
        do
        {
            ObjPath_GetPointWorldPosition(obj, i + 4, (float*)(pathPoint + 0x3d8),
                                          (u32*)(pathPoint + 0x3dc), (float*)(pathPoint + 0x3e0), 0);
            pathPoint = pathPoint + 0xc;
            i = i + 1;
        }
        while (i < 4);
        ObjPath_GetPointWorldPosition(obj, 8, (float*)(pathState + 0x408),
                                      (u32*)(pathState + 0x40c), (float*)(pathState + 0x410), 0);
        pathInfo = objModelGetVecFn_800395d8(obj, 0);
        *(s16*)(pathState + 0x414) = *(s16*)(pathInfo + 2);
        if ((((TrickyState*)state)->stateFlags & 0x10) != 0)
        {
            switch (((TrickyState*)state)->unk08)
            {
            case 2:
                fn_8013ADFC(obj);
                break;
            case 3:
                if (((TrickyState*)state)->substate == 4)
                {
                    fn_8013ADFC(obj);
                }
                break;
            }
            if ((((((TrickyState*)state)->stateFlags & 0x200) == 0) && (((TrickyState*)state)->unk08 == 0xb)) &&
                (((TrickyState*)state)->substate >= 3))
            {
                if (((TrickyState*)state)->substate != 3)
                {
                    ((GameObject*)((TrickyState*)state)->unk700)->anim.localPosX = ((TrickyState*)state)->renderPosX;
                    ((GameObject*)((TrickyState*)state)->unk700)->anim.localPosY = ((TrickyState*)state)->renderPosY;
                    ((GameObject*)((TrickyState*)state)->unk700)->anim.localPosZ = ((TrickyState*)state)->renderPosZ;
                }
                objRenderFn_8003b8f4(*(int*)&((TrickyState*)state)->unk700, p2, p3, p4, p5,
                                     lbl_803E23E8);
            }
        }
        Tricky_emitQueuedPathParticles(obj, state);
        ObjPath_GetPointWorldPositionArray(obj, 4, 4, (float*)((TrickyState*)state)->pad7D8);
        ((TrickyState*)state)->unk838 = ((TrickyState*)state)->unk838 - timeDelta;
        if (((TrickyState*)state)->unk838 > lbl_803E23DC)
        {
            objParticleFn_80099d84(obj, lbl_803E253C, 6, lbl_803E23E8, 0);
        }
    }
    return;
}

void Tricky_hitDetect(int obj)
{
    f32 dy;
    f32 y;
    int* objects;
    int i;
    void* firepipeObj;
    int state;
    f32 height;
    int count[2];

    state = *(int*)&((GameObject*)obj)->extra;
    y = ((GameObject*)obj)->anim.localPosY;
    dy = (y - ((GameObject*)obj)->anim.previousLocalPosY >= lbl_803E23DC)
             ? y - ((GameObject*)obj)->anim.previousLocalPosY
             : -(y - ((GameObject*)obj)->anim.previousLocalPosY);
    if (lbl_803E23E8 == dy)
    {
        if (y == ((GameObject*)obj)->anim.worldPosY)
        {
            ((TrickyStatusFlags58*)&((TrickyState*)state)->statusFlags)->heightTracking = 1;
            *(s32*)&((TrickyState*)state)->heightTrackObjId = -1;
            ((TrickyState*)state)->trackedHeight = lbl_803E23DC;
        }
    }
    else
    {
        firepipeObj = ObjList_FindObjectById(TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID);
        if ((firepipeObj != 0) &&
            (getXZDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)((int)firepipeObj + 0x18)) < lbl_803E2540))
        {
            ((TrickyStatusFlags58*)&((TrickyState*)state)->statusFlags)->heightTracking = 1;
            ((TrickyState*)state)->heightTrackObjId = TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID;
            ((TrickyState*)state)->trackedHeight = lbl_803E23DC;
        }
    }
    if ((((TrickyState*)state)->statusFlags >> 5 & 1) != 0u)
    {
        {
            int* t = ObjGroup_GetObjects(TRICKY_HEIGHT_TRACK_GROUP, count);
            i = 0;
            objects = t;
        }
        for (; i < count[0]; i++)
        {
            height = objFn_801948c0(*objects,TRICKY_HEIGHT_TRACK_MODEL_SLOT);
            if (*(s32*)&((TrickyState*)state)->heightTrackObjId == -1)
            {
                dy = (height - ((GameObject*)obj)->anim.localPosY >= lbl_803E23DC)
                         ? height - ((GameObject*)obj)->anim.localPosY
                         : -(height - ((GameObject*)obj)->anim.localPosY);
                if (dy < lbl_803E24B8)
                {
                    ((TrickyState*)state)->heightTrackObjId = *(u32*)(*(int*)(*objects + 0x4c) + 0x14);
                }
            }
            if (((TrickyState*)state)->heightTrackObjId == *(u32*)(*(int*)(*objects + 0x4c) + 0x14))
            {
                if ((((TrickyState*)state)->trackedHeight != lbl_803E23DC) &&
                    (((TrickyState*)state)->trackedHeight == height))
                {
                    ((TrickyStatusFlags58*)&((TrickyState*)state)->statusFlags)->heightTracking = 0;
                }
                else
                {
                    ((GameObject*)obj)->anim.localPosY = height;
                    ((TrickyState*)state)->trackedHeight = height;
                }
                break;
            }
            objects = objects + 1;
        }
        if (i == count[0])
        {
            ((TrickyStatusFlags58*)&((TrickyState*)state)->statusFlags)->heightTracking = 0;
        }
    }
    return;
}

void FUN_80146fa0(void)
{
    return;
}

void FUN_80147884(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8,
                  u32 unused9, u32 unused10, float* pointA, float* pointB)
{
    short objId;
    bool applyOffset;
    int* target;
    char blocked;
    int player;
    double dist;
    u64 packed;
    char hitFlag[4];
    short screenA[4];
    short screenB[4];
    float delta[3];
    float pointX;
    float pointY;
    float pointZ;
    int hitScratch[29];

    packed = FUN_8028683c();
    target = (int*)((u64)packed >> 0x20);
    player = packed;
    hitFlag[0] = '\0';
    blocked = '\0';
    if (((TrickyState*)player)->actionTargetObj != 0)
    {
        pointX = *pointA;
        pointY = pointA[1];
        pointZ = pointA[2];
        applyOffset = true;
        objId = *(short*)((int)target + 0x46);
        if (((((objId != 0x613) && (objId != 0x642)) && (objId != 0x3fe)) &&
            ((objId != 0x7c6 && (objId != 0x7c8)))) && ((objId != 0x251 && (objId != 0x851))))
        {
            pointY = pointY + lbl_803E3234;
            applyOffset = false;
        }
        FUN_80006a68(&pointX, screenA);
        pointX = *pointB;
        pointY = lbl_803E3234 + pointB[1];
        pointZ = pointB[2];
        FUN_80006a68(&pointX, screenB);
        FUN_80247eb8(pointA, &pointX, delta);
        dist = SeekTwiceBeforeRead(delta);
        if (dist < (double)lbl_803E3244)
        {
            if (target[0xc] == 0)
            {
                blocked = FUN_80006a64(dist, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                     screenB, screenA, (u32*)0x0, hitFlag, 0);
            }
            if ((!applyOffset) && (hitFlag[0] == '\x01'))
            {
                blocked = '\x01';
            }
        }
    }
    if ((blocked != '\0') && ((((TrickyState*)player)->controlFlags & 8) != 0))
    {
        FUN_800620e8(pointA, &pointX, (float*)0x0, hitScratch, target, (u32)((TrickyState*)player)->unk261,
                     0xffffffff, 0, 0);
    }
    FUN_80286888();
    return;
}

int Tricky_getExtraSize(void) { return 0x83c; }

u8 Tricky_func0E(int* obj) { return *((u8*)((int**)obj)[0xb8 / 4][0x0 / 4] + 0x1); }
u8 Tricky_render2(int* obj) { return *((u8*)((int**)obj)[0xb8 / 4][0x0 / 4] + 0x0); }

int Tricky_getCurrentCommandType(int* obj, int* out)
{
    *out = *((s8*)obj[0xb8 / 4] + 0xd);
    return 1;
}

extern u8 Objfsa_GetWalkGroupIndexAtPoint(void* pos, int patchInfo);
extern int Objfsa_GetPatchGroupIdAtPoint(void* pos);
extern int Objfsa_FindNearestEnabledCurveType24(void* pos, int filter4, int filter5);

void trickyFn_801451d8(int obj, int state)
{
    u8 pathBytes[16];
    u32 pathByte = Objfsa_GetWalkGroupIndexAtPoint((void*)(obj + 0x18), 0);

    pathByte = pathByte;
    pathBytes[0] = pathByte;
    if (pathByte == 0)
    {
        int pathId = Objfsa_GetPatchGroupIdAtPoint((void*)(obj + 0x18));
        if (pathId != 0)
        {
            walkPath_writeU16LE(pathId & 0xffff, pathBytes);
        }
    }
    if (pathBytes[0] != 0)
    {
        f32 resetTimer;

        ((TrickyState*)state)->walkGroup = pathBytes[0];
        ((TrickyState*)state)->unk08 = 1;
        ((TrickyState*)state)->substate = 0;
        resetTimer = lbl_803E23DC;
        ((TrickyState*)state)->unk71C = resetTimer;
        ((TrickyState*)state)->unk720 = resetTimer;
        *(u32*)&((TrickyState*)state)->stateFlags = *(u32*)&((TrickyState*)state)->stateFlags & (u64)~0x10u;
        *(u32*)&((TrickyState*)state)->stateFlags = *(u32*)&((TrickyState*)state)->stateFlags & (u64)~0x10000u;
        *(u32*)&((TrickyState*)state)->stateFlags = *(u32*)&((TrickyState*)state)->stateFlags & (u64)~0x20000u;
        *(u32*)&((TrickyState*)state)->stateFlags = *(u32*)&((TrickyState*)state)->stateFlags & (u64)~0x40000u;
        *(s8*)&((TrickyState*)state)->unkD = -1;
    }
    if (gTrickyHelperObject == 0)
    {
        int setup = Obj_AllocObjectSetup(0x18, 0x25);
        gTrickyHelperObject = Obj_SetupObject(setup, 4, -1, -1, *(int*)&((GameObject*)obj)->anim.parent);
    }
    ((TrickyByteFlags*)&((TrickyState*)state)->statusFlags)->bit7 = 1;
}

void Tricky_func11(int* obj)
{
    register u32* p = (u32*)obj[0xb8 / 4];
    if (GameBit_Get(0x4e4))
    {
        p[0x54 / 4] |= 0x10000LL;
    }
}

int Tricky_func13(int* obj)
{
    u8 mode = *((u8*)obj[0xb8 / 4] + 8);
    if (mode == 8 || mode == 0xe) return 1;
    return 0;
}

int Tricky_func12(int* obj)
{
    u8 mode;
    int result;
    mode = *((u8*)obj[0xb8 / 4] + 8);
    switch (mode)
    {
    case 5:
        result = 1;
        break;
    default:
        result = 0;
        break;
    }
    return result;
}

#pragma opt_propagation off
int Tricky_func10(int* obj, int targetObj)
{
    int* state = (int*)obj[0xb8 / 4];
    s32 objBlocked = ((GameObject*)obj)->objectFlags & TRICKY_OBJFLAG_PARENT_SLACK;

    if (objBlocked != 0)
    {
        return 0;
    }
    if (((u32)state[0x54 / 4] & 0x10) == 0)
    {
        state[0x24 / 4] = targetObj;
        if ((void*)state[0x28 / 4] != (void*)(targetObj + 0x18))
        {
            state[0x28 / 4] = targetObj + 0x18;
            {
                u32 m;
                u32 f2 = *(u32*)&state[0x54 / 4];
                m = ~0x400;
                state[0x54 / 4] = f2 & m;
            }
            *(s16*)((u8*)state + 0xd2) = 0;
        }
        *((u8*)state + 10) = 0;
        *((u8*)state + 8) = 10;
    }
    else
    {
        *((u8*)state + 0x7d0) = 1;
        state[0x7d4 / 4] = targetObj;
        *(u32*)&state[0x54 / 4] = *(u32*)&state[0x54 / 4] | 0x10000LL;
    }
    return 1;
}
#pragma opt_propagation reset

#pragma optimization_level 1
void Tricky_func0F(int* obj, int commandEnabled, int targetObj)
{
    register int* state = (int*)obj[0xb8 / 4];

    if (commandEnabled != 0)
    {
        if (*((u8*)state + 8) == 5)
        {
            if (*((u8*)state + 10) != 0)
            {
                state[0x24 / 4] = targetObj;
            }
        }
        else
        {
            u32 busy = state[0x54 / 4] & 0x10;
            void* nextTarget;
            if (busy != 0)
            {
                return;
            }
            state[0x700 / 4] = Objfsa_FindNearestEnabledCurveType24((void*)(targetObj + 0x18), -1, 3);
            *(f32*)((u8*)state + 0x710) = (f32)(int)
            randomGetRange(0x168, 0x28);
            *((u8*)state + 8) = 5;
            state[0x24 / 4] = targetObj;
            nextTarget = (void*)(state[0x700 / 4] + 8);
            if ((void*)state[0x28 / 4] != nextTarget)
            {
                state[0x28 / 4] = (int)nextTarget;
                *(u32*)&state[0x54 / 4] &= ~0x400LL;
                *(s16*)((u8*)state + 0xd2) = 0;
            }
            *((u8*)state + 10) = 0;
        }
    }
    else
    {
        *(u32*)&state[0x54 / 4] |= 0x10000LL;
    }
}
#pragma optimization_level reset

int Tricky_getAvailableCommands(void)
{
    int r = 0;
    if (GameBit_Get(0x4e4) != 0)
    {
        r = 0xa;
        if (GameBit_Get(0xdd) != 0) r |= 0x1;
        if (GameBit_Get(0x25) != 0) r |= 0x20;
        if (GameBit_Get(0x245) != 0) r |= 0x10;
    }
    return r;
}

void trickyReportError(const char* fmt, ...)
{
}

void trickyDebugPrint(const char* fmt, ...)
{
}

extern f32 lbl_803E25A4;
extern f32 lbl_803E2500;
extern f32 lbl_803E2418;

u8* Tricky_findNearestGroup4BObject(u8* obj, TrickyState* state)
{
    int* objs;
    int count[1];
    u8* result;
    f32 d;
    f32 bestD;
    int i;

    result = 0;
    objs = ObjGroup_GetObjects(0x4b, count);
    d = getXZDistance(&((GameObject*)state->playerObj)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
    if ((d >= lbl_803E2538) || (state->unk71C > lbl_803E23DC))
    {
        if (ViewFrustum_IsSphereVisible(&((GameObject*)obj)->anim.localPosX, lbl_803E2500) == 0)
        {
            bestD = lbl_803E2418;
            for (i = 0; i < count[0]; i++)
            {
                f32 cd = getXZDistance((f32*)((char*)state->playerObj + 0x18), (f32*)((char*)*objs + 0x18));
                if (cd < d && cd < bestD)
                {
                    bestD = cd;
                    result = (u8*)*objs;
                }
                objs++;
            }
        }
    }
    return result;
}

void trickyFn_80144f50(int obj, int state)
{
    int sfxState;
    int isInWater;
    u32 sfxDisabled;
    u32 transitionFlag;

    if (trickyFoodFn_8014460c(obj, state) == 0)
    {
        ((TrickyState*)state)->unk72C =
            ((GameObject*)obj)->anim.worldPosX - mathSinf((lbl_803E2454 * (f32) * (s16*)obj) / lbl_803E2458);
        *(f32*)&((TrickyState*)state)->unk730 = ((GameObject*)obj)->anim.worldPosY;
        ((TrickyState*)state)->unk734 =
            ((GameObject*)obj)->anim.worldPosZ - mathCosf((lbl_803E2454 * (f32) * (s16*)obj) / lbl_803E2458);

        if (trickyFn_8013b368(obj, lbl_803E247C, state) != 1)
        {
            ((TrickyState*)state)->unk740 -= timeDelta;
            if (((TrickyState*)state)->unk740 <= lbl_803E23DC)
            {
                ((TrickyState*)state)->unk740 = (f32)(int)
                randomGetRange(0x1f4, 0x2ee);
                sfxState = *(int*)&((GameObject*)obj)->extra;
                sfxDisabled = (*(u8*)(sfxState + 0x58) >> 6) & 1;
                if ((sfxDisabled == 0) &&
                    ((((GameObject*)obj)->anim.currentMove >= 0x30) || (((GameObject*)obj)->anim.currentMove < 0x29)) &&
                    (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0))
                {
                    objAudioFn_800393f8(obj, (void*)(sfxState + 0x3a8), 0x360, 0x500, -1, 0);
                }
            }

            if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
            {
                isInWater = 0;
            }
            else if (lbl_803E2410 == ((TrickyState*)state)->eventTime)
            {
                isInWater = 1;
            }
            else if ((((TrickyState*)state)->currentTime - ((TrickyState*)state)->eventTime) > lbl_803E2414)
            {
                isInWater = 1;
            }
            else
            {
                isInWater = 0;
            }

            if (isInWater)
            {
                objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                ((TrickyState*)state)->unk79C = lbl_803E2440;
                ((TrickyState*)state)->unk838 = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            }
            else
            {
                switch (((GameObject*)obj)->anim.currentMove)
                {
                case 0x31:
                    break;
                case 0xd:
                    transitionFlag = ((TrickyState*)state)->stateFlags & 0x08000000;
                    if (transitionFlag != 0)
                    {
                        objAnimFn_8013a3f0(obj, 0x31, lbl_803E243C, 0);
                    }
                    break;
                default:
                    objAnimFn_8013a3f0(obj, 0xd, lbl_803E2444, 0);
                    break;
                }
                trickyDebugPrint(lbl_8031D478);
            }
        }
    }
}

void frozenEnemyFn_80149bb4(int* obj, u32 flags, f32 f, u16 val)
{
    *((u8*)obj + 0x2f1) = 0;
    if ((flags & 0x2) != 0)
    {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x20);
    }
    if ((flags & 0x1) != 0)
    {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x40);
    }
    if ((flags & 0x4) != 0)
    {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x1);
    }
    if ((flags & 0x8) != 0)
    {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x2);
    }
    if ((flags & 0x10) != 0)
    {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x4);
    }
    if (lbl_803E25A4 == f)
    {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x8);
    }
    else if (lbl_803E2594 == f)
    {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x10);
    }
    if ((flags & 0x80) != 0)
    {
        *((u8*)obj + 0x2f1) = (u8)(*((u8*)obj + 0x2f1) | 0x80);
    }
    if ((flags & 0x100) != 0)
    {
        *((u8*)obj + 0x2f5) = 1;
    }
    else if ((flags & 0x200) != 0)
    {
        *((u8*)obj + 0x2f5) = 2;
    }
    else if ((flags & 0x400) != 0)
    {
        *((u8*)obj + 0x2f5) = 3;
    }
    *(u16*)((char*)obj + 0x2ec) = val;
}

/* pooled sidekick-command debug format strings (embedded NULs), raw bytes. */
char sSidekickCommandDebugTextBlock[] =
{
    0x73, 0x69, 0x64, 0x65, 0x43, 0x6F, 0x6D, 0x6D, 0x61, 0x6E, 0x64, 0x45,
    0x6E, 0x61, 0x62, 0x6C, 0x65, 0x20, 0x77, 0x61, 0x72, 0x6E, 0x69, 0x6E,
    0x67, 0x3A, 0x20, 0x6E, 0x65, 0x65, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x69,
    0x6E, 0x63, 0x72, 0x65, 0x61, 0x73, 0x65, 0x20, 0x4D, 0x41, 0x58, 0x5F,
    0x43, 0x4F, 0x4D, 0x4D, 0x5F, 0x50, 0x52, 0x45, 0x53, 0x45, 0x4E, 0x54,
    0x0A, 0x00, 0x00, 0x00, 0x68, 0x69, 0x74, 0x73, 0x3A, 0x20, 0x25, 0x64,
    0x20, 0x25, 0x64, 0x20, 0x25, 0x64, 0x20, 0x25, 0x64, 0x20, 0x25, 0x64,
    0x20, 0x25, 0x64, 0x20, 0x25, 0x64, 0x20, 0x25, 0x64, 0x00, 0x00, 0x00,
    0x0A, 0x45, 0x6E, 0x65, 0x72, 0x67, 0x79, 0x3A, 0x20, 0x25, 0x64, 0x2F,
    0x25, 0x64, 0x0A, 0x00, 0x66, 0x69, 0x6E, 0x64, 0x20, 0x63, 0x6F, 0x6D,
    0x6D, 0x61, 0x6E, 0x64, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x6F, 0x6E,
    0x20, 0x74, 0x68, 0x65, 0x20, 0x77, 0x72, 0x6F, 0x6E, 0x67, 0x20, 0x6F,
    0x62, 0x6A, 0x65, 0x63, 0x74, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

u8 lbl_8031DBD8[12] = {0};
u8 lbl_8031DBE4[12] = {0};
