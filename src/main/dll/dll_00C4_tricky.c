#include "main/audio/sfx_ids.h"
#include "main/dll/objfx_api.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_limited_object_api.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_play_int_return_legacy_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/object_render_legacy.h"
#include "main/shader_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/objanim.h"
#include "main/objprint_api.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_sound_api.h"
#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/frustum.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/track_bbox_api.h"
#include "main/obj_group.h"
#include "main/obj_path.h"
#include "main/object.h"
#include "main/dll/dll_80136a40.h"
#include "main/object_api.h"
#include "main/model_light.h"
#include "main/objhits.h"
#include "dolphin/mtx.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/dll/dll_00C4_tricky_api.h"
#include "main/dll/cmenu_item_table.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll/baddie_state.h"
#include "main/dll/skeetla_route_api.h"
#include "main/dll/skeetla_anim_api.h"
#include "main/dll/flameblast_api.h"
#include "main/dll/player_api.h"
#include "main/dll/path_control_interface.h"
#include "main/mapEventTypes.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/gameloop_gamebit_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/tricky_state.h"
#include "main/dll/WC/WCbeacon.h"
#include "main/gamebit_ids.h"
#include "main/voxmaps.h"
#include "main/frame_timing.h"
#include "main/track_dolphin_api.h"

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
    s32 childObj; /* 0x700: child flame object handle (per-slot, walked by Tricky_free) */
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

typedef struct PromptSlotByte
{
    u8 slotA : 2;
    u8 slotB : 2;
    u8 unk4 : 4;
} PromptSlotByte;

typedef struct
{
    u8 slotA : 2;
    u8 slotB : 2;
    u8 slotC : 2;
    u8 slotD : 2;
} TrickySlotBits;

typedef void (*TrickyHandlerFn)(int obj, int state);

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

struct TrickyCommandSpawnPair
{
    u32 a;
    u32 b;
};

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

/* group owned by another DLL, queried here */
#define TRICKYWARP_OBJ_GROUP 0x4b /* DLL 0x100 trickywarp */

#define TRICKY_CONTROL_FLAG_BBOX_BLOCKS_SIGHT   0x00000008
#define TRICKY_CONTROL_FLAG_USE_SPECIAL_FLOOR_Y 0x08000000
#define TRICKY_CONTROL_FLAG_OFFSET_FLOOR_Y      0x20000000
#define TRICKY_CONTROL_FLAG_FLOOR_RESPONSE_MASK 0x28000002
#define TRICKY_SURFACE_FLAG_HAS_NEARBY_FLOOR    0x10
/* flags2DC status bits set by the floor-response pass (Tricky_applyFloorResponse /
 * Tricky_findNearbyFloorHeights) to record what floor correction ran this frame. */
#define TRICKY_STATE2DC_FLAG_FLOOR_OFFSET_APPLIED 0x08000000LL /* offset-floor-Y push applied */
#define TRICKY_STATE2DC_FLAG_FLOOR_SNAP_APPLIED   0x00100000LL /* snap-to-floor velocity applied */
#define TRICKY_STATE2DC_FLAG_SPECIAL_FLOOR_FOUND  0x10000000LL /* a nearby type-0xe special floor was found */
/* stateFlags movement-enable bits: each gates applying its matching per-frame
 * position delta (backstepDelta / verticalDelta / sidestepDelta) or the
 * rotate-toward-target interpolation in the per-frame update. */
#define TRICKY_STATE_FLAG_SIDESTEP      0x20  /* apply sidestepDelta lateral offset */
#define TRICKY_STATE_FLAG_BACKSTEP      0x40  /* apply backstepDelta offset */
#define TRICKY_STATE_FLAG_VERTICAL_MOVE 0x80  /* apply verticalDelta to localPosY */
#define TRICKY_STATE_FLAG_ROTATE        0x100 /* interpolate rotation toward targetYaw target */
/* stateFlags flame-particle child bookkeeping: 0x800 marks the 7 flame children
 * as spawned; on teardown it is cleared and 0x1000 is set. */
#define TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE  0x800  /* 7 flame child objects are spawned */
#define TRICKY_STATE_FLAG_FLAME_CHILDREN_CLEANUP 0x1000 /* flame children torn down this cycle */
/* GameObject.objectFlags bit (distinct field from stateFlags above). */
#define TRICKY_OBJFLAG_PARENT_SLACK            0x1000
#define TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID 0x46406
#define TRICKY_HEIGHT_TRACK_GROUP              0x51
#define TRICKY_OBJGROUP                        1
#define TRICKY_HEIGHT_TRACK_MODEL_SLOT         3
#define TRICKY_BBOX_HIT_SCRATCH_SIZE           84
/* ObjPlacement offsets read by the defeat handler to fire the baddie's
 * death gamebits. */
#define BADDIE_PLACEMENT_DEATH_GAMEBIT          0x18 /* s16: gamebit incremented on defeat */
#define BADDIE_PLACEMENT_CLEAR_ON_DEATH_GAMEBIT 0x1a /* s16: gamebit cleared on defeat */

extern u64 ObjLink_DetachChild();
extern u64 ObjLink_AttachChild();
extern void freeAndNull(void* p);
extern void trickyVoxAllocFn_8004b5d4(void* out);
extern void objAudioFn_8006edcc(int obj, u16 mask, int arg5, float* points, void* aux, f32 scaleX, f32 scaleY);
extern void objAudioFn_8006ef38(int obj, int joint, int pointCount, int pathPoints, int scratch, f32 scaleX,
                                f32 scaleY);
extern void doNothing_onTrickyFree(void);
extern void doNothing_onTrickyInit(void);
extern void walkgroupFindExitPointFn_800dc398(void);
extern void objAnimFreeChildren(int a, int b, GameObject** c);
extern int trickyFoodFn_8014460c(GameObject* obj, int state);
extern int trickyFindNearestUsableBaddie(int p1, f32 maxRadius, int p2);
extern void skeetla_spawnLinkedSparks(int obj);
extern void Tricky_emitQueuedPathParticles(int obj, int state);
extern int trickyFn_8013b368();
extern f32 objFn_801948c0(int obj, int coord);
extern int fn_80296240(GameObject* obj);
__declspec(section ".rodata") u32 gTrickyVisibilityBitsInit[4] = {0x10000, 0x20000, 0x40000, 0x80000};
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
extern u16 lbl_803E23C0;
extern f32 lbl_803E24B8;
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

extern int fn_80138D7C(int obj, int state);
extern void Tricky_updateBlendChannelWeight(int obj, int state);
extern u8 Objfsa_GetWalkGroupIndexAtPoint(void* pos, int patchInfo);
extern int Objfsa_GetPatchGroupIdAtPoint(void* pos);
extern int Objfsa_FindNearestEnabledCurveType24(void* pos, int filter4, int filter5);
extern f32 lbl_803E25A4;
extern f32 lbl_803E2500;
__declspec(section ".rodata") int gTrickyFrozenFxColors[4] = {0x08, 0xFF, 0xFF, 0x78};
extern int* lbl_803DDA50;
extern f32 lbl_803E2588;
extern f32 lbl_803E258C;
extern f32 lbl_803E2590;
extern f32 lbl_803E2594;
extern f32 lbl_803E259C;
extern void fn_802972B4(GameObject* player, u32* outEffects, f32* outA, f32* outB, f32* outC, u16* outSfx);
extern void fn_802961FC(u8* proj, int result);
extern int sidekickToy_handleHitMessage(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                        int sector, f32 hDist, f32 vDist);
extern void guardClawUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                       int sector);
extern void gcRobotPatrol_updateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                            int sector);
extern void mikaladon_updateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                        int sector);
extern void vambat_updateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                     int sector);
extern void kooshy_updateWhileFrozen(GameObject* obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                     int sector);
extern void weevil_updateWhileFrozen(GameObject* obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                     int sector);
extern void Baddie_HandleHitReaction(GameObject* obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                     int sector);
extern void rachnopUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                     int sector);
extern void wbUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
extern void baddieUpdateWhileFrozen_80155e10(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                             int sector);
extern void mutatedEbaUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                        int sector);
extern void whirlpool_updateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                        int sector);
extern void snowworm_updateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                       int sector);
extern void hoodedZyckUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                        int sector);
extern void battleDroidUpdateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                         int sector);
extern void crawler_onHit(GameObject* obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos, int sector);
extern void hagabonMK2_updateWhileFrozen(int obj, u8* state, int attacker, int hit, int p5, int p6, Vec* hitPos,
                                         int sector);
extern int gTrickyCmdQueryInit[];
extern TrickySfxPair lbl_803E23C4;
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
extern void fn_801B17F4(GameObject*);
extern void fn_801B6D40(void);
extern void fn_801FD4A8(GameObject*);
extern void fn_801B0784(GameObject*);
extern void drchimmey_countdownCallback(void);
extern void fn_801DA9CC(GameObject*);
extern void fn_8003B228(GameObject* obj, void* p);

#pragma explicit_zero_data on
__declspec(section ".sdata2") u16 gSkeetlaFootstepSfxId2 = 0x355;
__declspec(section ".sdata2") f32 lbl_803E23DC = 0.0f;
__declspec(section ".sdata2") f32 lbl_803E23E0 = 10.0f;
__declspec(section ".sdata2") f32 lbl_803E23E4 = 0.004f;
__declspec(section ".sdata2") f32 lbl_803E23E8 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E23EC = 0.01f;
__declspec(section ".sdata2") f32 lbl_803E23F0 = 0.7f;
__declspec(section ".sdata2") f32 lbl_803E23F4 = -0.01f;
__declspec(section ".sdata2") f32 lbl_803E23F8 = 2.0f;
__declspec(section ".sdata2") f64 lbl_803E2400 = 4503599627370496.0;
__declspec(section ".sdata2") f32 lbl_803E2408 = 20.0f;
__declspec(section ".sdata2") f32 lbl_803E240C = 196.0f;
__declspec(section ".sdata2") f32 lbl_803E2410 = -100000.0f;
__declspec(section ".sdata2") f32 lbl_803E2414 = 8.0f;
__declspec(section ".sdata2") f32 lbl_803E2418 = 3.4028235e38f;
__declspec(section ".sdata2") f32 lbl_803E241C = -0.15f;
__declspec(section ".sdata2") f32 lbl_803E2420 = 0.05f;
__declspec(section ".sdata2") f32 lbl_803E2424 = 100.0f;
__declspec(section ".sdata2") f32 lbl_803E2428 = -0.17f;
__declspec(section ".sdata2") f32 lbl_803E242C = 40.0f;
__declspec(section ".sdata2") f32 lbl_803E2430 = 400.0f;
__declspec(section ".sdata2") f32 lbl_803E2434 = 0.014f;
__declspec(section ".sdata2") f32 lbl_803E2438 = 300.0f;
__declspec(section ".sdata2") f32 lbl_803E243C = 0.02f;
__declspec(section ".sdata2") f32 lbl_803E2440 = 600.0f;
__declspec(section ".sdata2") f32 lbl_803E2444 = 0.005f;
__declspec(section ".sdata2") f32 lbl_803E2448 = -2.0f;
__declspec(section ".sdata2") f32 lbl_803E244C = 1.5f;
__declspec(section ".sdata2") f32 lbl_803E2450 = 512.0f;
__declspec(section ".sdata2") f32 lbl_803E2454 = 3.1415927f;
__declspec(section ".sdata2") f32 lbl_803E2458 = 32768.0f;
#pragma explicit_zero_data off

void frozenEnemyFn_80149bb4(int* obj, u32 flags, f32 f, u16 val);
void Tricky_findNearbyFloorHeights(GameObject* obj, int state, f32* nearestFloorY, f32* nearestSpecialY);

int tricky_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int state;
    int i;
    int slot;
    int j;
    int k;
    u8* p;
    int setup;
    u8 blockFlags[120];

    state = *(int*)&((GameObject*)obj)->extra;
    if ((((TrickyState*)state)->stateFlags & 0x200) == 0)
    {
        ObjHits_DisableObject(obj);
        Sfx_StopObjectChannel(obj, 0x7f);
        if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE) != 0)
        {
            ((TrickyState*)state)->stateFlags =
                ((TrickyState*)state)->stateFlags & ~(u64)TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE;
            ((TrickyState*)state)->stateFlags =
                ((TrickyState*)state)->stateFlags | TRICKY_STATE_FLAG_FLAME_CHILDREN_CLEANUP;
            for (k = 0, slot = state; k < 7; slot = slot + 4, k = k + 1)
            {
                objSetAnimSpeedTo1((GameObject*)*(int*)(slot + 0x700));
            }
            Sfx_RemoveLoopedObjectSoundIntLegacy(obj, SFXTRIG_trpopn_c);
            slot = *(int*)&((GameObject*)obj)->extra;
            if ((((TrickyByteFlags*)(slot + 0x58))->bit6 == 0) &&
                (((((GameObject*)obj)->anim.currentMove >= 0x30 || (((GameObject*)obj)->anim.currentMove < 0x29)) &&
                  (Sfx_IsPlayingFromObjectChannelIntLegacy(obj, 0x10) == 0))))
            {
                objAudioFn_800393f8Legacy(obj, (void*)(slot + 0x3a8), 0x29d, 0, 0xffffffff, 0);
            }
        }
        Sfx_RemoveLoopedObjectSoundIntLegacy(obj, SFXTRIG_trwhin1);
        ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 0x200;
        if ((animUpdate->hitVolumePair & 3) == 0)
        {
            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags | 0x4000;
        }
        if (((TrickyByteFlags*)&((TrickyState*)state)->unk82E)->bit5 == 0)
        {
            ObjModel_ClearBlendChannels(Obj_GetActiveModel((GameObject*)obj));
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
                ((TrickyState*)state)->stateFlags &= ~(u64)TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE;
                ((TrickyState*)state)->stateFlags |= TRICKY_STATE_FLAG_FLAME_CHILDREN_CLEANUP;
                for (j = 0, slot = state; j < 7; slot = slot + 4, j = j + 1)
                {
                    objSetAnimSpeedTo1((GameObject*)*(int*)(slot + 0x700));
                }
                Sfx_RemoveLoopedObjectSoundIntLegacy(obj, SFXTRIG_trpopn_c);
                slot = *(int*)&((GameObject*)obj)->extra;
                if ((((TrickyByteFlags*)(slot + 0x58))->bit6 == 0) &&
                    (((((GameObject*)obj)->anim.currentMove >= 0x30 || (((GameObject*)obj)->anim.currentMove < 0x29)) &&
                      (Sfx_IsPlayingFromObjectChannelIntLegacy(obj, 0x10) == 0))))
                {
                    objAudioFn_800393f8Legacy(obj, (void*)(slot + 0x3a8), 0x29d, 0, 0xffffffff, 0);
                }
            }
            else if (Obj_IsLoadingLocked())
            {
                ((TrickyState*)state)->stateFlags =
                    ((TrickyState*)state)->stateFlags | TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE;
                for (k = 0, p = (u8*)state; k < 7; p += 4, k = k + 1)
                {
                    setup = (int)Obj_AllocObjectSetup(0x24, 0x4f0);
                    *(u8*)(setup + 4) = 2;
                    *(u8*)(setup + 5) = 1;
                    *(s16*)(setup + 0x1a) = k;
                    *(int*)(p + 0x700) = (int)Obj_SetupObject((ObjPlacement*)setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                                              ((GameObject*)obj)->anim.parent);
                }
                Sfx_PlayFromObjectIntReturnLegacy(obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSoundIntReturnLegacy(obj, SFXTRIG_trpopn_c);
            }
            break;
        case 2:
            mainSetBits(GAMEBIT_Tricky_LoadBadge, 1);
            if ((mainGetBit(GAMEBIT_Tricky_LoadBadge) != 0 && *(void**)&((TrickyState*)state)->spawnedChild == NULL) &&
                Obj_IsLoadingLocked())
            {
                mapBlockFn_80059c2c(blockFlags);
                if (blockFlags[0xd] != 0)
                {
                    setup = (int)Obj_AllocObjectSetup(0x20, 0x244);
                }
                else
                {
                    setup = (int)Obj_AllocObjectSetup(0x20, 0x254);
                }
                *(int*)&((TrickyState*)state)->spawnedChild =
                    (int)Obj_SetupObject((ObjPlacement*)setup, 4, -1, -1, ((GameObject*)obj)->anim.parent);
                ObjLink_AttachChild(obj, *(int*)&((TrickyState*)state)->spawnedChild, 3);
            }
            break;
        case 3:
            **(u8**)&((TrickyState*)state)->progressPtr = ((TrickyState*)state)->progressValue;
            break;
        case 0x2b:
            ((GameObject*)obj)->anim.modelState->flags &= ~(u64)OBJ_MODEL_STATE_SHADOW_VISIBLE;
            break;
        case 0x2c:
            ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
            break;
        }
    }
    objAnimFreeChildren(obj, state, (GameObject**)(state + 0x7a8)); /* raw: arrow form shifts bytes */
    objAnimFreeChildren(obj, state, (GameObject**)(state + 0x7b0)); /* raw: arrow form shifts bytes */
    objAnimFreeChildren(obj, state, (GameObject**)&((TrickyState*)state)->child);
    fn_80138D7C(obj, state);
    Tricky_updateBlendChannelWeight(obj, state);
    objAudioFn_8006ef38(obj, (int)&animUpdate->animEvents, 1, state + 0x7d8, state + 0xf8, lbl_803E23E8,
                        *(f32*)&lbl_803E23E8);
    if ((((TrickyState*)state)->stateFlags & 1) != 0)
    {
        animUpdate->hitVolumePair &= ~0x40;
        characterDoEyeAnimsState((GameObject*)obj, state + 0x378);
        return (*gObjectTriggerInterface)->func20((void*)obj, (u8*)animUpdate, 1, 0xf, 0x1e, 0, 0);
    }
    return 0;
}

void sideCommandEnable(GameObject* obj, int targetObj, int commandKind, int commandType)
{
    int commandCount;
    int commandEntry;
    u32 count;
    int commandIndex;
    int state;

    state = *(int*)&obj->extra;
    if (((TrickyState*)state)->commandCount == 10)
    {
        trickyReportError(sSidekickCommandDebugTextBlock);
        return;
    }
    ((TrickyState*)state)->commandRequestBits = (u8)(((TrickyState*)state)->commandRequestBits | (1 << commandType));
    commandIndex = 0;
    commandEntry = state;
    count = (u32)((TrickyState*)state)->commandCount;
    for (commandCount = count; 0 < commandCount; commandCount = commandCount - 1)
    {
        if (*(u32*)(commandEntry + 0x748) == targetObj)
        {
            *(u8*)((state + 0x74e) + commandIndex * 8) = 3;
            return;
        }
        commandEntry = commandEntry + 8;
        commandIndex = commandIndex + 1;
    }
    *(int*)((state + 0x748) + count * 8) = targetObj;
    *(char*)((state + 0x74c) + (u32)((TrickyState*)state)->commandCount * 8) = commandKind;
    *(char*)((state + 0x74d) + (u32)((TrickyState*)state)->commandCount * 8) = commandType;
    *(u8*)((state + 0x74e) + (u32)((TrickyState*)state)->commandCount * 8) = 3;
    ((TrickyState*)state)->commandCount++;
    return;
}

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
    bitVal = mainGetBit(GAMEBIT_Tricky_Usable);
    if (bitVal != 0)
    {
        if ((((TrickyState*)state)->stateFlags & 0x10) != 0)
        {
            ((TrickyState*)state)->commandRequestBits = 0;
        }
        commandMask = ((TrickyState*)state)->commandRequestBits | 9;
        if (((((TrickyState*)state)->stateIndex == 8) || (((TrickyState*)state)->stateIndex == 0xd)) ||
            ((((TrickyState*)state)->stateIndex == 0xe && (((TrickyState*)state)->substate == 1))))
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
        if (((TrickyState*)state)->commandRequestBits != 0)
        {
            for (i = 0; i < ((TrickyState*)state)->commandCount; i++)
            {
                ref = state + i * 8;
                cmdByte = *(char*)(ref + 0x74c);
                if (cmdByte == '\0')
                {
                    if (((GameObject*)*(int*)(ref + 0x748))->anim.seqId == 0x6a)
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
        if (((((TrickyState*)state)->stateFlags & 0x10) == 0) &&
            (bitVal = mainGetBit(GAMEBIT_ITEM_TrickyBall_Usable), bitVal != 0))
        {
            ref = (int)Obj_GetPlayerObject();
            ref = fn_80296240((GameObject*)(ref));
            if ((ref != 0) && (bitVal = mainGetBit(GAMEBIT_NoBallsAllowed), bitVal == 0))
            {
                if (playerGetFlags3F0Bit5((GameObject*)(((TrickyState*)state)->playerObj)) == 0)
                {
                    commandMask |= 0x20;
                }
            }
        }
        if (mainGetBit(GAMEBIT_ITEM_TrickyCall_Got) == 0)
        {
            commandMask &= ~1;
        }
        if (mainGetBit(0x9e) == 0)
        {
            commandMask &= ~4;
        }
        if (mainGetBit(GAMEBIT_ITEM_TrickyFlame_Got) == 0)
        {
            commandMask &= ~0x10;
        }
        ((TrickyState*)state)->commandRequestBits = 0;
        if ((cond) && ((((TrickyState*)state)->stateFlags & 0x200) == 0))
        {
            *(float*)(state + 0x7b4) = lbl_803E24F8;
            if ((((TrickyState*)state)->childB == NULL) && (Obj_IsLoadingLocked() != 0))
            {
                bitVal = randomGetRange(0, 1);
                promptId = *(u16*)((int)promptTable + bitVal * 2);
                ref = *(int*)&((GameObject*)objVal)->extra;
                if (((*(u8*)(ref + 0x58) >> 6 & 1) == 0u) && (((((GameObject*)objVal)->anim.currentMove >= 0x30 ||
                                                                (((GameObject*)objVal)->anim.currentMove < 0x29)) &&
                                                               !Sfx_IsPlayingFromObjectChannelIntLegacy(objVal, 0x10))))
                {
                    objAudioFn_800393f8Legacy(objVal, (void*)(ref + 0x3a8), promptId, 0x500, 0xffffffff, 0);
                }
                setup = (u16*)Obj_AllocObjectSetup(0x20, 0x17c);
                flagsB[0] = -1;
                flagsB[1] = -1;
                flagsB[2] = -1;
                if (((TrickyState*)state)->childA != NULL)
                {
                    flagsB[*(u8*)(state + 0x7bc) >> 6 & 3] = '\x01';
                }
                if (((TrickyState*)state)->childB != NULL)
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
                spawnedObj = (int)Obj_SetupObject((ObjPlacement*)setup, 4, -1, 0xffffffff, ((GameObject*)objVal)->anim.parent);
                *(u32*)(state + 0x7b0) = spawnedObj; /* raw: arrow form shifts bytes */
                ObjLink_AttachChild(objVal, (int)((TrickyState*)state)->childB, *(u8*)(state + 0x7bc) >> 4 & 3);
            }
        }
        else if (((TrickyState*)state)->childB != NULL)
        {
            *(float*)(state + 0x7b4) = *(float*)(state + 0x7b4) - timeDelta;
            if (*(float*)(state + 0x7b4) <= lbl_803E23DC)
            {
                objAnimFreeChildren(objVal, state, (GameObject**)(state + 0x7b0)); /* raw: arrow form shifts bytes */
            }
        }
        if ((promptA) && ((((TrickyState*)state)->stateFlags & 0x200) == 0))
        {
            *(float*)(state + 0x7ac) = lbl_803E24F8;
            if ((((TrickyState*)state)->childA == NULL) && (Obj_IsLoadingLocked() != 0))
            {
                if (randomGetRange(0, 3) == 0)
                {
                    if (promptB)
                    {
                        refB = *(int*)&((GameObject*)objVal)->extra;
                        if (((*(u8*)(refB + 0x58) >> 6 & 1) == 0u) &&
                            (((((GameObject*)objVal)->anim.currentMove >= 0x30 ||
                               (((GameObject*)objVal)->anim.currentMove < 0x29)) &&
                              !Sfx_IsPlayingFromObjectChannelIntLegacy(objVal, 0x10))))
                        {
                            objAudioFn_800393f8Legacy(objVal, (void*)(refB + 0x3a8), 0x359, 0x500, 0xffffffff, 0);
                        }
                    }
                    else if ((((promptC) &&
                               (refC = *(int*)&((GameObject*)objVal)->extra, (*(u8*)(refC + 0x58) >> 6 & 1) == 0u)) &&
                              ((((GameObject*)objVal)->anim.currentMove >= 0x30 ||
                                (((GameObject*)objVal)->anim.currentMove < 0x29)))) &&
                             !Sfx_IsPlayingFromObjectChannelIntLegacy(objVal, 0x10))
                    {
                        objAudioFn_800393f8Legacy(objVal, (void*)(refC + 0x3a8), 0x358, 0x500, 0xffffffff, 0);
                    }
                }
                setup = (u16*)Obj_AllocObjectSetup(0x20, 0x175);
                flagsA[0] = -1;
                flagsA[1] = -1;
                flagsA[2] = -1;
                if (((TrickyState*)state)->childA != NULL)
                {
                    flagsA[*(u8*)(state + 0x7bc) >> 6 & 3] = '\x01';
                }
                if (((TrickyState*)state)->childB != NULL)
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
                spawnedObj = (int)Obj_SetupObject((ObjPlacement*)setup, 4, -1, 0xffffffff, ((GameObject*)objVal)->anim.parent);
                *(u32*)(state + 0x7a8) = spawnedObj; /* raw: arrow form shifts bytes */
                ObjLink_AttachChild(objVal, (int)((TrickyState*)state)->childA, *(u8*)(state + 0x7bc) >> 6 & 3);
            }
        }
        else if (((TrickyState*)state)->childA != NULL)
        {
            *(float*)(state + 0x7ac) = *(float*)(state + 0x7ac) - timeDelta;
            if (*(float*)(state + 0x7ac) <= lbl_803E23DC)
            {
                objAnimFreeChildren(objVal, state, (GameObject**)(state + 0x7a8)); /* raw: arrow form shifts bytes */
            }
        }
        return commandMask;
    }
    return -1;
}

#pragma opt_common_subs off
void Tricky_free(GameObject* obj, int shouldKeepFlameChildren)
{
    int i;
    int childSlot;
    int state;

    state = *(int*)&obj->extra;
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[0]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[1]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[2]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[3]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[4]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[5]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[6]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[7]);
    freeAndNull((void*)((TrickyState*)state)->voxBlocks[8]);
    ObjGroup_RemoveObject((int)obj, TRICKY_OBJGROUP);
    (*gExpgfxInterface)->freeSource((u32)obj);
    if ((shouldKeepFlameChildren == 0) &&
        ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE) != 0))
    {
        ((TrickyState*)state)->stateFlags =
            ((TrickyState*)state)->stateFlags & ~(u64)TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE;
        ((TrickyState*)state)->stateFlags =
            ((TrickyState*)state)->stateFlags | TRICKY_STATE_FLAG_FLAME_CHILDREN_CLEANUP;
        i = 0;
        childSlot = state;
        do
        {
            objSetAnimSpeedTo1((GameObject*)((TrickyDestroyState*)childSlot)->childObj);
            childSlot = childSlot + 4;
            i = i + 1;
        } while (i < 7);
        Sfx_RemoveLoopedObjectSoundIntLegacy((int)obj, SFXTRIG_trpopn_c);
        childSlot = *(int*)&obj->extra;
        if (((*(u8*)(childSlot + 0x58) >> 6 & 1) == 0u) &&
            (((obj->anim.currentMove >= 0x30 || (obj->anim.currentMove < 0x29)) &&
              (Sfx_IsPlayingFromObjectChannelIntLegacy((int)obj, 0x10) == 0))))
        {
            objAudioFn_800393f8Legacy(obj, (void*)(childSlot + 0x3a8), 0x29d, 0, 0xffffffff, 0);
        }
    }
    doNothing_onTrickyFree();
    objAnimFreeChildren((int)obj, state, (GameObject**)(state + 0x7a8)); /* raw: arrow form shifts bytes */
    objAnimFreeChildren((int)obj, state, (GameObject**)(state + 0x7b0)); /* raw: arrow form shifts bytes */
    objAnimFreeChildren((int)obj, state, (GameObject**)&((TrickyState*)state)->child);
    if (*(void**)&((TrickyState*)state)->spawnedChild != NULL)
    {
        ObjLink_DetachChild(obj, *(int*)&((TrickyState*)state)->spawnedChild);
        Obj_FreeObject((GameObject*)((TrickyState*)state)->spawnedChild);
    }
    if (((((TrickyState*)state)->statusFlags >> 7 & 1) != 0u) && (gTrickyHelperObject != 0))
    {
        Obj_FreeObject((GameObject*)gTrickyHelperObject);
        gTrickyHelperObject = 0;
    }
    return;
}
#pragma opt_common_subs reset

/* Tricky sidekick command state machine and per-frame update. */
#define TRICKY_RESET_COMMAND(state)                                                                                    \
    *(u8*)((state) + 8) = 1;                                                                                           \
    *(u8*)((state) + 0xa) = 0;                                                                                         \
    z = lbl_803E23DC;                                                                                                  \
    *(f32*)((state) + 0x71c) = z;                                                                                      \
    *(f32*)((state) + 0x720) = z;                                                                                      \
    *(u32*)((state) + 0x54) = *(u32*)((state) + 0x54) & (u64)~0x10U;                                                  \
    *(u32*)((state) + 0x54) = *(u32*)((state) + 0x54) & (u64)~0x10000U;                                               \
    *(u32*)((state) + 0x54) = *(u32*)((state) + 0x54) & (u64)~0x20000U;                                               \
    *(u32*)((state) + 0x54) = *(u32*)((state) + 0x54) & (u64)~0x40000U;                                               \
    ((TrickyState*)(state))->commandPhase = -1

#define TRICKY_VOICE(obj, sfx, vol)                                                                                    \
    {                                                                                                                  \
        st = ((GameObject*)obj)->extra;                                                                                \
        if (((TrickyByteFlags*)&st->statusFlags)->bit6 == 0)                                                           \
        {                                                                                                              \
            if (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29)           \
            {                                                                                                          \
                if (Sfx_IsPlayingFromObjectChannelIntLegacy((obj), 0x10) == 0)                                         \
                {                                                                                                      \
                    objAudioFn_800393f8Legacy((obj), (u8*)st + 0x3a8, (sfx), (vol), 0xffffffff, 0);                    \
                }                                                                                                      \
            }                                                                                                          \
        }                                                                                                              \
    }

#define TRICKY_SPAWN_BUBBLE(obj, state)                                                                                \
    if (*(void**)((state) + 0x7b8) == NULL)                                                                            \
    {                                                                                                                  \
        int setup_;                                                                                                    \
        s8 used_[4];                                                                                                   \
        int slot_;                                                                                                     \
        setup_ = (int)Obj_AllocObjectSetup(0x20, 0x17b);                                                               \
        used_[0] = -1;                                                                                                 \
        used_[1] = -1;                                                                                                 \
        used_[2] = -1;                                                                                                 \
        if (*(void**)((state) + 0x7a8) != NULL)                                                                        \
        {                                                                                                              \
            used_[((TrickySlotBits*)((state) + 0x7bc))->slotA] = 1;                                                    \
        }                                                                                                              \
        if (*(void**)((state) + 0x7b0) != NULL)                                                                        \
        {                                                                                                              \
            used_[((TrickySlotBits*)((state) + 0x7bc))->slotB] = 1;                                                    \
        }                                                                                                              \
        if (*(void**)((state) + 0x7b8) != NULL)                                                                        \
        {                                                                                                              \
            used_[((TrickySlotBits*)((state) + 0x7bc))->slotC] = 1;                                                    \
        }                                                                                                              \
        if (used_[0] == -1)                                                                                            \
        {                                                                                                              \
            slot_ = 0;                                                                                                 \
        }                                                                                                              \
        else if (used_[1] == -1)                                                                                       \
        {                                                                                                              \
            slot_ = 1;                                                                                                 \
        }                                                                                                              \
        else if (used_[2] == -1)                                                                                       \
        {                                                                                                              \
            slot_ = 2;                                                                                                 \
        }                                                                                                              \
        else if (used_[3] == -1)                                                                                       \
        {                                                                                                              \
            slot_ = 3;                                                                                                 \
        }                                                                                                              \
        else                                                                                                           \
        {                                                                                                              \
            slot_ = -1;                                                                                                \
        }                                                                                                              \
        ((TrickySlotBits*)((state) + 0x7bc))->slotC = slot_;                                                           \
        *(int*)((state) + 0x7b8) = (int)Obj_SetupObject((ObjPlacement*)setup_, 4, -1, -1, *(void**)((obj) + 0x30));    \
        ObjLink_AttachChild((obj), *(int*)((state) + 0x7b8), ((TrickySlotBits*)((state) + 0x7bc))->slotC);             \
        z = lbl_803E23DC;                                                                                              \
        *(f32*)((state) + 0x7c0) = z;                                                                                  \
        *(f32*)((state) + 0x7c4) = z;                                                                                  \
        *(f32*)((state) + 0x7c8) = z;                                                                                  \
    }

#pragma opt_propagation off
void Tricky_update(int obj)
{
    char* base;
    int state;
    TrickyState* trickyState;
    int found;
    int sfxId;
    u8* cursor;
    TrickyState* st;
    struct
    {
        int index;
    } childLoop;
    int i;
    int setup;
    int count;
    u32 flags;
    int step;
    int played;
    int talking;
    u8* target;
    f32 z;
    u8 blockFlags[120];
    TrickyCmdQuery cmdQuery;
    TrickySfxPair pair;

    base = lbl_8031D2E8;
    state = *(int*)&((GameObject*)obj)->extra;
    trickyState = (TrickyState*)state;
    found = 0;
    cmdQuery = *(TrickyCmdQuery*)gTrickyCmdQueryInit;
    pair = lbl_803E23C4;
    walkgroupFindExitPointFn_800dc398();
    if (mainGetBit(GAMEBIT_Tricky_LoadBadge) != 0 && *(void**)&trickyState->spawnedChild == NULL &&
        Obj_IsLoadingLocked())
    {
        mapBlockFn_80059c2c(blockFlags);
        if (blockFlags[0xd] != 0)
        {
            setup = (int)Obj_AllocObjectSetup(0x20, 0x244);
        }
        else
        {
            setup = (int)Obj_AllocObjectSetup(0x20, 0x254);
        }
        *(int*)&trickyState->spawnedChild =
            (int)Obj_SetupObject((ObjPlacement*)setup, 4, -1, -1, ((GameObject*)obj)->anim.parent);
        ObjLink_AttachChild(obj, *(int*)&trickyState->spawnedChild, 3);
    }
    if ((trickyState->stateFlags & 0x40000000) != 0)
    {
        u8* voiceCursor = *(u8**)state;

        if (*voiceCursor == *(voiceCursor + 1))
        {
            TRICKY_VOICE(obj, 0x364, 0x500);
        }
        else
        {
            TRICKY_VOICE(obj, 0x363, 0x500);
        }
        trickyState->stateFlags &= ~0x40000000LL;
    }
    {
        int flagsByte = trickyState->unk358;
        trickyDebugPrint(base + 0x894, flagsByte & 1, flagsByte & 2, flagsByte & 4, flagsByte & 8,
                         flagsByte & 0x10, flagsByte & 0x20, flagsByte & 0x40, flagsByte & 0x80);
    }
    {
        u8* debugCursor = *(u8**)state;

        trickyDebugPrint(base + 0x8b4, *debugCursor, *(debugCursor + 1));
    }
    if ((trickyState->stateFlags & 0x200) != 0)
    {
        ObjHits_EnableObject(obj);
        if ((trickyState->stateFlags & 0x4000) == 0)
        {
            TRICKY_RESET_COMMAND(state);
            trickyState->followPhase = 0;
            trickyState->prevSpeed = z;
            trickyState->speed = z;
            trickyState->homePosX = ((GameObject*)obj)->anim.worldPosX;
            trickyState->homePosY = ((GameObject*)obj)->anim.worldPosY;
            trickyState->homePosZ = ((GameObject*)obj)->anim.worldPosZ;
            (*gPathControlInterface)->attachObject((void*)obj, &trickyState->pathControlFlags);
            if (((GameObject*)obj)->anim.currentMove == 8 || ((GameObject*)obj)->anim.currentMove == 7)
            {
                trickyState->waterLevel = lbl_803E2414;
                trickyState->eventTime = lbl_803E2544;
            }
            else
            {
                trickyState->waterLevel = lbl_803E23DC;
            }
        }
        *(s32*)&trickyState->stateFlags &= ~0x4201;
        if (((TrickyByteFlags*)&trickyState->unk82E)->bit5 != 0)
        {
            ((TrickyByteFlags*)&trickyState->unk82E)->bit5 = 0;
        }
        else
        {
            ((TrickyByteFlags*)&trickyState->unk82E)->bit7 = 1;
        }
    }
    if (*(void**)&trickyState->followObj != NULL &&
        (((GameObject*)trickyState->followObj)->objectFlags & OBJECT_OBJFLAG_FREED) != 0)
    {
        if ((trickyState->stateFlags & 0x10) != 0)
        {
            trickyState->stateFlags &= ~0x10LL;
            trickyState->groundSnapCounter = 2;
            (*gPathControlInterface)->attachObject((void*)obj, &trickyState->pathControlFlags);
            ((GameObject*)obj)->anim.localPosX = trickyState->homePosX;
            ((GameObject*)obj)->anim.localPosY = trickyState->homePosY;
            ((GameObject*)obj)->anim.localPosZ = trickyState->homePosZ;
            ((GameObject*)obj)->anim.worldPosX = trickyState->homePosX;
            ((GameObject*)obj)->anim.worldPosY = trickyState->homePosY;
            ((GameObject*)obj)->anim.worldPosZ = trickyState->homePosZ;
            ObjHits_SyncObjectPosition(obj);
            childLoop.index = 0;
            trickyState->followPhase = childLoop.index;
            z = lbl_803E23DC;
            trickyState->prevSpeed = z;
            trickyState->speed = z;
            trickyState->stateFlags |= 0x80000LL;
            trickyState->stateFlags &= ~(u64)0x2000;
            if ((trickyState->stateFlags & TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE) != 0)
            {
                u8* childCursor;

                trickyState->stateFlags =
                    trickyState->stateFlags & ~(u64)TRICKY_STATE_FLAG_FLAME_CHILDREN_ACTIVE;
                trickyState->stateFlags =
                    trickyState->stateFlags | TRICKY_STATE_FLAG_FLAME_CHILDREN_CLEANUP;
                childCursor = (u8*)state;
                for (; childLoop.index < 7; childCursor += 4, childLoop.index++)
                {
                    objSetAnimSpeedTo1((GameObject*)*(int*)(childCursor + 0x700));
                }
                Sfx_RemoveLoopedObjectSoundIntLegacy(obj, SFXTRIG_trpopn_c);
                TRICKY_VOICE(obj, 0x29d, 0);
            }
            Sfx_RemoveLoopedObjectSoundIntLegacy(obj, SFXTRIG_trwhin1);
        }
        TRICKY_RESET_COMMAND(state);
        *(int*)&trickyState->followObj = 0;
    }
    {
        int cmd;

        if ((trickyState->stateFlags & 0x10) != 0 && (*gGameUIInterface)->isEventReady(0xc1) != 0)
        {
            cmd = 0;
        }
        else
        {
            cmd = (*gGameUIInterface)->isOneOfItemsBeingUsed((s32*)&cmdQuery, 5);
        }
        cursor = (u8*)state;
        count = trickyState->commandCount;
        for (i = 0; i < count; i++)
        {
            if (*(s8*)(cursor + 0x74d) == cmd)
            {
                found = 1;
                break;
            }
            cursor += 8;
        }
        if ((trickyState->stateFlags & 0x10) == 0 && trickyFoodFn_8013db3c(obj, state) == 2)
        {
            trickyState->stateIndex = 0x11;
        }
        else if (trickyState->stateIndex == 8 && cmd == 4)
        {
            *(u8*)&trickyState->wanderTargetZ = *(u8*)&trickyState->wanderTargetZ ^ 1;
        }
        else if (trickyState->stateIndex == 0xd && cmd == 4 && found == 0)
        {
            *(int*)&trickyState->stateFlags728 = 1;
        }
        else if (trickyState->stateIndex == 0xe && cmd == 4)
        {
            *(int*)&trickyState->stateFlags728 = 1;
        }
        else if (cmd == 0)
        {
            trickyState->stateFlags |= 0x30002LL;
        }
        else
        {
            flags = trickyState->stateFlags;
            if ((flags & 0x10) == 0)
            {
                switch (cmd)
                {
                case 1:
                    trickyState->commandPhase = 1;
                    trickySelectQueuedCommandTarget(state, 1);
                    TRICKY_VOICE(obj, 0x13c, 0);
                    switch (((GameObject*)trickyState->followObj)->anim.seqId)
                    {
                    case 0x1ca:
                        if (**(u8**)state < 4)
                        {
                            if (Obj_IsLoadingLocked())
                            {
                                trickyState->stateFlags |= 4;
                                TRICKY_RESET_COMMAND(state);
                                TRICKY_SPAWN_BUBBLE(obj, state);
                            }
                        }
                        else
                        {
                            trickyState->stateIndex = 2;
                        }
                        break;
                    case 0x160:
                        if (**(u8**)state < 4)
                        {
                            if (Obj_IsLoadingLocked())
                            {
                                trickyState->stateFlags |= 4;
                                TRICKY_RESET_COMMAND(state);
                                TRICKY_SPAWN_BUBBLE(obj, state);
                            }
                        }
                        else
                        {
                            trickyState->stateIndex = 3;
                        }
                        break;
                    case 0x6a:
                    case 0x193:
                    case 0x3fb:
                    case 0x658:
                        trickyState->stateIndex = 9;
                        break;
                    case 0x195:
                        if (**(u8**)state < 2)
                        {
                            if (Obj_IsLoadingLocked())
                            {
                                trickyState->stateFlags |= 4;
                                TRICKY_RESET_COMMAND(state);
                                TRICKY_SPAWN_BUBBLE(obj, state);
                            }
                        }
                        else
                        {
                            trickyState->stateIndex = 0x10;
                        }
                        break;
                    case 0x352:
                        if (**(u8**)state < 4)
                        {
                            if (Obj_IsLoadingLocked())
                            {
                                trickyState->stateFlags |= 4;
                                TRICKY_RESET_COMMAND(state);
                                TRICKY_SPAWN_BUBBLE(obj, state);
                            }
                        }
                        else
                        {
                            trickyState->stateIndex = 2;
                        }
                        break;
                    case 0x358:
                        trickyState->stateIndex = 0xe;
                        break;
                    default:
                        TRICKY_RESET_COMMAND(state);
                        trickyReportError(base + 0x8c4);
                        break;
                    }
                    break;
                case 3:
                    played = 0;
                    if (trickyState->commandPhase == 3)
                    {
                        cursor = (u8*)state;
                        count = trickyState->commandCount;
                        for (i = 0; i < count; i++)
                        {
                            if (*(s8*)(cursor + 0x74d) == 3)
                            {
                                played = 1;
                            }
                            cursor += 8;
                        }
                    }
                    else
                    {
                        played = 1;
                    }
                    if (played != 0)
                    {
                        trickyState->commandPhase = 3;
                        if (trickySelectQueuedCommandTarget(state, 3) != 0)
                        {
                            switch (((GameObject*)trickyState->followObj)->anim.seqId)
                            {
                            case 0x36:
                            case 0x104:
                            case 0x131:
                            case 0x19f:
                            case 0x26c:
                            case 0x475:
                            case 0x546:
                            case 0x7c3:
                                trickyState->stateIndex = 0xa;
                                trickyState->idleSfxTimer = (f32)(int)randomGetRange(0x1f4, 0x2ee);
                                break;
                            case 0x6f0:
                                trickyState->stateIndex = 0xe;
                                break;
                            default:
                                trickyState->stateIndex = 8;
                                break;
                            }
                        }
                        else
                        {
                            trickyState->stateFlags |= 0x40000LL;
                        }
                    }
                    break;
                case 4:
                    if (**(u8**)state < 4)
                    {
                        if (Obj_IsLoadingLocked())
                        {
                            trickyState->stateFlags |= 4;
                            TRICKY_RESET_COMMAND(state);
                            TRICKY_SPAWN_BUBBLE(obj, state);
                        }
                    }
                    else
                    {
                        trickyState->commandPhase = 4;
                        trickySelectQueuedCommandTarget(state, 4);
                        trickyState->stateIndex = 7;
                        switch (((GameObject*)trickyState->followObj)->anim.seqId)
                        {
                        case 0x1c9:
                            *(void**)&trickyState->unk724 = fn_801B17F4;
                            break;
                        case 0x718:
                            *(void**)&trickyState->unk724 = fn_801B6D40;
                            break;
                        case 0x551:
                            *(void**)&trickyState->unk724 = fn_801FD4A8;
                            break;
                        case 0x191:
                            *(void**)&trickyState->unk724 = fn_801B0784;
                            break;
                        case 0x470:
                            *(void**)&trickyState->unk724 = drchimmey_countdownCallback;
                            break;
                        case 0x102:
                        case 0x194:
                        case 0x542:
                        case 0x54c:
                        case 0x6f9:
                            *(void**)&trickyState->unk724 = 0;
                            break;
                        case 0x3c:
                            *(void**)&trickyState->unk724 = fn_801DA9CC;
                            break;
                        case 0x50f:
                            *(void**)&trickyState->unk724 = wcbeacon_aButtonCallback;
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
                        trickyState->commandPhase = 5;
                        setup = (int)Obj_AllocObjectSetup(0x18, 0x112);
                        *(u8*)(setup + 7) = 0xff;
                        *(u8*)(setup + 4) = 2;
                        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.worldPosX;
                        ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.worldPosY;
                        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.worldPosZ;
                        *(int*)&trickyState->followObj =
                            (int)Obj_SetupObject((ObjPlacement*)setup, 5, -1, -1, ((GameObject*)obj)->anim.parent);
                        target = (u8*)&((GameObject*)trickyState->followObj)->anim.worldPosX;
                        if (trickyState->targetPosPtr != target)
                        {
                            trickyState->targetPosPtr = target;
                            {
                                u32 mask;
                                u32 stateFlags = trickyState->stateFlags;
                                mask = ~0x400;
                                trickyState->stateFlags = stateFlags & mask;
                            }
                            trickyState->linkedWalkGroup = 0;
                        }
                        trickyState->substate = 0;
                        trickyState->stateIndex = 0xb;
                    }
                    break;
                default:
                    if (trickyState->stateIndex == 1 && trickyState->commandPhase != 0 &&
                        (flags & 0x20000) == 0)
                    {
                        step = trickyFindNearestUsableBaddie(trickyState->playerObj, lbl_803E24D8, 0);
                        if ((void*)step != NULL)
                        {
                            *(int*)&trickyState->followObj = step;
                            if (trickyState->targetPosPtr != (u8*)(step + 0x18))
                            {
                                trickyState->targetPosPtr = (u8*)(step + 0x18);
                                {
                                    u32 mask;
                                    u32 stateFlags = trickyState->stateFlags;
                                    mask = ~0x400;
                                    trickyState->stateFlags = stateFlags & mask;
                                }
                                trickyState->linkedWalkGroup = 0;
                            }
                            trickyState->stateIndex = 0xd;
                            trickyState->substate = 0;
                            *(int*)&trickyState->stateFlags728 = 0;
                        }
                    }
                    break;
                }
            }
            else if (cmd == 3)
            {
                trickyState->stateFlags = flags | 0x40000LL;
            }
        }
    }
    flags = trickyState->stateFlags;
    if ((flags & 0x10) == 0)
    {
        if ((flags & 0x10000) != 0)
        {
            if ((flags & 0x20000) != 0)
            {
                TRICKY_RESET_COMMAND(state);
                *(u8*)&trickyState->commandPhase = 0;
            }
            else
            {
                TRICKY_RESET_COMMAND(state);
            }
            trickyState->cooldownA = lbl_803E2548;
        }
        else if ((flags & 0x40000) != 0)
        {
            *(int*)&trickyState->followObj = obj;
            trickyState->stateIndex = 0xf;
            trickyState->idleSfxTimer = (f32)(int)randomGetRange(0x1f4, 0x2ee);
            {
                u32 mask;
                u32 stateFlags = trickyState->stateFlags;
                mask = ~0x40000;
                trickyState->stateFlags = stateFlags & mask;
            }
            trickyState->commandPhase = 3;
            if (trickyState->targetPosPtr != (u8*)&trickyState->wanderTargetX)
            {
                trickyState->targetPosPtr = (u8*)&trickyState->wanderTargetX;
                {
                    u32 mask;
                    u32 stateFlags = trickyState->stateFlags;
                    mask = ~0x400;
                    trickyState->stateFlags = stateFlags & mask;
                }
                trickyState->linkedWalkGroup = 0;
            }
        }
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED;
    trickyState->heightUpdateActive = 1;
    ((TrickyHandlerFn*)(base + 0x24))[trickyState->stateIndex](obj, state);
    trickyState->stateFlags &= ~(u64)0x2;
    trickyState->animTransitionTimer += timeDelta;
    if (trickyState->animTransitionTimer > lbl_803E247C)
    {
        if (((GameObject*)obj)->anim.currentMove != trickyState->moveId)
        {
            if ((trickyState->pendingStateFlags & 0x1000000) != 0 &&
                (trickyState->stateFlags & 0x1000000) != 0)
            {
                ObjAnim_SetCurrentMove(obj, trickyState->moveId, ((GameObject*)obj)->anim.currentMoveProgress,
                                       0);
            }
            else
            {
                ObjAnim_SetCurrentMove(obj, trickyState->moveId, lbl_803E23DC, 0);
            }
            trickyState->stateFlags &= ~0x060001e0LL;
            trickyState->stateFlags |= trickyState->pendingStateFlags;
            trickyState->animTransitionTimer = lbl_803E23DC;
            trickyState->moveProgress = trickyState->moveProgressTarget;
        }
    }
    if ((trickyState->stateFlags & 0x2000000) != 0)
    {
        ((GameObject*)obj)->anim.localPosX += timeDelta * (trickyState->dirX * trickyState->speed);
        ((GameObject*)obj)->anim.localPosZ += timeDelta * (trickyState->dirZ * trickyState->speed);
        ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)(
            obj, trickyState->speed, (float*)(state + 0x34));
    }
    if (trickyState->moveProgress == lbl_803E23DC)
    {
        ((ObjAnimSetProgressObjectFirstFn)ObjAnim_SetMoveProgress)(obj, trickyState->arcMoveProgress);
    }
    if (ObjAnim_AdvanceCurrentMove((int)obj, trickyState->moveProgress, timeDelta,
                                                                    (void*)(state + 0x80c)) != 0)
    {
        trickyState->stateFlags |= 0x8000000LL;
    }
    else
    {
        trickyState->stateFlags &= ~0x8000000LL;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_ROTATE) != 0)
    {
        int rotationDiff;
        int rotationStep;

        rotationDiff = trickyState->targetYaw - (u16)((GameObject*)obj)->anim.rotX;
        if (rotationDiff > 0x8000)
        {
            rotationDiff -= 0xffff;
        }
        if (rotationDiff < -0x8000)
        {
            rotationDiff += 0xffff;
        }
        rotationStep = (int)((f32)trickyState->rotRate * trickyState->rotStepScale);
        if ((rotationDiff >= 0 ? rotationDiff : -rotationDiff) >= 4)
        {
            if ((rotationStep > 0 && rotationDiff > 0) || (rotationStep < 0 && rotationDiff < 0))
            {
                if ((rotationStep >= 0 ? rotationStep : -rotationStep) >
                    (rotationDiff >= 0 ? rotationDiff : -rotationDiff))
                {
                    ((GameObject*)obj)->anim.rotX += rotationDiff;
                }
                else
                {
                    ((GameObject*)obj)->anim.rotX += rotationStep;
                }
            }
            else
            {
                ((GameObject*)obj)->anim.rotX += rotationStep;
            }
        }
        else
        {
            ((GameObject*)obj)->anim.rotX += rotationDiff;
        }
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_BACKSTEP) != 0)
    {
        ((GameObject*)obj)->anim.localPosX += trickyState->backstepDelta *
                                              (trickyState->dirX * -trickyState->backstepScale);
        ((GameObject*)obj)->anim.localPosZ += trickyState->backstepDelta *
                                              (trickyState->dirZ * -trickyState->backstepScale);
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_VERTICAL_MOVE) != 0)
    {
        ((GameObject*)obj)->anim.localPosY +=
            trickyState->verticalScale * trickyState->verticalDelta;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_SIDESTEP) != 0)
    {
        ((GameObject*)obj)->anim.localPosX +=
            trickyState->sidestepDelta * (trickyState->dirZ * trickyState->sidestepScale);
        ((GameObject*)obj)->anim.localPosZ += trickyState->sidestepDelta *
                                              (trickyState->dirX * -trickyState->sidestepScale);
    }
    if (*(void**)&trickyState->followObj != NULL)
    {
        trickyState->followPosValid = 1;
        trickyState->followPosX = ((GameObject*)trickyState->followObj)->anim.worldPosX;
        trickyState->followPosY = ((GameObject*)trickyState->followObj)->anim.worldPosY;
        trickyState->followPosZ = ((GameObject*)trickyState->followObj)->anim.worldPosZ;
    }
    else
    {
        trickyState->followPosValid = 0;
    }
    if (((GameObject*)obj)->anim.currentMove == 0x2a)
    {
        fn_8003A168PointerStateLegacy((GameObject*)(obj), (void*)(state + 0x378));
        fn_8003B228((GameObject*)(obj), (void*)(state + 0x378));
    }
    else
    {
        fn_8003A230((GameObject*)obj, (CharacterEyeAnimState*)(state + 0x378), lbl_803E23DC);
        characterDoEyeAnimsState((GameObject*)obj, state + 0x378);
    }
    objAnimFn_80038f38((GameObject*)obj, (char*)state + 0x3a8);
    {
        u8* pathCursor;
        TrickyState* pathState;

        pathState = ((GameObject*)obj)->extra;
        pathCursor = (u8*)pathState->targetPosPtr;
        pathState->previousPathPoint = (f32*)pathCursor;
        if (pathState->previousPathPoint != NULL)
        {
            pathState->previousPathX = *(f32*)pathCursor;
            pathState->previousPathY = *(f32*)(pathCursor + 4);
            pathState->previousPathZ = *(f32*)(pathCursor + 8);
        }
    }
    trickyState->prevSpeed = trickyState->speed;
    i = trickyState->commandCount - 1;
    {
        u8* commandCursor = (u8*)state + i * 8;

        for (; i >= 0; commandCursor -= 8, i--)
        {
            *(u8*)(commandCursor + 0x74e) -= 1;
            if (*(s8*)(commandCursor + 0x74e) == 0)
            {
                memmove((void*)(commandCursor + 0x748), (void*)(state + (i + 1) * 8 + 0x748),
                        (trickyState->commandCount - i - 1) * 8);
                trickyState->commandCount -= 1;
            }
        }
    }
    if (getXZDistance(&((GameObject*)obj)->anim.worldPosX,
                      &((GameObject*)trickyState->playerObj)->anim.worldPosX) >= lbl_803E2538 &&
        mainGetBit(GAMEBIT_Tricky_Usable) != 0)
    {
        trickyState->stateFlags |= 0x10000LL;
    }
    trickyState->cooldownC -= timeDelta;
    if (trickyState->cooldownC < 0.0f)
    {
        trickyState->cooldownC = 0.0f;
    }
    if ((trickyState->stateFlags & 4) != 0)
    {
        st = ((GameObject*)obj)->extra;
        if (((TrickyByteFlags*)((u8*)st + 0x58))->bit6 != 0)
        {
            played = 0;
        }
        else
        {
            switch (((GameObject*)obj)->anim.currentMove)
            {
            case 0x29:
            case 0x2a:
            case 0x2b:
            case 0x2c:
            case 0x2d:
            case 0x2e:
            case 0x2f:
                played = 0;
                break;
            default:
                if (Sfx_IsPlayingFromObjectChannelIntLegacy(obj, 0x10) != 0)
                {
                    played = 0;
                }
                else
                {
                    objAudioFn_800393f8Legacy(obj, (u8*)st + 0x3a8, 0x298, 0x500, 0xffffffff, 0);
                    played = 1;
                }
                break;
            }
        }
        if (played != 0)
        {
            trickyState->stateFlags &= ~(u64)0x4;
        }
    }
    trickyState->voiceCooldown -= timeDelta;
    if (trickyState->voiceCooldown < 0.0f)
    {
        trickyState->voiceCooldown = 0.0f;
    }
    if (trickyState->voiceCooldown > lbl_803E23DC)
    {
        TRICKY_VOICE(obj, 0x29c, 0x100);
    }
    trickyUpdateCollisionAndPathState((u8*)obj);
    if ((trickyState->stateFlags & 0x80000000) != 0)
    {
        trickyState->impressTimer -= timeDelta;
        if (trickyState->impressTimer <= lbl_803E23DC)
        {
            trickyState->stateFlags &= 0x7FFFFFFF;
            sfxId = ((u16*)&pair)[randomGetRange(0, 1)];
            TRICKY_VOICE(obj, sfxId, 0x500);
        }
    }
    fn_80138D7C(obj, state);
    Tricky_updateBlendChannelWeight(obj, state);
    if (trickyState->speed > lbl_803E254C)
    {
        objAudioFn_8006ef38(obj, state + 0x80c, 1, state + 0x7d8, state + 0xf8, trickyState->speed,
                            lbl_803E23E8);
    }
    if (lbl_803E23DC == trickyState->waterLevel)
    {
        talking = 0;
    }
    else if (lbl_803E2410 == trickyState->eventTime)
    {
        talking = 1;
    }
    else if (trickyState->currentTime - trickyState->eventTime > lbl_803E2414)
    {
        talking = 1;
    }
    else
    {
        talking = 0;
    }
    if (talking != 0)
    {
        u8* soundCursor;
        int sfx2;

        soundCursor = (u8*)state + 0x80c;
        sfx2 = 0;
        for (i = 0, count = *(s8*)(soundCursor + 0x1b); i < count; i++)
        {
            switch (*(s8*)(soundCursor + i + 0x13))
            {
            case 0:
            case 1:
            case 2:
                sfx2 = 0x433;
                break;
            }
        }
        if (sfx2 != 0)
        {
            Sfx_PlayFromObjectIntReturnLegacy(obj, (u16)sfx2);
        }
    }
    trickyState->prevLocalPosX = ((GameObject*)obj)->anim.previousLocalPosX;
    trickyState->prevLocalPosY = ((GameObject*)obj)->anim.previousLocalPosY;
    trickyState->prevLocalPosZ = ((GameObject*)obj)->anim.previousLocalPosZ;
    if (*(void**)&trickyState->child != NULL)
    {
        trickyState->childPhaseTimer0 += timeDelta;
        trickyState->childPhaseTimer1 += timeDelta;
        trickyState->childPhaseTimer2 += timeDelta;
        if (trickyState->childPhaseTimer2 > *(f32*)&lbl_803E24C8)
        {
            trickyState->childPhaseTimer2 -= lbl_803E24C8;
        }
        if (trickyState->childPhaseTimer2 >= lbl_803E2408)
        {
            *(s16*)(*(int*)&trickyState->child + 6) =
                *(s16*)(*(int*)&trickyState->child + 6) | 0x4000;
        }
        else
        {
            *(s16*)(*(int*)&trickyState->child + 6) =
                *(s16*)(*(int*)&trickyState->child + 6) & ~0x4000;
        }
        if (trickyState->childPhaseTimer1 > lbl_803E24D8)
        {
            if (trickyState->childPhaseTimer1 > lbl_803E2440)
            {
                trickyState->childPhaseTimer1 -= lbl_803E2440;
            }
            *(s16*)(*(int*)&trickyState->child + 6) =
                *(s16*)(*(int*)&trickyState->child + 6) | 0x4000;
        }
        if (trickyState->childPhaseTimer0 > lbl_803E2550)
        {
            if (mainGetBit(GAMEBIT_ITEM_TrickyFood_Count) != 0)
            {
                TRICKY_VOICE(obj, 0x392, 0x500);
            }
            else
            {
                TRICKY_VOICE(obj, 0x298, 0x500);
            }
            trickyState->childPhaseTimer0 -= lbl_803E2550;
        }
        ObjAnim_AdvanceCurrentMove(*(int*)&trickyState->child, lbl_803E23EC, timeDelta, 0);
    }
    if (*(void**)&trickyState->childB != NULL)
    {
        ObjAnim_AdvanceCurrentMove(*(int*)&trickyState->childB, lbl_803E23EC, timeDelta, 0);
    }
    if (*(void**)&trickyState->childA != NULL)
    {
        ObjAnim_AdvanceCurrentMove(*(int*)&trickyState->childA, lbl_803E23EC, timeDelta, 0);
    }
}

#pragma opt_propagation reset
void Tricky_init(GameObject* obj)
{
    int state;
    int model;
    int pathState;
    u32 modelVariant;
    u16 startPath[4];

    state = *(int*)&(obj)->extra;
    startPath[0] = lbl_803E23C0;
    mainSetBits(GAMEBIT_TrickyTalk, 0xff);
    if (mainGetBit(GAMEBIT_ITEM_TrickyBall_Bought) != 0)
    {
        mainSetBits(GAMEBIT_ITEM_TrickyBall_Usable, 1);
    }
    (obj)->animEventCallback = tricky_SeqFn;
    ObjGroup_AddObject((int)obj, TRICKY_OBJGROUP);
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
    ((TrickyState*)state)->playerObj = (int)Obj_GetPlayerObject();
    ((TrickyState*)state)->stateIndex = 0;
    ((TrickyState*)state)->commandRequestBits = 0;
    ((TrickyState*)state)->previousPathPoint = NULL;
    ((TrickyState*)state)->activeWalkGroup = 0;
    ((TrickyState*)state)->homePosX = (obj)->anim.worldPosX;
    ((TrickyState*)state)->homePosY = (obj)->anim.worldPosY;
    ((TrickyState*)state)->homePosZ = (obj)->anim.worldPosZ;
    modelVariant = *(u8*)(((TrickyState*)state)->progressPtr + 2) / 10;
    ((TrickyState*)state)->modelVariant = modelVariant;
    model = (int)Obj_GetActiveModel(obj);
    *(u8*)(*(int*)(model + 0x34) + 8) = ((TrickyState*)state)->modelVariant;
    pathState = (int)&((TrickyState*)state)->pathControlFlags;
    (*gPathControlInterface)->init((void*)pathState, 1, 0xa7, 1);
    (*gPathControlInterface)->setLocalPointCollision((void*)pathState, 1, gTrickyPathPointCollision, &lbl_803DBC48, 2);
    (*gPathControlInterface)->setup((void*)pathState, 2, lbl_8031D2E8, &lbl_803DBC40, startPath);
    (*gPathControlInterface)->attachObject((void*)obj, (void*)pathState);
    doNothing_onTrickyInit();
    walkgroupFindExitPointFn_800dc398();
    ((TrickyState*)state)->groundSnapCounter = 2;
    ((TrickyInitFlags*)&((TrickyState*)state)->unk82E)->initBit7 = 1;
    ((TrickyState*)state)->commandPhase = -1;
}

void Tricky_resumeAfterCommand(GameObject* obj, int state)
{
    ObjHitsPriorityState* hitState;
    u8 moveId;

    ((TrickyState*)state)->actionId = 1;
    if (((((TrickyState*)state)->flags2DC & 0x1000) != 0) && ((((TrickyState*)state)->flags2E0 & 0x1000) == 0))
    {
        (obj)->anim.flags = (obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN;
        moveId = ((TrickyState*)state)->moveId0;
        ((TrickyState*)state)->animPlaySpeed = lbl_803E256C / (lbl_803E2570 * ((TrickyState*)state)->moveSpeedScale0);
        ((TrickyState*)state)->flags323 = 1;
        ObjAnim_SetCurrentMove((int)obj, moveId, lbl_803E2574, OBJANIM_MOVE_CONTROL_SKIP_EVENT_COUNTDOWN);
        if ((obj)->anim.hitReactState != NULL)
        {
            hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
            hitState->suppressOutgoingHits = 0;
        }
        ((TrickyState*)state)->flags2E8 = ((TrickyState*)state)->flags2E8 | 4;
        Sfx_PlayFromObjectLimited((int)obj, SFXTRIG_holorays16, 2);
        ObjHits_EnableObject((int)obj);
    }
    if ((((TrickyState*)state)->flags2DC & 0x40000000) != 0)
    {
        ((TrickyState*)state)->animPlaySpeed = lbl_803E2578;
        ((TrickyState*)state)->flags323 = 0;
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2574, 0);
        if ((obj)->anim.hitReactState != NULL)
        {
            hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
            hitState->suppressOutgoingHits = 0;
        }
        ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC & 0xffffef7f;
        ((TrickyState*)state)->flags2E8 = ((TrickyState*)state)->flags2E8 & ~(u64)0x4;
        ((TrickyState*)state)->currentMoveProgress = lbl_803E2574;
        (obj)->anim.alpha = 0xff;
    }
    else
    {
        (obj)->anim.alpha = (int)(lbl_803E257C * (obj)->anim.currentMoveProgress);
        ((TrickyState*)state)->currentMoveProgress = (obj)->anim.currentMoveProgress;
    }
}

void tricky_handleDefeat(GameObject* obj, int state)
{
    ObjHitsPriorityState* hitState;
    int setup;
    int alpha;
    void* tricky;
    int spawnBits;
    u8 moveId;

    setup = *(int*)&(obj)->anim.placementData;
    ((TrickyState*)state)->actionId = 0;
    if (((((TrickyState*)state)->flags2DC & 0x800) != 0) && ((((TrickyState*)state)->flags2E0 & 0x800) == 0))
    {
        tricky = (void*)getTrickyObject();
        if (tricky != NULL)
        {
            trickyImpress((GameObject*)tricky);
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
                mainSetBits(*(s16*)(setup + BADDIE_PLACEMENT_CLEAR_ON_DEATH_GAMEBIT), 0);
            }
        }
        ((TrickyState*)state)->actionTargetObj = NULL;
        ObjHits_DisableObject((int)obj);
        *(u8*)&(obj)->anim.resetHitboxMode = *(u8*)&(obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED;
        moveId = ((TrickyState*)state)->moveId1;
        ((TrickyState*)state)->animPlaySpeed = lbl_803E256C / (lbl_803E2570 * ((TrickyState*)state)->moveSpeedScale1);
        ((TrickyState*)state)->flags323 = 1;
        ObjAnim_SetCurrentMove((int)obj, moveId, lbl_803E2574, 0);
        if (*(void**)&(obj)->anim.hitReactState != NULL)
        {
            hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
            hitState->suppressOutgoingHits = 0;
        }
        ((TrickyState*)state)->flags2E8 = ((TrickyState*)state)->flags2E8 | 1;
        Sfx_PlayFromObjectIntReturnLegacy((int)obj, SFXTRIG_wp_iceywindlp16_233);
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
    alpha = 0xff - (int)(lbl_803E257C * (obj)->anim.currentMoveProgress);
    alpha = (alpha < 0) ? 0 : ((alpha > 0xff) ? 0xff : alpha);
    (obj)->anim.alpha = alpha;
    ((TrickyState*)state)->currentMoveProgress = lbl_803E256C + (f32)(0xff - (obj)->anim.alpha) / lbl_803E257C;
    if ((obj)->anim.alpha < 5)
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
                mainSetBits(*(s16*)(setup + BADDIE_PLACEMENT_CLEAR_ON_DEATH_GAMEBIT), 0);
            }
        }
        ((TrickyState*)state)->currentMoveProgress = lbl_803E2574;
        ((TrickyState*)state)->flags2DC = 0;
        (obj)->anim.flags = (obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
        (obj)->anim.alpha = 0;
        *(u32*)&(obj)->unkF4 = 1;
        if ((u32)((ObjPlacement*)setup)->mapId == 0xFFFFFFFF)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            if (*(s16*)(setup + 0x2c) != 0)
            {
                (*gMapEventInterface)
                    ->addTime(((ObjPlacement*)setup)->mapId, lbl_803E2570 * (f32) * (s16*)(setup + 0x2c));
            }
            ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC & ~(u64)0x800;
            ((TrickyState*)state)->flags2E8 = ((TrickyState*)state)->flags2E8 & ~3LL;
        }
    }
}

int collectibleFn_80149cec(GameObject* obj, int state, int spawnBits, u32 useAltMode, u32 mode)
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
    parentSetup = *(int*)&(obj)->anim.placementData;
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
        setup = (int)Obj_AllocObjectSetup(0x30, *(u16*)((int)commandSpawnIds + index * 2));
    }
    else if (mode == 2)
    {
        index = ((spawnBits & 0xf000) >> 0xc) - 1;
        if (index > 1)
        {
            index = 1;
        }
        setup = (int)Obj_AllocObjectSetup(0x30, *(u16*)((int)&rewardSpawnIds0 + index * 2));
    }
    else if (mode == 3)
    {
        switch (spawnBits)
        {
        case 1:
            setup = (int)Obj_AllocObjectSetup(0x30, 0x2cd);
            break;
        case 3:
            setup = (int)Obj_AllocObjectSetup(0x30, 0xb);
            break;
        case 4:
            setup = (int)Obj_AllocObjectSetup(0x30, 0x2cd);
            break;
        case 5:
            savedX = (obj)->anim.worldPosX;
            savedY = (obj)->anim.worldPosY;
            savedZ = (obj)->anim.worldPosZ;
            parentSetup = *(int*)&(obj)->anim.placementData;
            if ((void*)parentSetup != NULL)
            {
                (obj)->anim.worldPosX = ((ObjPlacement*)parentSetup)->posX;
                (obj)->anim.worldPosY = ((ObjPlacement*)parentSetup)->posY;
                (obj)->anim.worldPosZ = ((ObjPlacement*)parentSetup)->posZ;
            }
            nearestDistance = lbl_803E25A8;
            gTrickyNearestObject = ObjGroup_FindNearestObject(4, (int)obj, &nearestDistance);
            (obj)->anim.worldPosX = savedX;
            (obj)->anim.worldPosY = savedY;
            (obj)->anim.worldPosZ = savedZ;
            if ((void*)gTrickyNearestObject != NULL)
            {
                v = (obj)->anim.localPosX;
                ((GameObject*)gTrickyNearestObject)->anim.worldPosX = v;
                ((GameObject*)gTrickyNearestObject)->anim.localPosX = v;
                v = lbl_803E25AC + (obj)->anim.localPosY;
                ((GameObject*)gTrickyNearestObject)->anim.worldPosY = v;
                ((GameObject*)gTrickyNearestObject)->anim.localPosY = v;
                v = (obj)->anim.localPosZ;
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
        setup = (int)Obj_AllocObjectSetup(0x30, ((u16*)((u8*)&rewardTail.pair - 2))[index]);
    }
    *(u8*)(setup + 0x1a) = 0x14;
    *(s16*)(setup + 0x2c) = -1;
    *(s16*)(setup + 0x1c) = -1;
    *(s16*)(setup + 0x24) = -1;
    ((ObjPlacement*)setup)->posX = (obj)->anim.localPosX;
    ((ObjPlacement*)setup)->posY = lbl_803E2598 + (obj)->anim.localPosY;
    ((ObjPlacement*)setup)->posZ = (obj)->anim.localPosZ;
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
    nearest = (int)Obj_SetupObject((ObjPlacement*)setup, 5, (obj)->anim.mapEventSlot, -1, (obj)->anim.parent);
    gTrickyNearestObject = nearest;
    if ((((GameObject*)nearest)->anim.seqId == 0x3cd) || (((GameObject*)nearest)->anim.seqId == 0xb))
    {
        (*(void (**)(int, f32, f32, f32))(*(int*)(*(int*)&((GameObject*)nearest)->anim.dll) + 0x2c))(
            nearest, lbl_803E2574, lbl_803E256C, lbl_803E2574);
    }
    return gTrickyNearestObject;
}

/* Shared frozen-state update + per-baddie reaction dispatch. */
void baddie_updateWhileFrozen(GameObject* obj, u8* state, u8 fromHit)
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

    player = (int)Obj_GetPlayerObject();
    colors = *(FrozenFxColors*)gTrickyFrozenFxColors;
    result = 2;
    if ((((TrickyState*)state)->flags2DC & 0x1800) == 0)
    {
        if ((((TrickyState*)state)->controlFlags & 1) != 0)
        {
            ObjHits_EnableObject((int)obj);
        }
        else
        {
            ObjHits_DisableObject((int)obj);
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
        fn_802972B4((GameObject*)(player), &hitEffects, &fxA, &fxB, &fxC, &impactSfx);
        frozenEnemyFn_80149bb4((int*)state, hitEffects, fxA, impactSfx);
        if (hit != 0)
        {
            if (fromHit)
            {
                if (hit != 0x10)
                {
                    params.scale = lbl_803E258C;
                    (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x7fb, NULL, 0x64, &params);
                    (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x7fc, NULL, 0x32, NULL);
                    Obj_Shatter((GameObject*)obj);
                    *(u16*)&((TrickyState*)state)->eventTime = 0;
                    ((TrickyState*)state)->flags2E8 = ((TrickyState*)state)->flags2E8 & ~0x20LL;
                    ((TrickyState*)state)->flags2E8 = ((TrickyState*)state)->flags2E8 | 0x200;
                    Sfx_PlayFromObjectIntReturnLegacy((int)obj, SFXTRIG_barrel_bounce1);
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
                            (obj)->anim.velocityX = zero;
                            (obj)->anim.velocityY = zero;
                            if ((((TrickyState*)state)->flags2DC & 0x40) != 0)
                            {
                                (obj)->anim.velocityZ = lbl_803E2594 * fxB;
                            }
                            else
                            {
                                (obj)->anim.velocityZ = fxB;
                            }
                            vecRotateZXY(&((GameObject*)obj)->anim.rotX, &((GameObject*)obj)->anim.velocityX);
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
                dp[0] = (obj)->anim.worldPosX - hitPos.x;
                dp[1] = (obj)->anim.worldPosY - hitPos.y;
                dp[2] = (obj)->anim.worldPosZ - hitPos.z;
                diff = (u16)getAngle(-dp[0], -dp[2]) - (u16)(obj)->anim.rotX;
                if (diff > 0x8000)
                {
                    diff -= 0xffff;
                }
                if (diff < -0x8000)
                {
                    diff += 0xffff;
                }
                sector = (u32)(u16)diff >> 13;
                hDist = sqrtf(dp[0] * dp[0] + dp[2] * dp[2]);
                vDist = sqrtf(dp[1] * dp[1]);
                switch ((obj)->anim.seqId)
                {
                case 0x11:
                case 0x13a:
                case 0x5b7:
                case 0x5b8:
                case 0x5b9:
                case 0x5e1:
                case 0x7a6:
                    result = sidekickToy_handleHitMessage((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos,
                                                          sector, hDist, vDist);
                    break;
                case 0xd8:
                case 0x281:
                    guardClawUpdateWhileFrozen((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x613:
                    gcRobotPatrol_updateWhileFrozen((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x642:
                    mikaladon_updateWhileFrozen((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x3fe:
                case 0x7c6:
                    vambat_updateWhileFrozen((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x58b:
                    kooshy_updateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x369:
                    weevil_updateWhileFrozen(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x251:
                    Baddie_HandleHitReaction(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x25d:
                    rachnopUpdateWhileFrozen((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x4d7:
                    wbUpdateWhileFrozen((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x457:
                    baddieUpdateWhileFrozen_80155e10((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x458:
                    mutatedEbaUpdateWhileFrozen((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x851:
                    whirlpool_updateWhileFrozen((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x842:
                case 0x84b:
                    snowworm_updateWhileFrozen((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x4ac:
                    hoodedZyckUpdateWhileFrozen((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x427:
                    battleDroidUpdateWhileFrozen((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x6a2:
                case 0x6a3:
                case 0x6a4:
                case 0x6a5:
                    crawler_onHit(obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                case 0x7c8:
                    hagabonMK2_updateWhileFrozen((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
                    break;
                default:
                    battleDroidUpdateWhileFrozen((int)obj, state, attacker, hit, hitArg, hitCount, &hitPos, sector);
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
                ((TrickyState*)state)->light = (int)objCreateLight(NULL, 1);
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
                    ((void (**)(int, int, void*, int, int, void*)) * (int*)lbl_803DDA50)[1](0, 1, &params, 0x401, -1,
                                                                                            &colors);
                }
                ((TrickyState*)state)->freezeEffectTimer = lbl_803E25A0;
                if (*(void**)&((TrickyState*)state)->light == NULL)
                {
                    ((TrickyState*)state)->light = (int)objCreateLight(NULL, 1);
                }
                objLightFn_8009a1dc((void*)obj, lbl_803E259C, &params, 4, (void*)((TrickyState*)state)->light);
            }
            proj = (u8*)((TrickyState*)state)->actionTargetObj;
            if (proj != NULL && ((GameObject*)proj)->anim.classId == 1)
            {
                fn_802961FC(proj, result);
            }
        }
        else if ((((TrickyState*)state)->flags2E8 & 0x20) != 0)
        {
            if (((FrozenByte2F6*)((TrickyState*)state)->pad2F6)->fadeCounter == 0)
            {
                Sfx_PlayFromObjectIntReturnLegacy((int)obj, SFXTRIG_fox_kick2);
                ((FrozenByte2F6*)((TrickyState*)state)->pad2F6)->fadeCounter = 0x1f;
            }
            Obj_StartModelFadeIn((GameObject*)obj, 0x12c);
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

void baddieInstantiateWeapon(GameObject* obj, int state)
{
    int parentSetup;
    void* child;
    int setup;

    parentSetup = *(int*)&(obj)->anim.placementData;
    if ((*(s16*)&((TrickyState*)state)->currentTime != *(s16*)(state + 0x2b6)) && ((obj)->anim.alpha != 0))
    {
        if ((obj)->childObjs[0] != NULL)
        {
            child = (obj)->childObjs[0];
            ObjLink_DetachChild(obj, child);
            Obj_FreeObject((GameObject*)child);
        }
        if (Obj_IsLoadingLocked() != 0)
        {
            if (*(s16*)(state + 0x2b6) > 0)
            {
                setup = (int)Obj_AllocObjectSetup(0x20, *(s16*)(state + 0x2b6));
                *(u8*)(setup + 5) = *(u8*)(setup + 5) | (((BaddieInstantiateWeaponPlacement*)parentSetup)->unk5 & 0x18);
                child = Obj_SetupObject((ObjPlacement*)setup, 4, (obj)->anim.mapEventSlot, -1, (obj)->anim.parent);
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

u8 baddieTargetFn_8014a150(GameObject* obj, int state, void* from, void* to)
{
    u8 traceHit[4];
    s16 toGrid[4];
    s16 fromGrid[4];
    Vec probe;
    Vec delta;
    TrackBBoxHit bboxHit;
    s16 setupId;
    u8 visible;
    int keepGroundOffset;

    traceHit[0] = 0;
    visible = 0;
    if (((TrickyState*)state)->actionTargetObj != NULL)
    {
        probe.x = *(f32*)((int)from + 0);
        probe.y = *(f32*)((int)from + 4);
        probe.z = *(f32*)((int)from + 8);
        keepGroundOffset = 1;
        setupId = (obj)->anim.seqId;
        if (((((setupId != 0x613) && (setupId != 0x642)) && (setupId != 0x3fe)) &&
             ((setupId != 0x7c6) && (setupId != 0x7c8))) &&
            ((setupId != 0x251) && (setupId != 0x851)))
        {
            probe.y += lbl_803E25A0;
            keepGroundOffset = 0;
        }
        voxmaps_worldToGrid((f32*)&probe, fromGrid);
        probe.x = *(f32*)((int)to + 0);
        probe.y = lbl_803E25A0 + *(f32*)((int)to + 4);
        probe.z = *(f32*)((int)to + 8);
        voxmaps_worldToGrid((f32*)&probe, toGrid);
        PSVECSubtract((Vec*)from, &probe, &delta);
        if (PSVECMag(&delta) < enemySightRange)
        {
            if (*(u32*)&(obj)->anim.parent == 0)
            {
                visible = voxmaps_traceLine((VoxPos*)toGrid, (VoxPos*)fromGrid, NULL, traceHit, 0);
            }
            if ((keepGroundOffset == 0) && (traceHit[0] == 1))
            {
                visible = 1;
            }
        }
    }
    if ((visible != 0) && ((((TrickyState*)state)->controlFlags & TRICKY_CONTROL_FLAG_BBOX_BLOCKS_SIGHT) != 0))
    {
        if (objBboxFn_800640cc((f32*)from, (f32*)&probe, lbl_803E256C, 0, &bboxHit, obj,
                               ((TrickyState*)state)->unk261, -1, 0, 0) != 0)
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
    TrackBBoxHit bboxHit;
    s16 baseAngle;
    u16 i;
    u8 visible;
    f32 angle;
    s16 setupId;

    *(struct VisBits16*)&visibilityBits[0] = *(struct VisBits16*)&gTrickyVisibilityBitsInit[0];
    probe.x = ((GameObject*)obj)->anim.localPosX;
    probe.y = lbl_803E25A0 + ((GameObject*)obj)->anim.localPosY;
    probe.z = ((GameObject*)obj)->anim.localPosZ;
    voxmaps_worldToGrid((f32*)&probe, baseGrid);
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
        angle = (lbl_803E25B4 * (f32)(s32)((s32)baseAngle + ((u32)(u16)i << 0xe))) / lbl_803E25B8;
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
        voxmaps_worldToGrid((f32*)&probe, probeGrid);
        PSVECSubtract((Vec*)(obj + 0x18), &probe, &delta);
        if (PSVECMag(&delta) < enemySightRange)
        {
            if (*(u32*)&((GameObject*)obj)->anim.parent != 0)
            {
                visible = 1;
            }
            else
            {
                visible = voxmaps_traceLine((VoxPos*)probeGrid, (VoxPos*)baseGrid, NULL, traceHit, 0);
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
            if (objBboxFn_800640cc((f32*)(obj + 0x18), (f32*)&probe, lbl_803E256C, 0, &bboxHit,
                                   (GameObject*)obj,
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

void Tricky_applyFloorResponse(GameObject* obj, int state)
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
            f32 sd = nearestSpecialY - (obj)->anim.localPosY;
            (obj)->anim.velocityY = sd * oneOverTimeDelta;
        }
        else if ((flags & TRICKY_CONTROL_FLAG_OFFSET_FLOOR_Y) != 0)
        {
            f32 dy = nearestFloorY - (obj)->anim.localPosY;
            if ((dy > lbl_803E25BC) && (dy < lbl_803E25A0))
            {
                f32 od = lbl_803E25C0 + dy;
                (obj)->anim.velocityY = od * oneOverTimeDelta;
                ((TrickyState*)state)->flags2DC |= TRICKY_STATE2DC_FLAG_FLOOR_OFFSET_APPLIED;
            }
        }
        else
        {
            f32 dy = nearestFloorY - (obj)->anim.localPosY;
            if ((dy > lbl_803E25BC) && (dy < lbl_803E25A0))
            {
                (obj)->anim.velocityY = dy * oneOverTimeDelta;
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
        (obj)->anim.velocityY = lbl_803E2574;
        ((TrickyState*)state)->flags2DC |= TRICKY_STATE2DC_FLAG_FLOOR_SNAP_APPLIED;
    }
    if ((((TrickyState*)state)->controlFlags & 0x00200000) != 0)
    {
        ObjPath_GetPointWorldPositionArray(obj, 2, 2, points);
        objAudioFn_8006edcc((int)obj, ((TrickyState*)state)->animEventMask, 7, points, (void*)(state + 4),
                            ((TrickyState*)state)->unk310, lbl_803E256C);
    }
}

void Tricky_findNearbyFloorHeights(GameObject* obj, int state, f32* nearestFloorY, f32* nearestSpecialY)
{
    TrackGroundHit** hitList[2];
    u16 hitCount;
    u16 i;
    TrackGroundHit* hit;
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
    hitCount = (u16)hitDetectFn_80065e50(obj, (obj)->anim.localPosX, (obj)->anim.localPosY,
                                         (obj)->anim.localPosZ, hitList, 0, 0);
    *nearestFloorY = (obj)->anim.localPosY;
    *nearestSpecialY = (obj)->anim.localPosY;
    nearestSpecialDelta = nearestFloorDelta = lbl_803E25C8;
    i = 0;
    ((TrickyState*)state)->flags2DC &= ~TRICKY_STATE2DC_FLAG_SPECIAL_FLOOR_FOUND;
    zero = lbl_803E2574;
    ((TrickyState*)state)->nearestSpecialDeltaY = zero;
    *(s8*)&((TrickyState*)state)->surfaceFlags &= ~TRICKY_SURFACE_FLAG_HAS_NEARBY_FLOOR;
    for (; i < hitCount; i++)
    {
        hit = hitList[0][i];
        hitY = hit->height;
        dy = hitY - (obj)->anim.localPosY;
        absDy = dy;
        if (dy < zero)
        {
            absDy = -dy;
        }
        if ((s8)hit->surfaceType == 0xe)
        {
            if (absDy < nearestSpecialDelta)
            {
                ((TrickyState*)state)->nearestSpecialDeltaY = dy;
                *(s8*)&((TrickyState*)state)->surfaceFlags |= TRICKY_SURFACE_FLAG_HAS_NEARBY_FLOOR;
                nearestSpecialDelta = absDy;
                *nearestSpecialY = hitList[0][i]->height;
                if (((TrickyState*)state)->nearestSpecialDeltaY > lbl_803E25A0)
                {
                    ((TrickyState*)state)->flags2DC |=
                        (TRICKY_STATE2DC_FLAG_SPECIAL_FLOOR_FOUND | TRICKY_STATE2DC_FLAG_FLOOR_SNAP_APPLIED);
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

void Tricky_render(GameObject* obj, int p2, int p3, int p4, int p5, char doRender)
{
    u8 mode;
    int i;
    int pathState;
    int pathPoint;
    s16* pathInfo;
    int state;

    if (doRender != '\0')
    {
        state = *(int*)&(obj)->extra;
        objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E23E8);
        pathState = *(int*)&(obj)->extra;
        i = 0;
        pathPoint = pathState;
        do
        {
            ObjPath_GetPointWorldPosition(obj, i + 4, (float*)(pathPoint + 0x3d8), (float*)(pathPoint + 0x3dc),
                                          (float*)(pathPoint + 0x3e0), 0);
            pathPoint = pathPoint + 0xc;
            i = i + 1;
        } while (i < 4);
        ObjPath_GetPointWorldPosition(obj, 8, (float*)(pathState + 0x408), (float*)(pathState + 0x40c),
                                      (float*)(pathState + 0x410), 0);
        pathInfo = objModelGetVecFn_800395d8(obj, 0);
        *(s16*)(pathState + 0x414) = pathInfo[1];
        if ((((TrickyState*)state)->stateFlags & 0x10) != 0)
        {
            switch (((TrickyState*)state)->stateIndex)
            {
            case 2:
                skeetla_spawnLinkedSparks((int)obj);
                break;
            case 3:
                if (((TrickyState*)state)->substate == 4)
                {
                    skeetla_spawnLinkedSparks((int)obj);
                }
                break;
            }
            if ((((((TrickyState*)state)->stateFlags & 0x200) == 0) && (((TrickyState*)state)->stateIndex == 0xb)) &&
                (((TrickyState*)state)->substate >= 3))
            {
                if (((TrickyState*)state)->substate != 3)
                {
                    ((GameObject*)((TrickyState*)state)->unk700)->anim.localPosX = ((TrickyState*)state)->renderPosX;
                    ((GameObject*)((TrickyState*)state)->unk700)->anim.localPosY = ((TrickyState*)state)->renderPosY;
                    ((GameObject*)((TrickyState*)state)->unk700)->anim.localPosZ = ((TrickyState*)state)->renderPosZ;
                }
                objRenderModelAndHitVolumes(*(int*)&((TrickyState*)state)->unk700, p2, p3, p4, p5, lbl_803E23E8);
            }
        }
        Tricky_emitQueuedPathParticles((int)obj, state);
        ObjPath_GetPointWorldPositionArray(obj, 4, 4, (float*)((TrickyState*)state)->pad7D8);
        ((TrickyState*)state)->particleTimer = ((TrickyState*)state)->particleTimer - timeDelta;
        if (((TrickyState*)state)->particleTimer > lbl_803E23DC)
        {
            objParticleFn_80099d84((GameObject*)obj, lbl_803E253C, 6, lbl_803E23E8, 0);
        }
    }
    return;
}

void Tricky_hitDetect(GameObject* obj)
{
    f32 dy;
    f32 y;
    int* objects;
    int i;
    void* firepipeObj;
    int state;
    f32 height;
    int count[2];

    state = *(int*)&obj->extra;
    y = obj->anim.localPosY;
    dy = (y - obj->anim.previousLocalPosY >= lbl_803E23DC) ? y - obj->anim.previousLocalPosY
                                                           : -(y - obj->anim.previousLocalPosY);
    if (lbl_803E23E8 == dy)
    {
        if (y == obj->anim.worldPosY)
        {
            ((TrickyStatusFlags58*)&((TrickyState*)state)->statusFlags)->heightTracking = 1;
            *(s32*)&((TrickyState*)state)->heightTrackObjId = -1;
            ((TrickyState*)state)->trackedHeight = lbl_803E23DC;
        }
    }
    else
    {
        firepipeObj = ObjList_FindObjectById(TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID);
        if ((firepipeObj != 0) && (getXZDistance(&obj->anim.worldPosX, (f32*)((int)firepipeObj + 0x18)) < lbl_803E2540))
        {
            ((TrickyStatusFlags58*)&((TrickyState*)state)->statusFlags)->heightTracking = 1;
            ((TrickyState*)state)->heightTrackObjId = TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID;
            ((TrickyState*)state)->trackedHeight = lbl_803E23DC;
        }
    }
    if ((((TrickyState*)state)->statusFlags >> 5 & 1) != 0u)
    {
        {
            int* t = (int*)ObjGroup_GetObjects(TRICKY_HEIGHT_TRACK_GROUP, count);
            i = 0;
            objects = t;
        }
        for (; i < count[0]; i++)
        {
            height = objFn_801948c0(*objects, TRICKY_HEIGHT_TRACK_MODEL_SLOT);
            if (*(s32*)&((TrickyState*)state)->heightTrackObjId == -1)
            {
                dy = (height - obj->anim.localPosY >= lbl_803E23DC) ? height - obj->anim.localPosY
                                                                    : -(height - obj->anim.localPosY);
                if (dy < lbl_803E24B8)
                {
                    ((TrickyState*)state)->heightTrackObjId =
                        ((ObjPlacement*)*(int*)&((GameObject*)*objects)->anim.placementData)->mapId;
                }
            }
            if (((TrickyState*)state)->heightTrackObjId ==
                (u32)((ObjPlacement*)*(int*)&((GameObject*)*objects)->anim.placementData)->mapId)
            {
                if ((((TrickyState*)state)->trackedHeight != lbl_803E23DC) &&
                    (((TrickyState*)state)->trackedHeight == height))
                {
                    ((TrickyStatusFlags58*)&((TrickyState*)state)->statusFlags)->heightTracking = 0;
                }
                else
                {
                    obj->anim.localPosY = height;
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

int Tricky_getExtraSize(void)
{
    return 0x83c;
}

u8 Tricky_func0E(int* obj)
{
    return *((u8*)((int**)obj)[0xb8 / 4][0x0 / 4] + 0x1);
}
u8 Tricky_render2(int* obj)
{
    return *((u8*)((int**)obj)[0xb8 / 4][0x0 / 4] + 0x0);
}

int Tricky_getCurrentCommandType(int* obj, int* out)
{
    *out = *((s8*)obj[0xb8 / 4] + 0xd);
    return 1;
}

#pragma opt_common_subs off
void trickyFn_801451d8(GameObject* obj, int state)
{
    u8 pathBytes[16];
    u32 pathByte = Objfsa_GetWalkGroupIndexAtPoint((void*)((int)obj + 0x18), 0);

    pathBytes[0] = pathByte;
    if (pathByte == 0)
    {
        int pathId = Objfsa_GetPatchGroupIdAtPoint((void*)((int)obj + 0x18));
        if (pathId != 0)
        {
            walkPath_writeU16LE(pathId & 0xffff, pathBytes);
        }
    }
    if (pathBytes[0] != 0)
    {
        f32 resetTimer;

        ((TrickyState*)state)->walkGroup = pathBytes[0];
        ((TrickyState*)state)->stateIndex = 1;
        ((TrickyState*)state)->substate = 0;
        resetTimer = lbl_803E23DC;
        ((TrickyState*)state)->cooldownA = resetTimer;
        ((TrickyState*)state)->cooldownB = resetTimer;
        *(u32*)&((TrickyState*)state)->stateFlags = *(u32*)&((TrickyState*)state)->stateFlags & (u64)~0x10u;
        *(u32*)&((TrickyState*)state)->stateFlags = *(u32*)&((TrickyState*)state)->stateFlags & (u64)~0x10000u;
        *(u32*)&((TrickyState*)state)->stateFlags = *(u32*)&((TrickyState*)state)->stateFlags & (u64)~0x20000u;
        *(u32*)&((TrickyState*)state)->stateFlags = *(u32*)&((TrickyState*)state)->stateFlags & (u64)~0x40000u;
        *(s8*)&((TrickyState*)state)->commandPhase = -1;
    }
    if (gTrickyHelperObject == 0)
    {
        int setup = (int)Obj_AllocObjectSetup(0x18, 0x25);
        gTrickyHelperObject = (int)Obj_SetupObject((ObjPlacement*)setup, 4, -1, -1, obj->anim.parent);
    }
    ((TrickyByteFlags*)&((TrickyState*)state)->statusFlags)->bit7 = 1;
}
#pragma opt_common_subs reset

void Tricky_func11(int* obj)
{
    register u32* p = (u32*)obj[0xb8 / 4];
    if (mainGetBit(GAMEBIT_Tricky_Usable))
    {
        p[0x54 / 4] |= 0x10000LL;
    }
}

int Tricky_func13(int* obj)
{
    u8 mode = *((u8*)obj[0xb8 / 4] + 8);
    if (mode == 8 || mode == 0xe)
        return 1;
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
            *(f32*)((u8*)state + 0x710) = (f32)(int)randomGetRange(0x168, 0x28);
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
    if (mainGetBit(GAMEBIT_Tricky_Usable) != 0)
    {
        r = TRICKY_ABILITY_FIND_SECRET | TRICKY_ABILITY_STAY;
        if (mainGetBit(GAMEBIT_ITEM_TrickyCall_Got) != 0)
            r |= TRICKY_ABILITY_CALL;
        if (mainGetBit(GAMEBIT_ITEM_TrickyBall_Bought) != 0)
            r |= TRICKY_ABILITY_THROW_BALL;
        if (mainGetBit(GAMEBIT_ITEM_TrickyFlame_Got) != 0)
            r |= TRICKY_ABILITY_FLAME;
    }
    return r;
}

void trickyReportError(const char* fmt, ...)
{
}

void trickyDebugPrint(const char* fmt, ...)
{
}

u8* Tricky_findNearestGroup4BObject(u8* obj, TrickyState* state)
{
    int* objs;
    int count[1];
    u8* result;
    f32 d;
    f32 bestD;
    int i;

    result = 0;
    objs = (int*)ObjGroup_GetObjects(TRICKYWARP_OBJ_GROUP, count);
    d = getXZDistance(&((GameObject*)state->playerObj)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
    if ((d >= lbl_803E2538) || (state->cooldownA > lbl_803E23DC))
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

void trickyFn_80144f50(GameObject* obj, int state)
{
    int sfxState;
    int isInWater;
    u32 sfxDisabled;
    u32 transitionFlag;

    if (trickyFoodFn_8014460c(obj, state) == 0)
    {
        ((TrickyState*)state)->wanderTargetX =
            (obj)->anim.worldPosX - mathSinf((lbl_803E2454 * (f32) * (s16*)obj) / lbl_803E2458);
        *(f32*)&((TrickyState*)state)->wanderTargetY = (obj)->anim.worldPosY;
        ((TrickyState*)state)->wanderTargetZ =
            (obj)->anim.worldPosZ - mathCosf((lbl_803E2454 * (f32) * (s16*)obj) / lbl_803E2458);

        if (trickyFn_8013b368(obj, lbl_803E247C, state) != 1)
        {
            ((TrickyState*)state)->idleSfxTimer -= timeDelta;
            if (((TrickyState*)state)->idleSfxTimer <= lbl_803E23DC)
            {
                ((TrickyState*)state)->idleSfxTimer = (f32)(int)randomGetRange(0x1f4, 0x2ee);
                sfxState = *(int*)&(obj)->extra;
                sfxDisabled = (*(u8*)(sfxState + 0x58) >> 6) & 1;
                if ((sfxDisabled == 0) && (((obj)->anim.currentMove >= 0x30) || ((obj)->anim.currentMove < 0x29)) &&
                    (Sfx_IsPlayingFromObjectChannelIntLegacy((int)obj, 0x10) == 0))
                {
                    objAudioFn_800393f8Legacy(obj, (void*)(sfxState + 0x3a8), 0x360, 0x500, -1, 0);
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
                objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
                ((TrickyState*)state)->cooldownC = lbl_803E2440;
                ((TrickyState*)state)->particleTimer = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            }
            else
            {
                switch ((obj)->anim.currentMove)
                {
                case 0x31:
                    break;
                case 0xd:
                    transitionFlag = ((TrickyState*)state)->stateFlags & 0x08000000;
                    if (transitionFlag != 0)
                    {
                        objAnimFn_8013a3f0((int)obj, 0x31, lbl_803E243C, 0);
                    }
                    break;
                default:
                    objAnimFn_8013a3f0((int)obj, 0xd, lbl_803E2444, 0);
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
char sSidekickCommandDebugTextBlock[] = {
    0x73, 0x69, 0x64, 0x65, 0x43, 0x6F, 0x6D, 0x6D, 0x61, 0x6E, 0x64, 0x45, 0x6E, 0x61, 0x62, 0x6C, 0x65, 0x20,
    0x77, 0x61, 0x72, 0x6E, 0x69, 0x6E, 0x67, 0x3A, 0x20, 0x6E, 0x65, 0x65, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x69,
    0x6E, 0x63, 0x72, 0x65, 0x61, 0x73, 0x65, 0x20, 0x4D, 0x41, 0x58, 0x5F, 0x43, 0x4F, 0x4D, 0x4D, 0x5F, 0x50,
    0x52, 0x45, 0x53, 0x45, 0x4E, 0x54, 0x0A, 0x00, 0x00, 0x00, 0x68, 0x69, 0x74, 0x73, 0x3A, 0x20, 0x25, 0x64,
    0x20, 0x25, 0x64, 0x20, 0x25, 0x64, 0x20, 0x25, 0x64, 0x20, 0x25, 0x64, 0x20, 0x25, 0x64, 0x20, 0x25, 0x64,
    0x20, 0x25, 0x64, 0x00, 0x00, 0x00, 0x0A, 0x45, 0x6E, 0x65, 0x72, 0x67, 0x79, 0x3A, 0x20, 0x25, 0x64, 0x2F,
    0x25, 0x64, 0x0A, 0x00, 0x66, 0x69, 0x6E, 0x64, 0x20, 0x63, 0x6F, 0x6D, 0x6D, 0x61, 0x6E, 0x64, 0x20, 0x75,
    0x73, 0x65, 0x64, 0x20, 0x6F, 0x6E, 0x20, 0x74, 0x68, 0x65, 0x20, 0x77, 0x72, 0x6F, 0x6E, 0x67, 0x20, 0x6F,
    0x62, 0x6A, 0x65, 0x63, 0x74, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

u8 lbl_8031DBD8[12] = {0};
u8 lbl_8031DBE4[12] = {0};
