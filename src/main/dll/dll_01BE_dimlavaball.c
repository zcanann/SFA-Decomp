/* === moved from main/dll/DIM/DIMboulder.c [801AE0EC-801AE100) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "main/effect_interfaces.h"
#include "main/objseq.h"



/*
 * Per-object extra state for the IM ice-mountain event controller
 * (imicemountain_getExtraSize == 0x14).
 */
typedef struct IMIceMountainState
{
    u8 eventState; /* 0..7 event machine (imicemountain_updateEventState) */
    u8 pad01[3];
    s32 latchFlags; /* SCGameBitLatch record; bit 1 = latch fired this frame */
    s8 warpCountdown; /* state 6: frames until warpToMap(0x1A) */
    u8 pad09;
    s16 musicTrack; /* -1 or 26; Music_Trigger edge latch */
    u8 mapEventState; /* MEVT_QUERY result at init (1/2/5) */
    u8 pad0D[3];
    f32 warningTextTimer; /* shows text 0x351 while above the floor value */
} IMIceMountainState;

STATIC_ASSERT(sizeof(IMIceMountainState) == 0x14);

/*
 * Per-object extra state for the magiclight proximity light
 * (magiclight_getExtraSize == 0x14 for non-0x172 types).
 */
typedef struct MagicLightState
{
    f32 triggerRadius; /* preset by subtype */
    s16 lifetime; /* rand(200,600) at init */
    s16 enterAction; /* L-action when the player enters the radius */
    s16 leaveAction; /* L-action when the player leaves radius + hysteresis */
    u8 pad0A;
    s8 inRange; /* hysteresis latch */
    s8 subtype; /* params+0x1A */
    u8 pad0D[3];
    s16 unk10; /* 301 at init */
    u8 pad12[2];
} MagicLightState;

STATIC_ASSERT(sizeof(MagicLightState) == 0x14);

/*
 * Per-object extra state for the dll_16C map-event boulder proxy
 * (dll_16C_getExtraSize == 0x24).
 */
typedef struct Dll16CState
{
    void* linkedObj; /* group-10 object matched by type (364/367) */
    f32 unk04; /* set on anim event 2 */
    f32 snapX; /* path point snapshot taken on anim event 2 */
    f32 snapY;
    f32 snapZ;
    f32 pathPointX; /* path point 1 world position, refreshed in render */
    f32 pathPointY;
    f32 pathPointZ;
    u8 opacity; /* distance fade; 0xFF when unlinked */
    s8 subObjIndex; /* lbl_802C2308 id selector; -1 = clear (anim event 3) */
    s8 subObjIndexApplied;
    u8 pad23;
} Dll16CState;

STATIC_ASSERT(sizeof(Dll16CState) == 0x24);

/*
 * Per-object extra state for the crrockfall falling rock
 * (crrockfall_getExtraSize == 0x14).
 */
typedef struct CrRockfallCfgEntry
{
    f32 unk00;
    s32 landSfx; /* 0 = none */
    f32 restOffsetY; /* scaled by obj scale, added to floorY at rest */
} CrRockfallCfgEntry;

typedef struct CrRockfallState
{
    CrRockfallCfgEntry* cfg; /* lbl_803236B8 entry 0, or entry 1 for type 0x600 */
    f32 floorY; /* probed landing height */
    f32 startY; /* obj Y at init; fade fraction reference */
    u8 mode; /* 0 armed, 1 falling, 2 resting, 3 shattered */
    u8 fallStarted;
    u8 floorFound;
    u8 pad0F;
    s16 fallDelay; /* params+0x1E; counts down while the player is in range */
    u8 pad12[2];
} CrRockfallState;

STATIC_ASSERT(sizeof(CrRockfallState) == 0x14);


extern uint GameBit_Get(int eventId);
extern undefined4 FUN_80017ac8();
extern undefined4 ObjHits_DisableObject();

extern ObjectTriggerInterface** gObjectTriggerInterface;

/*
 * --INFO--
 *
 * Function: FUN_801ac248
 * EN v1.0 Address: 0x801AC248
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AC4FC
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801ad984
 * EN v1.0 Address: 0x801AD984
 * EN v1.0 Size: 420b
 * EN v1.1 Address: 0x801AD9F4
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801adca0
 * EN v1.0 Address: 0x801ADCA0
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x801ADD98
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_801addec
 * EN v1.0 Address: 0x801ADDEC
 * EN v1.0 Size: 896b
 * EN v1.1 Address: 0x801ADEE4
 * EN v1.1 Size: 576b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */



#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setAnimEvent((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMode((a), (b))
#define MEVT_QUERY(a)         (*gMapEventInterface)->getMode((a))

/* EN v1.0 0x801AC9C0  size: 828b  imicemountain_init: clear the ice-mountain
 * gamebit block, arm the map-event triggers, then branch on the queried level
 * state to set the boulder's start state and fire the appropriate triggers. */
#pragma scheduling off
#pragma peephole reset
#pragma scheduling reset
#undef MEVT_TRIGGER
#undef MEVT_SET
#undef MEVT_QUERY





extern u32 randomGetRange(int min, int max);

/* EN v1.0 0x801AD684  size: 344b  magiclight_init: seed header + update fn;
 * for the non-172 variants pick a random lifetime and, for type 0x16b, map
 * the spawn subtype to a light-pair / intensity preset. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


void imicepillar_free(void);

/* 8b "li r3, N; blr" returners. */
int imicepillar_getExtraSize(void);
int imicepillar_getObjectTypeId(void);

/* Pattern wrappers. */
extern void* lbl_803DDB40;

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
#pragma peephole reset

#pragma peephole off

#pragma peephole reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset


#pragma peephole reset
#pragma scheduling reset

/* if (o->_X == K) return A; else return B; */
#pragma peephole off
#pragma peephole reset



/* conditional init/free pair. */

/* dll_16C_hitDetect: if extra->p && vtable(p,0x38)()==2, sync its transform into obj. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

/* dll_16C_init: install callback, configure sub-obj, init extra fields from arg. */
#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern void warpToMap(int mapId, int flags);

#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setAnimEvent((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMode((a), (b))

/* EN v1.0 0x801AC248  imicemountain_updateEventState: 8-state ice-mountain event machine dispatched
 * through jumptable_80323698 (states 1..7; state 0 idles). */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
#undef MEVT_TRIGGER
#undef MEVT_SET

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int kind, int id);
extern u8 lbl_802C2308[];


/* dll_16C_SeqFn: per-frame sequence callback - manage the spawned sub-object
 * from a small id table, then run the map-event sub-object state callbacks. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

/* dll_16C_syncSubObjectTransform: snapshot the map-event sub-object's transform into the boulder
 * extra block, optionally re-issuing a move on the sub-object first. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern void Music_Trigger(int track, int flag);
extern void SCGameBitLatch_Update(void* state, int mask, int a, int b, int c, int d);
extern f32 timeDelta;

/* imicemountain_update: lazy-spawn the ambient effects, run the active state,
 * fade the warning timer, drive the music latch, then refresh the gamebit latches. */
#pragma scheduling off
#pragma scheduling reset

extern u8 framesThisStep;

/* dll_16C_update: re-link the spawned sub-object, then while active/visible run
 * its move and fade opacity by distance to the player. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern u8 lbl_803236B8[];

/* crrockfall_init: derive the per-rock scale from the placement params, size the
 * capsule hitbox from the sub-object bounds, set up render flags, and pick the
 * state-table variant by object type. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


/* crrockfall_update: drive the falling-rock state machine - fade-in opacity by
 * height/distance, trigger the fall when the player is in range, integrate the
 * fall, then shatter (sfx + explosion) on impact. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling reset

#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/DIM/DIMcannon.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"

typedef struct Lavaball1bePlacement
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x20 - 0x19];
} Lavaball1bePlacement;


typedef struct Lavaball1bfPlacement
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1E - 0x19];
    s16 unk1E;
    u8 pad20[0x24 - 0x20];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} Lavaball1bfPlacement;


/* imanimspacecraft_getExtraSize == 0x4. */
typedef struct ImAnimSpacecraftState
{
    s16 blinkTimer; /* 0x00 */
    u8 maskBits; /* 0x02: per-event toggle bits (bit4..6 = group) */
    u8 flags; /* 0x03: 2 = blink phase, 4/8 = SeqFn toggles */
} ImAnimSpacecraftState;

STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

/* imspacethruster_getExtraSize == 0xc. */
typedef struct ImSpaceThrusterState
{
    u8 kind; /* 0x00: thruster slot from def+0x19 */
    u8 phase; /* 0x01 */
    s16 blendTimer; /* 0x02 */
    void* bufA; /* 0x04: mmAlloc'd getTabEntry rows */
    void* bufB; /* 0x08 */
} ImSpaceThrusterState;

STATIC_ASSERT(sizeof(ImSpaceThrusterState) == 0xC);

/* link_levcontrol_getExtraSize == 0x10. */
typedef struct LinkLevControlState
{
    s8 areaCell; /* 0x00 */
    u8 pad01[3];
    int unk04; /* 0x04: init -1 */
    int musicTrack; /* 0x08 */
    int latch; /* 0x0c: SCGameBitLatch block */
} LinkLevControlState;

STATIC_ASSERT(sizeof(LinkLevControlState) == 0x10);

/* lavaball1be extra (getExtraSize 0x14 for the non-0x1fa variant). */
typedef struct Lavaball1beState
{
    char* targetObj; /* 0x00: ObjList_FindObjectById(linkedId) */
    u8* light; /* 0x04 */
    f32 floorY; /* 0x08: spawn height; falling below it re-arms */
    int linkedId; /* 0x0c */
    u8 flags; /* 0x10: 8 = ticked, 0x10 = dormant, 0x20 = whistle sfx */
    u8 explodeCooldown; /* 0x11 */
    u8 pad12[2];
} Lavaball1beState;

STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

/* lavaball1bf_getExtraSize == 0x1c (launcher). */
typedef struct Lavaball1bfState
{
    u8 pad00[8];
    int* spawnedObj; /* 0x08: the 0x18d cannon object */
    f32 fireTimer; /* 0x0c */
    f32 firePeriod; /* 0x10 */
    s16 gateA; /* 0x14 */
    s16 pending; /* 0x16 */
    u8 gateB; /* 0x18 */
    u8 pad19;
    u8 gbState; /* 0x1a */
    u8 soloLatch; /* 0x1b */
} Lavaball1bfState;

STATIC_ASSERT(sizeof(Lavaball1bfState) == 0x1C);

static inline int* DIMcannon_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

extern undefined4 ObjHits_EnableObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80057690();
extern undefined8 FUN_80286830();
extern undefined4 FUN_8028687c();

extern EffectInterface** gPartfxInterface;


/*
 * --INFO--
 *
 * Function: imicepillar_render
 * EN v1.0 Address: 0x801AE100
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801AE134
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_801ae0_dropped_old_imicepillar_render(undefined8 param_1, undefined8 param_2, undefined8 param_3,
                                               undefined8 param_4,
                                               undefined8 param_5, undefined8 param_6, undefined8 param_7,
                                               undefined8 param_8,
                                               int param_9)
{
    if (*(int*)&((GameObject*)param_9)->childObjs[0] != 0)
    {
        FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     *(int*)&((GameObject*)param_9)->childObjs[0]);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ae184
 * EN v1.0 Address: 0x801AE184
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801AE160
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ae184(undefined4 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4,
                  undefined4 param_5, char param_6)
{
    extern undefined4 FUN_801adca0(); /* #57 */
    extern undefined4 ObjPath_GetPointWorldPosition(); /* #57 */
    u8 uVar1;
    bool bVar2;
    undefined2* puVar3;
    uint uVar4;
    int iVar5;
    undefined4 uVar6;
    undefined2* puVar7;
    undefined4* puVar8;
    undefined8 uVar9;

    uVar9 = FUN_80286830();
    puVar3 = (undefined2*)((ulonglong)uVar9 >> 0x20);
    if (puVar3[0x23] == 0x373)
    {
        FUN_8003b818((int)puVar3);
    }
    else
    {
        uVar4 = GameBit_Get(0x6e);
        if ((uVar4 == 0) || (uVar4 = GameBit_Get(0x382), uVar4 != 0))
        {
            puVar8 = *(undefined4**)(puVar3 + 0x5c);
            puVar7 = (undefined2*)*puVar8;
            bVar2 = false;
            if ((puVar7 != (undefined2*)0x0) &&
                (iVar5 = (**(code**)(**(int**)(puVar7 + 0x34) + 0x38))(puVar7), iVar5 == 2))
            {
                bVar2 = true;
            }
            if (bVar2)
            {
                puVar3[3] = puVar3[3] | 8;
                uVar6 = FUN_80057690((int)puVar7);
                param_6 = (char)uVar6;
                FUN_801adca0(puVar3, puVar7, (int)uVar9, param_3, param_4, param_5, param_6,
                             (uint) * (byte*)(puVar8 + 8), 1);
            }
            else
            {
                puVar3[3] = puVar3[3] & ~0x8;
            }
            if ((param_6 != '\0') && (*(char*)(puVar8 + 8) != '\0'))
            {
                uVar1 = *(u8*)((int)puVar3 + 0x37);
                if (bVar2)
                {
                    *(char*)((int)puVar3 + 0x37) = *(char*)(puVar8 + 8);
                }
                FUN_8003b818((int)puVar3);
                ObjPath_GetPointWorldPosition(puVar3, 1, (float*)(puVar8 + 5), puVar8 + 6, (float*)(puVar8 + 7), 0);
                *(u8*)((int)puVar3 + 0x37) = uVar1;
            }
        }
    }
    FUN_8028687c();
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_801ae9e4
 * EN v1.0 Address: 0x801AE9E4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801AE9BC
 * EN v1.1 Size: 48b
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
 * Function: FUN_801aea18
 * EN v1.0 Address: 0x801AEA18
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801AE9EC
 * EN v1.1 Size: 76b
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
 * Function: FUN_801aea40
 * EN v1.0 Address: 0x801AEA40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AEA38
 * EN v1.1 Size: 148b
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
 * Function: FUN_801aea44
 * EN v1.0 Address: 0x801AEA44
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801AEACC
 * EN v1.1 Size: 72b
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
 * Function: FUN_801b0190
 * EN v1.0 Address: 0x801B0190
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801AFE04
 * EN v1.1 Size: 96b
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
 * Function: FUN_801b01e8
 * EN v1.0 Address: 0x801B01E8
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x801AFE64
 * EN v1.1 Size: 200b
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
void imicepillar_hitDetect(void);

void imicepillar_update(void);

void imicepillar_init(void);

void imicepillar_release(void);

void imicepillar_initialise(void);

ObjectDescriptor gIMIcePillarObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imicepillar_initialise,
    (ObjectDescriptorCallback)imicepillar_release,
    0,
    (ObjectDescriptorCallback)imicepillar_init,
    (ObjectDescriptorCallback)imicepillar_update,
    (ObjectDescriptorCallback)imicepillar_hitDetect,
    (ObjectDescriptorCallback)imicepillar_render,
    (ObjectDescriptorCallback)imicepillar_free,
    (ObjectDescriptorCallback)imicepillar_getObjectTypeId,
    imicepillar_getExtraSize,
};

void imanimspacecraft_modelMtxFn(void);

void imanimspacecraft_hitDetect(void);

void imanimspacecraft_release(void);

void imanimspacecraft_initialise(void);

void imspacethruster_hitDetect(void);

void imspacethruster_release(void);

void imspacethruster_initialise(void);

void imspacering_free(void);

void imspacering_hitDetect(void);

void imspacering_release(void);

void imspacering_initialise(void);

void imspaceringgen_hitDetect(void);

void imspaceringgen_release(void);

void imspaceringgen_initialise(void);

void lavaball1be_hitDetect(void)
{
}

void lavaball1be_release(void)
{
}

void lavaball1be_initialise(void)
{
}

void lavaball1bf_hitDetect(void);

void lavaball1bf_release(void);

void lavaball1bf_initialise(void);

/* 8b "li r3, N; blr" returners. */
int imanimspacecraft_getExtraSize(void);
int imanimspacecraft_getObjectTypeId(void);
int imspacethruster_getExtraSize(void);
int imspacethruster_getObjectTypeId(void);
int imspacering_getExtraSize(void);
int imspacering_getObjectTypeId(void);
int imspaceringgen_getExtraSize(void);
int imspaceringgen_getObjectTypeId(void);
int linkb_levcontrol_getExtraSize(void);
int link_levcontrol_getExtraSize(void);
int lavaball1bf_getExtraSize(void);
int lavaball1bf_getObjectTypeId(void);
int dimlogfire_getExtraSize(void);

/* Pattern wrappers. */
extern u32 lbl_803DDB48;
void imspaceringgen_free(void);

/* Init: clear obj->_F4 and record obj globally in lbl_803DDB48. */
void imspaceringgen_init(int* obj);

/* If obj->_F4 == 0, set it to 1; else early-return. */
void imanimspacecraft_update(int* obj);

/* Free: call vtable[6] on obj through global dll-services pointer. */
void imanimspacecraft_free(int* obj);

extern f32 lbl_803E4784;
extern char lbl_803AC948[];

void imanimspacecraft_init(int* obj);

/* setScale (test): is bit (1 << idx) set in obj->_b8->_2? Returns 1/0. */
int imanimspacecraft_setScale(int* obj, int bitIdx);

/* lavaball1bf "consume" hook: only clear pending flag if both gates set. */
void lavaball1bf_func11(int* obj);

/* lavaball1bf "request" hook: set pending if gated, return success. */
int lavaball1bf_setScale(int* obj);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4768;
extern f32 lbl_803E4780;
extern f32 lbl_803E4788;
extern f32 lbl_803E47B8;
extern f32 lbl_803E4810;

void imicepillar_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void imanimspacecraft_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void imspacethruster_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void imspacering_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void lavaball1bf_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* if (o->_X == K) return A; else return B;  pattern. */
int lavaball1be_getExtraSize(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == 0x1fa) return 0x0;
    return 0x14;
}

int lavaball1be_getObjectTypeId(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == 0x1fa) return 0x0;
    return 0x2;
}

/* chained byte mask. */
u32 imanimspacecraft_func0B(int* obj);
u32 lavaball1be_func11(int* obj) { return *((u8*)((int**)obj)[0xb8 / 4] + 0x10) & 0x10; }

int fn_801B0784(int obj, int delta);

extern void Music_Trigger(int id, int p2);
extern int getSaveGameLoadStatus(void);
extern void* Obj_GetPlayerObject(void);
extern int coordsToMapCell(f32 x, f32 z);

void link_levcontrol_free(int obj);

void link_levcontrol_update(int* obj);

extern void SCGameBitLatch_Update(void* p, int a, int b, int c, int d, int e);

void link_levcontrol_updateAreaMusic(int* obj);

extern void fn_80088870(u8 * a, u8 * b, u8 * c, u8 * d);
extern void envFxActFn_800887f8(int id);
extern u8 lbl_803239F0[];

void link_levcontrol_applyEnterAreaEffects(int* obj);

extern void ObjModel_SetBlendChannelTargets(int* model, int channel, int p3, int p4, f32 weight, int p6);
extern void ObjModel_SetBlendChannelWeight(int* model, int channel, f32 weight);
extern f32 lbl_803E47A8, lbl_803E47AC, lbl_803E47B0, lbl_803E47B4, lbl_803E4798, lbl_803E4788;
extern s16 lbl_80323818[], lbl_80323824[];

void imspacethruster_init(int* obj, u8* param2);

void link_levcontrol_init(int* obj);

extern u8 lbl_803238D8[];
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern int* getTrickyObject(void);
extern void fn_80138908(int* tricky, int mode);
extern f32 lbl_803E47C8;

typedef struct
{
    int flags;
    s8 cnt : 2;
    u8 stage : 3;
    u8 low : 3;
    u8 flag5 : 1;
    u8 pad5 : 7;
    u8 pad6[2];
    f32 timer;
    s16 music;
} LinkbLevState;

void linkb_levcontrol_init(int* obj);

void linkb_levcontrol_update(int* obj);

extern f32 lbl_803E47C0;
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
extern int Obj_AllocObjectSetup(int extraSize, int id);
extern f32 lbl_803E47C4;

typedef struct
{
    int* ringA;
    int* ringB;
    u8 visible;
} RingGenState;

void imspacering_init(s16* obj, s8* p);

void imspacering_update(s16* obj);

void imspaceringgen_render(int obj, int p1, int p2, int p3, int p4, s8 visible);

void imspaceringgen_update(s16* obj);

extern void ModelLightStruct_free(void* light);
extern void mm_free(void* p);

extern f32 lbl_803E4814;

void lavaball1bf_init(s16* obj, u8* p);

void lavaball1bf_free(int obj, int mode);

void lavaball1be_free(int obj)
{
    Lavaball1beState* inner = ((GameObject*)obj)->extra;
    if (inner->light != 0)
    {
        ModelLightStruct_free(inner->light);
        inner->light = 0;
    }
}

void imspacethruster_free(int obj);

void dimlogfire_free(int* obj, int mode);



extern void queueGlowRender(int* obj);


extern int modelLightStruct_getActiveState(int* p);
extern f32 lbl_803E47F0;

void lavaball1be_render(int* obj, int p2, int p3, int p4, int p5)
{
    Lavaball1beState* state = ((GameObject*)obj)->extra;
    if ((int*)state->light != NULL)
    {
        if (modelLightStruct_getActiveState((int*)state->light) != 0)
        {
            queueGlowRender((int*)state->light);
        }
    }
    ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E47F0);
}

extern void modelLightStruct_updateGlowAlpha(int p);
extern f32 lbl_803E47D0, lbl_803E47F4, lbl_803E47F8, lbl_803E47FC;
extern f32 lbl_803E47D4, lbl_803E47D8, lbl_803E47DC, lbl_803E47E0;
extern f32 lbl_803E4800, lbl_803E4804, lbl_803E4808;
extern u8 lbl_802C2318[];
extern void vecRotateZXY(void* in, void* out);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern int ObjList_FindObjectById(int id);
extern u8* objCreateLight(s16* obj, int b);
extern void modelLightStruct_setLightKind(u8* light, int value);
extern void modelLightStruct_setDiffuseColor(u8* light, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(u8* light, f32 a, f32 b);
extern void modelLightStruct_setupGlow(u8* light, int p3, int p4, int p5, int p6, int p7, f32 a);
extern void modelLightStruct_setGlowProjectionRadius(u8* light, f32 a);

typedef struct
{
    f32 x, y, z;
} LavaVec;

void lavaball1be_init(s16* obj, u8* p)
{
    Lavaball1beState* state;
    if (((GameObject*)obj)->anim.seqId == 0x1fa)
    {
        struct
        {
            LavaVec vec;
            s16 rot[3];
            u8 pad[18];
        } s;
        s.vec = *(LavaVec*)lbl_802C2318;
        s.rot[2] = 0;
        s.rot[1] = (s16)randomGetRange(-0x2ee0, 0x2ee0);
        s.rot[0] = (s16)randomGetRange(0, 0xfffe);
        vecRotateZXY((u8*)&s + 12, &s.vec);
        ((GameObject*)obj)->unkF4 = 0x4b;
        ((GameObject*)obj)->anim.velocityX = s.vec.x;
        ((GameObject*)obj)->anim.velocityY = s.vec.y;
        ((GameObject*)obj)->anim.velocityZ = s.vec.z;
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E47D4;
    }
    else
    {
        f32 vy;
        f32 vxz;
        int* sub;
        u8* light;

        ((GameObject*)obj)->anim.rotX = (s16)((s32) * (s8*)(p + 0x18) << 8);
        state = ((GameObject*)obj)->extra;
        vy = lbl_803E47D8 * (f32) * (s16*)(p + 0x1a);
        vxz = lbl_803E47D8 * (f32) * (s16*)(p + 0x1c);
        state->floorY = ((GameObject*)obj)->anim.localPosY;
        state->linkedId = *(int*)(p + 0x14);
        *(int*)(p + 0x14) = -1;
        ((GameObject*)obj)->anim.velocityX = vxz * -mathSinf(
            lbl_803E47DC * (f32)((GameObject*)obj)->anim.rotX / lbl_803E47E0);
        ((GameObject*)obj)->anim.velocityY = vy;
        ((GameObject*)obj)->anim.velocityZ = vxz * -mathCosf(
            lbl_803E47DC * (f32)((GameObject*)obj)->anim.rotX / lbl_803E47E0);
        sub = *(int**)&((GameObject*)obj)->anim.hitReactState;
        if (sub != NULL)
        {
            *((u8*)sub + 0x6a) = 0;
        }
        sub = (int*)((GameObject*)obj)->anim.modelState;
        if (sub != NULL)
        {
            ((GameObject*)obj)->anim.modelState->flags |= 0x810;
        }
        *(int*)&state->targetObj = ObjList_FindObjectById(state->linkedId);
        state->flags |= 0x10;
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->objectFlags |= 0x2000;
        state->light = objCreateLight(obj, 1);
        light = state->light;
        if (light != NULL)
        {
            modelLightStruct_setLightKind(light, 2);
            modelLightStruct_setDiffuseColor(state->light, 0xff, 0x80, 0, 0);
            modelLightStruct_setDistanceAttenuation(state->light, lbl_803E4800, lbl_803E4804);
            modelLightStruct_setupGlow(state->light, 0, 0xff, 0x80, 0, 0x64, lbl_803E4808);
            modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E4808);
        }
    }
}

void lavaball1be_update(s16* obj)
{
    extern void spawnExplosion(s16* obj, f32 scale, int a, int b, int c, int d, int e, int f, int g); /* #57 */
    extern int Sfx_PlayFromObject(int* obj, int sfxId); /* #57 */
    extern void Obj_FreeObject(void* o); /* #57 */
    Lavaball1beState* state;
    int* sub;

    if (((GameObject*)obj)->anim.seqId == 0x1fa)
    {
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)->anim.
            localPosX;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.
            localPosY;
        ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)->anim.
            localPosZ;
        (*gPartfxInterface)->spawnObject(obj, 0x1f5, NULL, 1, -1, NULL);
        ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX + framesThisStep * 0x374;
        ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY + framesThisStep * 0x12c;
        ((GameObject*)obj)->anim.velocityY = -(lbl_803E47D0 * timeDelta - ((GameObject*)obj)->anim.velocityY);
        ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - framesThisStep;
        if (((GameObject*)obj)->unkF4 < 0)
        {
            Obj_FreeObject(obj);
        }
    }
    else
    {
        state = ((GameObject*)obj)->extra;
        if (state->flags & 0x10)
        {
            ObjHits_DisableObject(obj);
        }
        else
        {
            f32 dt = timeDelta;
            u8 steps = framesThisStep;
            if (state->explodeCooldown != 0)
            {
                state->explodeCooldown--;
            }
            ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX + (steps << 6);
            ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY - (steps << 9);
            ((GameObject*)obj)->anim.velocityY = lbl_803E47F4 * dt + ((GameObject*)obj)->anim.velocityY;
            objMove((int)obj,
                    ((GameObject*)obj)->anim.velocityX * dt,
                    ((GameObject*)obj)->anim.velocityY * dt,
                    ((GameObject*)obj)->anim.velocityZ * dt);
            if (((GameObject*)obj)->anim.velocityY < lbl_803E47F8)
            {
                if (!(state->flags & 0x20))
                {
                    Sfx_PlayFromObject((int*)obj, 0x3dd);
                    state->flags |= 0x20;
                }
            }
            else
            {
                state->flags &= ~0x20;
            }
            sub = *(int**)&((GameObject*)obj)->anim.hitReactState;
            if (sub != NULL)
            {
                *((u8*)sub + 0x6e) = 0xb;
                *((u8*)sub + 0x6f) = 1;
                sub[0x48 / 4] = 0x10;
                sub[0x4c / 4] = 0x10;
                if (*(void**)&((ObjHitsPriorityState*)sub)->lastHitObject != NULL)
                {
                    if (state->explodeCooldown != 0)
                    {
                        spawnExplosion(obj, lbl_803E47FC, 0, 1, 0, 0, 0, 0, 0);
                    }
                    else
                    {
                        state->explodeCooldown = 0xa;
                        spawnExplosion(obj, lbl_803E47FC, 1, 1, 0, 0, 0, 0, 0);
                    }
                    state->flags |= 0x10;
                    ((GameObject*)obj)->anim.flags |= 0x4000;
                }
                if (((ObjAnimComponent*)sub)->bankIndex & 1)
                {
                    spawnExplosion(obj, lbl_803E47FC, 1, 1, 0, 0, 0, 0, 0);
                    state->flags |= 0x10;
                    ((GameObject*)obj)->anim.flags |= 0x4000;
                    return;
                }
            }
            if (((GameObject*)obj)->anim.localPosY < state->floorY)
            {
                state->flags |= 0x10;
            }
            if (!(state->flags & 8))
            {
                state->flags |= 8;
            }
            if ((void*)state->light != NULL && modelLightStruct_getActiveState((int*)state->light) != 0)
            {
                modelLightStruct_updateGlowAlpha((int)state->light);
            }
        }
    }
}

extern int* objFindTexture(int* obj, int a, int b);
extern f32 lbl_803E4770, lbl_803E4774, lbl_803E4778, lbl_803E477C;

int imanimspacecraft_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);

extern f32 lbl_803E478C, lbl_803E4790, lbl_803E4794, lbl_803E4798;

void imspacethruster_update(int* obj);


void lavaball1bf_update(int* obj);

void lavaball1be_setScale(s16* obj, int p2, int p3)
{
    Lavaball1beState* state;
    u8* setup;
    f32 vxz;
    f32 x;

    state = ((GameObject*)obj)->extra;
    setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    vxz = lbl_803E47D8 * (f32)p3;
    x = *(f32*)(*(char**)&state->targetObj + 0xc);
    ((GameObject*)obj)->anim.worldPosX = x;
    ((GameObject*)obj)->anim.localPosX = x;
    x = *(f32*)(*(char**)&state->targetObj + 0x10);
    ((GameObject*)obj)->anim.worldPosY = x;
    ((GameObject*)obj)->anim.localPosY = x;
    x = *(f32*)(*(char**)&state->targetObj + 0x14);
    ((GameObject*)obj)->anim.worldPosZ = x;
    ((GameObject*)obj)->anim.localPosZ = x;
    x = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousWorldPosX = x;
    ((GameObject*)obj)->anim.previousLocalPosX = x;
    x = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousWorldPosY = x;
    ((GameObject*)obj)->anim.previousLocalPosY = x;
    x = ((GameObject*)obj)->anim.localPosZ;
    ((GameObject*)obj)->anim.previousWorldPosZ = x;
    ((GameObject*)obj)->anim.previousLocalPosZ = x;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)((Lavaball1bePlacement*)setup)->unk18 << 8);
    ((GameObject*)obj)->anim.velocityX = vxz * -mathSinf(
        lbl_803E47DC * (f32)((GameObject*)obj)->anim.rotX / lbl_803E47E0);
    ((GameObject*)obj)->anim.velocityY = lbl_803E47D8 * (f32)p2;
    ((GameObject*)obj)->anim.velocityZ = vxz * -mathCosf(
        lbl_803E47DC * (f32)((GameObject*)obj)->anim.rotX / lbl_803E47E0);
    ((GameObject*)obj)->anim.flags &= ~0x4000;
    ObjHits_EnableObject(obj);
    state->flags &= ~0x10;
}
