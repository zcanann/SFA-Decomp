/*
 * wispbaddieseq - the wisp/hagabon anim-sequence driver shared with the
 * sidekick-toy and ground-baddie seq objects: fn_8014FFB4 walks the per-family
 * event rows and starts the next move, fn_8015039C fires the per-frame
 * move-progress sfx (with rumble + radial camera shake), and fn_801504BC
 * primes the next chain entry. The per-family tables live in the wisp baddie
 * DLL and are reached here by extern.
 */
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/vecmath.h"
#include "main/pad_api.h"
#include "main/camera_shake_api.h"
#include "main/frame_timing.h"
#include "main/dll/seqobj11d_ext.h"

#define WISPBADDIE_OBJFLAG_PARENT_SLACK 0x1000

typedef struct WispEventRow
{
    f32 blend; /* +0x0 */
    u32 flags; /* +0x4 (low byte = move flags) */
    u8 moveId; /* +0x8 */
    u8 pad9[3];
} WispEventRow;
STATIC_ASSERT(sizeof(WispEventRow) == 0xc);
STATIC_ASSERT(offsetof(WispEventRow, moveId) == 0x8);

/*
 * HagabonAnimState - file-local overlay naming the PER-FAMILY anim-control
 * scratch that baddie_state.h leaves raw for the hagabon/swarmbaddie fighter
 * driven by fn_8014FFB4. moveEventFlags(0x2F8) is the u16 per-frame
 * move-progress event bitmask read by fn_8015039C to fire SFX.
 */
typedef struct HagabonAnimState
{
    u8 pad00[0x2F1];
    u8 animEvent; /* 0x2F1 packed anim-event byte: low 5 bits = event row index, bits 0x10/0x20 flags */
    u8 animFlags; /* 0x2F2 (bit 0x80) */
    u8 unk2F3;    /* 0x2F3 */
    u8 unk2F4;    /* 0x2F4 */
    u8 pad2F5[0x2F8 - 0x2F5];
    u16 moveEventFlags; /* 0x2F8 move-progress event bits (0x200/0x40/0x1000/1/0x80) */
    u8 pad2FA[0x324 - 0x2FA];
    f32 eventDelayTimer; /* 0x324 next-event delay countdown */
    f32 unk328;          /* 0x328 */
    f32 moveHoldTimer;   /* 0x32C current move hold countdown */
    f32 unk330;          /* 0x330 */
    f32 unk334;          /* 0x334 */
    u16 unk338;          /* 0x338 */
    u8 pad33A[0x33C - 0x33A];
    u8 activeEventIndex; /* 0x33C latched active event-row index */
} HagabonAnimState;

STATIC_ASSERT(offsetof(HagabonAnimState, animEvent) == 0x2F1);
STATIC_ASSERT(offsetof(HagabonAnimState, moveEventFlags) == 0x2F8);
STATIC_ASSERT(offsetof(HagabonAnimState, eventDelayTimer) == 0x324);
STATIC_ASSERT(offsetof(HagabonAnimState, unk338) == 0x338);
STATIC_ASSERT(offsetof(HagabonAnimState, activeEventIndex) == 0x33C);

/* per-family table-of-tables row (0x28 bytes); holds pointers to the
 * sub-tables that drive a family's anim sequencing. */
typedef struct
{
    u8* tbl0;       /* 0x00 */
    u8* tbl4;       /* 0x04 */
    u8 pad08[0x08]; /* 0x08 */
    u8* tbl10;      /* 0x10 */
    u8 pad14[0x08]; /* 0x14 */
    u8* tbl1c;      /* 0x1c */
    u8* tbl20;      /* 0x20 */
    u8* tbl24;      /* 0x24 */
} FamilyTable;

extern FamilyTable lbl_8031F16C[]; /* per-family table-of-tables, 0x28-byte rows */
extern u8 lbl_8031DD30[];          /* per-anim move-progress floats, indexed anim*4 */

f32 lbl_803E2740 = 0.0f;

u32 fn_8014FFB4(GameObject* obj, int state, u32 allowNewEvent)
{
    u8* base = lbl_8031DD30;
    u8* sequenceBase;
    WispEventRow* eventRows;
    u8 eventIndex;
    int ei;
    int flag20;
    u8 eventFlags;
    u32 stateFlags;
    u8 sequenceIndex;
    f32 blendScale;
    f32 blendTimer;
    int eventTableIndex;
    int controlMask;
    int controlFlags;
    WispEventRow* row;
    u32 sf2;

    sequenceIndex = ((BaddieState*)state)->userData2;
    sequenceBase = base + sequenceIndex * 0x28;
    eventRows = *(WispEventRow**)(sequenceBase + 0x1444);
    stateFlags = ((BaddieState*)state)->controlFlags;
    if ((stateFlags & 0x4000) != 0)
    {
        return 0;
    }
    if (((HagabonAnimState*)state)->unk328 != lbl_803E2740 && ((HagabonAnimState*)state)->unk338 != 0)
    {
        return 0;
    }
    eventFlags = ((HagabonAnimState*)state)->animEvent;
    ei = eventFlags & 0x1f;
    eventIndex = ei;
    if ((ei & 0x10) != 0)
    {
        eventIndex = ei & ~0x8;
    }
    if (eventIndex > 0x18)
    {
        eventIndex = 0;
    }
    flag20 = eventFlags & 0x20;
    if (flag20 != 0)
    {
        blendScale = 3.0f;
        eventIndex = 0;
    }
    else
    {
        blendScale = 1.0f;
    }
    if ((u8)allowNewEvent != 0)
    {
        if ((eventFlags != 0 || ((HagabonAnimState*)state)->eventDelayTimer != lbl_803E2740) &&
            (stateFlags & 0x40) == 0 && flag20 == 0)
        {
            if (((HagabonAnimState*)state)->eventDelayTimer != lbl_803E2740)
            {
                ((HagabonAnimState*)state)->eventDelayTimer = ((HagabonAnimState*)state)->eventDelayTimer - timeDelta;
                if (((HagabonAnimState*)state)->eventDelayTimer <= lbl_803E2740)
                {
                    ((HagabonAnimState*)state)->eventDelayTimer = lbl_803E2740;
                }
                else
                {
                    return 0;
                }
            }
            else
            {
                eventTableIndex = sequenceIndex * 2;
                ((HagabonAnimState*)state)->eventDelayTimer =
                    ((HagabonAnimState*)state)->unk334 +
                    (f32)(int)randomGetRange(base[eventTableIndex + 0x152c], base[eventTableIndex + 0x152d]);
                ((HagabonAnimState*)state)->unk334 = lbl_803E2740;
                return 0;
            }
        }
    }
    if ((((u8)allowNewEvent != 0 && ((HagabonAnimState*)state)->animEvent != 0 && eventRows[eventIndex].moveId != 0) ||
         (((HagabonAnimState*)state)->animEvent & 0x20) != 0) &&
        !(((HagabonAnimState*)state)->activeEventIndex == eventIndex && lbl_803E2740 != ((HagabonAnimState*)state)->moveHoldTimer))
    {
        sf2 = ((BaddieState*)state)->controlFlags;
        if ((sf2 & 0x800080) != 0 || (((HagabonAnimState*)state)->animEvent & 0x20) != 0)
        {
            blendTimer = 60.0f * (blendScale * (row = &eventRows[eventIndex])->blend);
            ((HagabonAnimState*)state)->unk330 = blendTimer;
            ((HagabonAnimState*)state)->moveHoldTimer = blendTimer;
            ((BaddieState*)state)->controlFlags = ((BaddieState*)state)->controlFlags | 0x40;
            ((HagabonAnimState*)state)->animFlags = ((HagabonAnimState*)state)->animFlags | 0x80;
            ((HagabonAnimState*)state)->unk2F3 = 0;
            ((HagabonAnimState*)state)->unk2F4 = 0;
            Baddie_SetMove(obj, state, row->moveId, blendScale * row->blend, 0, row->flags & 0xff);
            ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj,
                                                                       *(f32*)(base + row->moveId * 4));
            ((HagabonAnimState*)state)->activeEventIndex = eventIndex;
            return 1;
        }
        if ((sf2 & 0x40000000) != 0)
        {
            ((void (*)(GameObject*, int))fn_801513AC)(obj, state);
        }
        return 0;
    }
    if (((HagabonAnimState*)state)->moveHoldTimer != lbl_803E2740)
    {
        GameObject* pos = (GameObject*)((BaddieState*)state)->trackedObj;
        baddieTurnTowardPoint(obj, state, pos->anim.localPosX, pos->anim.localPosZ, 0xf, 0);
        if (((BaddieState*)state)->unk308 > 0.0166f)
        {
            ((BaddieState*)state)->unk308 = ((BaddieState*)state)->unk308 - 0.005f;
        }
        if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            eventTableIndex = ((HagabonAnimState*)state)->activeEventIndex;
            Baddie_SetMove(obj, state, eventRows[eventTableIndex].moveId,
                           eventRows[((HagabonAnimState*)state)->activeEventIndex].blend, 0,
                           eventRows[eventTableIndex].flags & 0xff);
            ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)(
                (ObjAnimComponent*)obj, *(f32*)(base + eventRows[((HagabonAnimState*)state)->activeEventIndex].moveId * 4));
        }
        ((HagabonAnimState*)state)->moveHoldTimer = ((HagabonAnimState*)state)->moveHoldTimer - timeDelta;
        if (((HagabonAnimState*)state)->moveHoldTimer <= lbl_803E2740)
        {
            ((HagabonAnimState*)state)->moveHoldTimer = lbl_803E2740;
            controlFlags = ((BaddieState*)state)->controlFlags;
            controlMask = ~0x40;
            ((BaddieState*)state)->controlFlags = controlFlags & controlMask;
            ((BaddieState*)state)->controlFlags =
                ((BaddieState*)state)->controlFlags | (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
            ((HagabonAnimState*)state)->animFlags = ((HagabonAnimState*)state)->animFlags & ~0x80;
            ((HagabonAnimState*)state)->activeEventIndex = 0;
            return 0;
        }
        else
        {
            return 1;
        }
    }
    return 0;
}

void fn_8015039C(GameObject* obj, int animState)
{
    GameObject* player;
    f32 distance;
    f32 rumbleFalloff;

    if ((((HagabonAnimState*)animState)->moveEventFlags & 0x200) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_sml_trex_snap3);
        player = Obj_GetPlayerObject();
        if ((player->objectFlags & WISPBADDIE_OBJFLAG_PARENT_SLACK) == 0)
        {
            distance = Vec_distance(&(obj)->anim.worldPosX, &player->anim.worldPosX);
            if (distance <= 640.0f)
            {
                rumbleFalloff = 1.0f - distance / 640.0f;
                rumbleFalloff = 3.0f * rumbleFalloff;
                doRumble(rumbleFalloff);
            }
            CameraShake_ApplyRadial((obj)->anim.localPosX, (obj)->anim.localPosY, (obj)->anim.localPosZ, 640.0f,
                                    4.0f);
        }
    }
    if ((((HagabonAnimState*)animState)->moveEventFlags & 0x40) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_spotfox01);
    }
    if ((((HagabonAnimState*)animState)->moveEventFlags & 0x1000) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_scream1);
    }
    if ((((HagabonAnimState*)animState)->moveEventFlags & 1) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_pullup2);
    }
    if ((((HagabonAnimState*)animState)->moveEventFlags & 0x80) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_death01);
    }
}

void fn_801504BC(int obj, int delta)
{
    u8* inner = ((GameObject*)obj)->extra;
    u8* ptr = lbl_8031F16C[inner[0x33b]].tbl4;
    inner[0x33d] = (u8)(delta + (u32)ptr[8] + 1);
    inner[0x33e] = 1;
}
