/*
 * wmseqpoint (DLL 0x20D) - sequence trigger points at Krazoa Palace
 * (map 'warlock').
 * Each placed instance arms one trigger sequence (state->sequenceId),
 * fired by player proximity and/or a condition game bit per
 * WMSEQPOINT_TRIGGER_*, then latches done. Two sequence families get
 * bespoke handling: the sky-toggle sequence swaps the palace sky
 * envfx set when it ends (wmseqpoint_onSeqFree), and the spirit
 * sequences re-arm the released-spirit indicator objects
 * (gWM_seqpointSpiritTargets) before re-running. Sequence 0's event
 * opcodes (wmseqpoint_SeqFn) drive game bits shared with the shrine
 * DLLs (0x143) and the palace sun (0x21D).
 */
#include "main/dll/WM/wm_shared.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/obj_placement.h"

typedef struct WmSeqPointState
{
    f32 triggerRadius;    /* 0x00: proximity radius, from placement */
    s16 conditionGameBit; /* 0x04: game bit arming the trigger (-1 = none) */
    s16 disableGameBit;   /* 0x06: set once fired; disables the point when set externally (-1 = none) */
    s16 sequenceId;       /* 0x08: trigger sequence to run */
    s16 unk0A;            /* 0x0A: cleared at init, never read */
    u8 command;           /* 0x0C: last sequence-0 event opcode handled */
    u8 doneLatch;         /* 0x0D: sequence has run; cleared by a spirit reset */
    u8 triggerMode;       /* 0x0E: WMSEQPOINT_TRIGGER_* */
    u8 skyEnabledLatch;   /* 0x0F: sky state cached when the sky-toggle sequence starts */
} WmSeqPointState;

typedef struct WmSeqPointMapData
{
    ObjPlacement base;
    s8 rotXByte;          /* 0x18: rotX in 1/256 turns */
    u8 triggerMode;       /* 0x19: WMSEQPOINT_TRIGGER_* */
    s16 triggerRadius;    /* 0x1A */
    s16 sequenceId;       /* 0x1C */
    s16 conditionGameBit; /* 0x1E */
    s16 disableGameBit;   /* 0x20 */
} WmSeqPointMapData;

STATIC_ASSERT(offsetof(WmSeqPointState, triggerRadius) == 0x0);
STATIC_ASSERT(offsetof(WmSeqPointState, conditionGameBit) == 0x4);
STATIC_ASSERT(offsetof(WmSeqPointState, disableGameBit) == 0x6);
STATIC_ASSERT(offsetof(WmSeqPointState, sequenceId) == 0x8);
STATIC_ASSERT(offsetof(WmSeqPointState, command) == 0xC);
STATIC_ASSERT(offsetof(WmSeqPointState, doneLatch) == 0xD);
STATIC_ASSERT(offsetof(WmSeqPointState, triggerMode) == 0xE);
STATIC_ASSERT(offsetof(WmSeqPointState, skyEnabledLatch) == 0xF);
STATIC_ASSERT(sizeof(WmSeqPointState) == 0x10);
STATIC_ASSERT(offsetof(WmSeqPointMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(WmSeqPointMapData, triggerMode) == 0x19);
STATIC_ASSERT(offsetof(WmSeqPointMapData, triggerRadius) == 0x1A);
STATIC_ASSERT(offsetof(WmSeqPointMapData, sequenceId) == 0x1C);
STATIC_ASSERT(offsetof(WmSeqPointMapData, conditionGameBit) == 0x1E);
STATIC_ASSERT(offsetof(WmSeqPointMapData, disableGameBit) == 0x20);
STATIC_ASSERT(sizeof(WmSeqPointMapData) == 0x24);

/* state->triggerMode: how the trigger sequence is armed */
enum
{
    WMSEQPOINT_TRIGGER_PROXIMITY = 0,           /* player within triggerRadius */
    WMSEQPOINT_TRIGGER_BIT_SET = 1,             /* conditionGameBit set */
    WMSEQPOINT_TRIGGER_PROXIMITY_BIT_SET = 2,   /* both of the above */
    WMSEQPOINT_TRIGGER_PROXIMITY_BIT_CLEAR = 3, /* proximity + bit clear; sets the bit after running */
    WMSEQPOINT_TRIGGER_BIT_CLEAR = 4,           /* bit clear; sets the bit after running */
    WMSEQPOINT_TRIGGER_BIT_SET_REPEAT = 5       /* bit set; re-runs every frame, no done latch */
};

/* trigger-sequence ids with bespoke handling in this DLL */
enum
{
    WMSEQPOINT_SEQ_SKY_TOGGLE = 0x1,   /* swaps the palace sky envfx set on end */
    WMSEQPOINT_SEQ_SPIRIT_1 = 0x21,    /* grants spirit bit 0xD1B on end */
    WMSEQPOINT_SEQ_SPIRIT_RESET = 0x22 /* re-arms all five spirit indicators */
};

/* spirit 1's pair (gWM_seqpointSpiritTargets[0..1]), hardcoded on the
   WMSEQPOINT_SEQ_SPIRIT_1 path */
#define WMSEQPOINT_SPIRIT_1_GAMEBIT 0xD1B
#define WMSEQPOINT_SPIRIT_1_OBJID 0x4AEB1

#define WMSEQPOINT_SPIRIT_COUNT 5

void wmseqpoint_onSeqFree(int obj);
int wmseqpoint_SeqFn(int obj, int unused, ObjAnimUpdateState* actor);
int wmseqpoint_getExtraSize(void);
int wmseqpoint_getObjectTypeId(void);
void wmseqpoint_free(void);
void wmseqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void wmseqpoint_hitDetect(void);
void wmseqpoint_update(int obj);
void wmseqpoint_init(int obj, int setup);
void wmseqpoint_release(void);
void wmseqpoint_initialise(void);

/* {game bit, placement id} per released-spirit indicator; bits 0xD1B-0xD1F
   are granted by the spirit places (see dll_020C_wmspiritplace.c) */
int gWM_seqpointSpiritTargets[10] = {
    0xD1B, 0x4AEB1,
    0xD1C, 0x4AEB2,
    0xD1D, 0x4AEB3,
    0xD1E, 0x4AEB4,
    0xD1F, 0x4AEB5,
};

ObjectDescriptor gWM_seqpointObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    wmseqpoint_initialise,
    wmseqpoint_release,
    0,
    (ObjectDescriptorCallback)wmseqpoint_init,
    (ObjectDescriptorCallback)wmseqpoint_update,
    wmseqpoint_hitDetect,
    (ObjectDescriptorCallback)wmseqpoint_render,
    wmseqpoint_free,
    (ObjectDescriptorCallback)wmseqpoint_getObjectTypeId,
    wmseqpoint_getExtraSize,
};

void wmseqpoint_onSeqFree(int obj)
{
    WmSeqPointState* state;
    int skyOn;

    state = ((GameObject*)obj)->extra;
    if (state->sequenceId == WMSEQPOINT_SEQ_SPIRIT_1)
    {
        GameBit_Set(WMSEQPOINT_SPIRIT_1_GAMEBIT, 1);
    }
    else if (state->sequenceId == WMSEQPOINT_SEQ_SKY_TOGGLE)
    {
        skyOn = getSkyColorFn_80088e08(0) & 0xff;
        if (state->skyEnabledLatch != 0 && skyOn == 0)
        {
            getEnvfxActImmediately(0, 0, 0x22d, 0);
            getEnvfxActImmediately(obj, obj, 0x22c, 0);
            getEnvfxActImmediately(obj, obj, 0x229, 0);
            getEnvfxActImmediately(obj, obj, 0x22a, 0);
            (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 4, 1);
            (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 10, 0);
            (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0xb, 0);
        }
        else if (state->skyEnabledLatch == 0 && skyOn != 0)
        {
            getEnvfxActImmediately(0, 0, 0x217, 0);
            getEnvfxActImmediately(obj, obj, 0x216, 0);
            getEnvfxActImmediately(obj, obj, 0x84, 0);
            getEnvfxActImmediately(obj, obj, 0x8a, 0);
            (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 4, 0);
            (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 10, 1);
            (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0xb, 1);
        }
    }
}

int wmseqpoint_SeqFn(int obj, int unused, ObjAnimUpdateState* actor)
{
    WmSeqPointState* state;
    int player;
    int i;

    state = ((GameObject*)obj)->extra;
    player = (int)Obj_GetPlayerObject();
    actor->sequenceEventActive = 0;
    actor->freeCallback = (ObjAnimSequenceFreeCallback)wmseqpoint_onSeqFree;

    for (i = 0; i < actor->eventCount; i++)
    {
        switch (state->sequenceId)
        {
        case 0:
            if (actor->eventIds[i] != 0)
            {
                state->command = actor->eventIds[i];
                switch (actor->eventIds[i])
                {
                case 1:
                    GameBit_Set(0x143, 1);
                    break;
                case 2:
                    GameBit_Set(0x143, 0);
                    break;
                case 5:
                    GameBit_Set(0x21d, 1);
                    break;
                case 4:
                    GameBit_Set(0x21d, 1);
                    fn_80296518(player, 8, 0);
                    GameBit_Set(0x277, 1);
                    break;
                default:
                    break;
                }
            }
            break;
        default:
            switch (actor->eventIds[i])
            {
            case 0xb:
                if ((u32)(getSkyColorFn_80088e08(0) & 0xff) != 0)
                {
                    getEnvfxActImmediately(0, 0, 0x217, 0);
                    getEnvfxActImmediately(obj, obj, 0x216, 0);
                    getEnvfxActImmediately(obj, obj, 0x84, 0);
                    getEnvfxActImmediately(obj, obj, 0x8a, 0);
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 4, 0);
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 10, 1);
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0xb, 1);
                }
                break;
            case 0xa:
                if ((u32)(getSkyColorFn_80088e08(0) & 0xff) == 0)
                {
                    getEnvfxActImmediately(0, 0, 0x22d, 0);
                    getEnvfxActImmediately(obj, obj, 0x22c, 0);
                    getEnvfxActImmediately(obj, obj, 0x229, 0);
                    getEnvfxActImmediately(obj, obj, 0x22a, 0);
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 4, 1);
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 10, 0);
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0xb, 0);
                }
                break;
            default:
                break;
            }
            break;
        }
        actor->eventIds[i] = 0;
    }

    return 0;
}

int wmseqpoint_getExtraSize(void) { return 0x10; }

int wmseqpoint_getObjectTypeId(void) { return 0x0; }

void wmseqpoint_free(void)
{
}

void wmseqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 isVisible;

    isVisible = visible;
    if (isVisible != 0)
    {
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E5F10); /* 1.0f */
    }
}

void wmseqpoint_hitDetect(void)
{
}

void wmseqpoint_update(int obj)
{
    WmSeqPointState* state;
    int player;
    int target;
    int i;
    extern u8 getSkyColorFn_80088e08(int skyId);

    player = (int)Obj_GetPlayerObject();
    state = ((GameObject*)obj)->extra;

    if (state->disableGameBit != -1)
    {
        if (state->doneLatch != 0)
        {
            if (GameBit_Get(state->disableGameBit) != 0)
            {
                return;
            }
            GameBit_Set(state->disableGameBit, 1);
            state->doneLatch = 1;
            return;
        }
        if (GameBit_Get(state->disableGameBit) != 0)
        {
            state->doneLatch = 1;
            return;
        }
    }

    if (state->doneLatch != 0)
    {
        return;
    }

    switch (state->triggerMode)
    {
    case WMSEQPOINT_TRIGGER_PROXIMITY:
        if (Vec_distance((void*)&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) < state->triggerRadius)
        {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
            state->doneLatch = 1;
        }
        break;
    case WMSEQPOINT_TRIGGER_BIT_SET:
        if (state->conditionGameBit != -1 && GameBit_Get(state->conditionGameBit) != 0)
        {
            if (state->sequenceId == WMSEQPOINT_SEQ_SPIRIT_RESET)
            {
                for (i = 0; i < WMSEQPOINT_SPIRIT_COUNT; i++)
                {
                    GameBit_Set(gWM_seqpointSpiritTargets[i * 2], 0);
                    target = ObjList_FindObjectById(gWM_seqpointSpiritTargets[i * 2 + 1]);
                    ((WmSeqPointState*)((GameObject*)target)->extra)->doneLatch = 0;
                    if (((GameObject*)target)->seqIndex != -1)
                    {
                        (*gObjectTriggerInterface)->endSequence(((GameObject*)target)->seqIndex);
                    }
                }
            }
            else if (state->sequenceId == WMSEQPOINT_SEQ_SKY_TOGGLE)
            {
                state->skyEnabledLatch = getSkyColorFn_80088e08(0);
            }
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
            state->doneLatch = 1;
        }
        break;
    case WMSEQPOINT_TRIGGER_PROXIMITY_BIT_SET:
        if (Vec_distance((void*)&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) < state->triggerRadius &&
            state->conditionGameBit != -1 && GameBit_Get(state->conditionGameBit) != 0)
        {
            if (state->sequenceId == WMSEQPOINT_SEQ_SPIRIT_1)
            {
                GameBit_Set(WMSEQPOINT_SPIRIT_1_GAMEBIT, 0);
                target = ObjList_FindObjectById(WMSEQPOINT_SPIRIT_1_OBJID);
                ((WmSeqPointState*)((GameObject*)target)->extra)->doneLatch = 0;
                if (((GameObject*)target)->seqIndex != -1)
                {
                    (*gObjectTriggerInterface)->endSequence(((GameObject*)target)->seqIndex);
                }
            }
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
            state->doneLatch = 1;
        }
        break;
    case WMSEQPOINT_TRIGGER_PROXIMITY_BIT_CLEAR:
        if (Vec_distance((void*)&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) < state->triggerRadius &&
            state->conditionGameBit != -1 && GameBit_Get(state->conditionGameBit) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
            GameBit_Set(state->conditionGameBit, 1);
            state->doneLatch = 1;
        }
        break;
    case WMSEQPOINT_TRIGGER_BIT_CLEAR:
        if (state->conditionGameBit != -1 && GameBit_Get(state->conditionGameBit) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
            GameBit_Set(state->conditionGameBit, 1);
            state->doneLatch = 1;
        }
        break;
    case WMSEQPOINT_TRIGGER_BIT_SET_REPEAT:
        if (state->conditionGameBit != -1 && GameBit_Get(state->conditionGameBit) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
        }
        break;
    default:
        break;
    }
}

void wmseqpoint_init(int obj, int setup)
{
    WmSeqPointState* state;
    WmSeqPointMapData* mapData;

    state = ((GameObject*)obj)->extra;
    mapData = (WmSeqPointMapData*)setup;
    ((GameObject*)obj)->animEventCallback = wmseqpoint_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)(mapData->rotXByte << 8);
    state->triggerRadius = mapData->triggerRadius;
    state->sequenceId = mapData->sequenceId;
    state->doneLatch = 0;
    state->triggerMode = mapData->triggerMode;
    state->conditionGameBit = mapData->conditionGameBit;
    state->disableGameBit = mapData->disableGameBit;
    state->command = 0;
    state->unk0A = 0;
}

void wmseqpoint_release(void)
{
}

void wmseqpoint_initialise(void)
{
}
