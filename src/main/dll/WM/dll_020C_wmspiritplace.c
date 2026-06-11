/*
 * wmspiritplace (DLL 0x20C) - the six spirit places on the world map.
 * Each placed instance is tagged by its placement mapId
 * (WMSPIRITPLACE_MAP_N) and becomes interactive once the world map's
 * map-event mode reaches N: it raises the A-button prompt, runs trigger
 * sequence 0 when the player interacts, and once the sequence game bit
 * is granted runs follow-up sequence 1. Level locks/loads, map warps,
 * sky restores and spirit vision are driven from the sequence events
 * (wmspiritplace_SeqFn).
 *
 * Interaction state machine bits in anim.resetHitboxFlags: 0x01 =
 * player interacted, 0x04 = player in range (show A icon), 0x08 =
 * interaction disabled, 0x10 = prompt armed.
 */
#include "main/dll/WM/wm_shared.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct WmSpiritPlaceState
{
    f32 heightOffset;       /* 0x00: placement height / 32767 / 100 (not read back) */
    int unk_04;             /* 0x04: cleared at init, never read */
    s16 unk_08;             /* 0x08: cleared at init, never read */
    s16 unk_0A;             /* 0x0A: cleared at init, never read */
    s16 promptGameBit;      /* 0x0C: game bit arming the interaction prompt */
    s16 sequenceGameBit;    /* 0x0E: game bit granted when sequence 0 completes */
    s16 setupParam;         /* 0x10: from placement, never read */
    u8 fxFlags;             /* 0x12: bit 1 = spawn spirit fx each SeqFn tick */
    u8 mapEventMode;        /* 0x13: world-map map-event mode, cached at init */
    u8 transitionDelay;     /* 0x14: frames until sequenceGameBit is set */
    u8 sequenceStarted : 1; /* 0x15 & 0x80: sequence 0 has run; lock interaction */
    u8 envFxPending : 1;    /* 0x15 & 0x40: place 5's one-shot env change due */
    u8 unusedFlags : 6;
    u8 pad16[2];
} WmSpiritPlaceState;

typedef struct WmSpiritPlaceMapData
{
    ObjPlacement base;
    s8 rotXByte;            /* 0x18: rotX in 1/256 turns */
    s8 setupParam;          /* 0x19 */
    s16 rotYAngle;          /* 0x1A: rotY in 1/256 turns */
    s16 heightOffset;       /* 0x1C */
    s16 sequenceGameBit;    /* 0x1E */
    s16 promptGameBit;      /* 0x20 */
} WmSpiritPlaceMapData;

STATIC_ASSERT(offsetof(WmSpiritPlaceState, promptGameBit) == 0x0C);
STATIC_ASSERT(offsetof(WmSpiritPlaceState, sequenceGameBit) == 0x0E);
STATIC_ASSERT(offsetof(WmSpiritPlaceState, setupParam) == 0x10);
STATIC_ASSERT(offsetof(WmSpiritPlaceState, transitionDelay) == 0x14);
STATIC_ASSERT(sizeof(WmSpiritPlaceState) == 0x18);
STATIC_ASSERT(offsetof(WmSpiritPlaceMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(WmSpiritPlaceMapData, setupParam) == 0x19);
STATIC_ASSERT(offsetof(WmSpiritPlaceMapData, rotYAngle) == 0x1A);
STATIC_ASSERT(offsetof(WmSpiritPlaceMapData, heightOffset) == 0x1C);
STATIC_ASSERT(offsetof(WmSpiritPlaceMapData, sequenceGameBit) == 0x1E);
STATIC_ASSERT(offsetof(WmSpiritPlaceMapData, promptGameBit) == 0x20);
STATIC_ASSERT(sizeof(WmSpiritPlaceMapData) == 0x24);

/* placement mapId tags of the six spirit-place instances; place N
   becomes active once the world map's map-event mode reaches N. */
enum
{
    WMSPIRITPLACE_MAP_1 = 0x2183,
    WMSPIRITPLACE_MAP_2 = 0x47295,
    WMSPIRITPLACE_MAP_3 = 0x49781,
    WMSPIRITPLACE_MAP_4 = 0x4A1C0,
    WMSPIRITPLACE_MAP_5 = 0x4A250,
    WMSPIRITPLACE_MAP_6 = 0x4A5E6
};

/* sequence event opcodes consumed by wmspiritplace_SeqFn */
enum
{
    WMSPIRITPLACE_SEQEV_UNLOCK_LEVEL = 1,
    WMSPIRITPLACE_SEQEV_MAP_PROGRESS = 2,
    WMSPIRITPLACE_SEQEV_WARP = 3,
    WMSPIRITPLACE_SEQEV_SET_SEQUENCE_BIT = 4,
    WMSPIRITPLACE_SEQEV_FX_ON = 5,
    WMSPIRITPLACE_SEQEV_FX_OFF = 6,
    WMSPIRITPLACE_SEQEV_SKY_RESTORE = 7,
    WMSPIRITPLACE_SEQEV_SPIRIT_VISION_ON = 8,
    WMSPIRITPLACE_SEQEV_SPIRIT_VISION_OFF = 9
};

void wmspiritplace_onSeqFree(void);
int wmspiritplace_SeqFn(int obj, int unused, ObjAnimUpdateState* actor);
int wmspiritplace_getExtraSize(void);
int wmspiritplace_getObjectTypeId(void);
void wmspiritplace_free(void);
void wmspiritplace_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void wmspiritplace_hitDetect(GameObject* obj);
void wmspiritplace_update(GameObject* obj);
void wmspiritplace_init(GameObject* obj, WmSpiritPlaceMapData* placement);
void wmspiritplace_release(void);
void wmspiritplace_initialise(void);

ObjectDescriptor gWM_spiritplaceObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    wmspiritplace_initialise,
    wmspiritplace_release,
    0,
    (ObjectDescriptorCallback)wmspiritplace_init,
    (ObjectDescriptorCallback)wmspiritplace_update,
    (ObjectDescriptorCallback)wmspiritplace_hitDetect,
    (ObjectDescriptorCallback)wmspiritplace_render,
    wmspiritplace_free,
    (ObjectDescriptorCallback)wmspiritplace_getObjectTypeId,
    wmspiritplace_getExtraSize,
};

void wmspiritplace_onSeqFree(void)
{
}

/* obj stays int-typed with per-use casts: the int->pointer conversion at
   each deref keeps the param's register web light, which MWCC's allocator
   needs for the matching r28-r31 assignment (CLAUDE.md recipes #77/#114). */
int wmspiritplace_SeqFn(int obj, int unused, ObjAnimUpdateState* actor)
{
    int i;
    WmSpiritPlaceState* state;
    int mapId;
    u8 eventId;
    u8 fxPos[24];

    state = ((GameObject*)obj)->extra;
    if ((state->fxFlags & 1) != 0)
    {
        (*gPartfxInterface)->spawnObject((void*)obj, 0x7d8, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x7d8, fxPos, 2, -1, NULL);
    }

    actor->sequenceEventActive = 0;
    ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags & ~0x8);
    actor->freeCallback = (ObjAnimSequenceFreeCallback)wmspiritplace_onSeqFree;

    for (i = 0; i < actor->eventCount; i++)
    {
        eventId = actor->eventIds[i];
        switch (eventId)
        {
        case WMSPIRITPLACE_SEQEV_UNLOCK_LEVEL:
            unlockLevel(0, 0, 1);
            break;
        case WMSPIRITPLACE_SEQEV_WARP:
            mapId = ((GameObject*)obj)->anim.placement->mapId;
            switch (mapId)
            {
            case WMSPIRITPLACE_MAP_2:
                warpToMap(0x7e, 0);
                break;
            case WMSPIRITPLACE_MAP_3:
                warpToMap(0x7e, 0);
                break;
            case WMSPIRITPLACE_MAP_4:
                warpToMap(0x7e, 0);
                break;
            }
            break;
        case WMSPIRITPLACE_SEQEV_SET_SEQUENCE_BIT:
            mapId = ((GameObject*)obj)->anim.placement->mapId;
            switch (mapId)
            {
            case WMSPIRITPLACE_MAP_2:
            case WMSPIRITPLACE_MAP_3:
            case WMSPIRITPLACE_MAP_4:
            case WMSPIRITPLACE_MAP_5:
            case WMSPIRITPLACE_MAP_6:
                state->transitionDelay = 1;
                break;
            }
            break;
        case WMSPIRITPLACE_SEQEV_FX_ON:
            state->fxFlags = (u8)(state->fxFlags | 1);
            break;
        case WMSPIRITPLACE_SEQEV_FX_OFF:
            state->fxFlags = (u8)(state->fxFlags & ~1);
            break;
        case WMSPIRITPLACE_SEQEV_SKY_RESTORE:
            skyFn_80088c94(7, 0);
            setDrawCloudsAndLights(1);
            getEnvfxAct(obj, obj, 0x84, 0);
            getEnvfxAct(obj, obj, 0x8a, 0);
            getEnvfxActImmediately(0, 0, 0x217, 0);
            getEnvfxActImmediately(0, 0, 0x216, 0);
            break;
        case WMSPIRITPLACE_SEQEV_SPIRIT_VISION_ON:
            Rcp_SetSpiritVisionEnabled(1);
            break;
        case WMSPIRITPLACE_SEQEV_SPIRIT_VISION_OFF:
            Rcp_SetSpiritVisionEnabled(0);
            break;
        case WMSPIRITPLACE_SEQEV_MAP_PROGRESS:
            mapId = ((GameObject*)obj)->anim.placement->mapId;
            switch (mapId)
            {
            case WMSPIRITPLACE_MAP_1:
                lockLevel(mapGetDirIdx(0x41), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*gMapEventInterface)->unk78(1);
                break;
            case WMSPIRITPLACE_MAP_2:
                loadMapAndParent(0x42);
                lockLevel(mapGetDirIdx(0x42), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*gMapEventInterface)->setMode(0x42, 3);
                (*gMapEventInterface)->setMode(7, 4);
                break;
            case WMSPIRITPLACE_MAP_3:
                loadMapAndParent(0x42);
                lockLevel(mapGetDirIdx(0x42), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*gMapEventInterface)->setMode(0x42, 3);
                (*gMapEventInterface)->setMode(7, 5);
                break;
            case WMSPIRITPLACE_MAP_4:
                loadMapAndParent(0x42);
                lockLevel(mapGetDirIdx(0x42), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*gMapEventInterface)->setMode(0x42, 3);
                (*gMapEventInterface)->setMode(7, 7);
                break;
            }
            break;
        }
    }

    return 0;
}

int wmspiritplace_getExtraSize(void) { return sizeof(WmSpiritPlaceState); }

int wmspiritplace_getObjectTypeId(void) { return 0x0; }

void wmspiritplace_free(void)
{
}

void wmspiritplace_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0)
    {
        return;
    }
}

void wmspiritplace_hitDetect(GameObject* obj)
{
    if (obj->anim.unk74 != NULL)
    {
        objRenderFn_80041018((int)obj);
    }
}

void wmspiritplace_update(GameObject* obj)
{
    WmSpiritPlaceState* state;
    uint mapId;

    state = obj->extra;
    if (state->transitionDelay != 0)
    {
        state->transitionDelay--;
        if (state->transitionDelay == 0)
        {
            GameBit_Set(state->sequenceGameBit, 1);
        }
    }
    else
    {
        state->fxFlags &= ~1;
        mapId = obj->anim.placement->mapId;
        if (mapId == WMSPIRITPLACE_MAP_2)
        {
            if (state->mapEventMode == 2)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= 0x10;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 flags = obj->anim.resetHitboxFlags;
                    if ((flags & 0x10) != 0)
                    {
                        obj->anim.resetHitboxFlags = (u8)(flags & ~0x10);
                    }
                    if ((obj->anim.resetHitboxFlags & 4) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((obj->anim.resetHitboxFlags & 1) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                        state->sequenceStarted = 1;
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(0x29b) != 0)
                {
                    (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                    GameBit_Set(state->promptGameBit, 0);
                    GameBit_Set(state->sequenceGameBit, 0);
                    GameBit_Set(0xbfd, 0);
                }
                else
                {
                    obj->anim.resetHitboxFlags &= ~8;
                }
            }
            else
            {
                obj->anim.resetHitboxFlags |= 8;
            }
        }
        else if (mapId == WMSPIRITPLACE_MAP_1)
        {
            if (state->mapEventMode == 1)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= 0x10;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 flags = obj->anim.resetHitboxFlags;
                    if ((flags & 0x10) != 0)
                    {
                        obj->anim.resetHitboxFlags = (u8)(flags & ~0x10);
                    }
                    if ((obj->anim.resetHitboxFlags & 4) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((obj->anim.resetHitboxFlags & 1) != 0)
                    {
                        GameBit_Set(state->sequenceGameBit, 1);
                        GameBit_Set(state->promptGameBit, 0);
                    }
                }
                else
                {
                    obj->anim.resetHitboxFlags &= ~8;
                }
            }
            else
            {
                obj->anim.resetHitboxFlags |= 8;
            }
        }
        else if (mapId == WMSPIRITPLACE_MAP_3)
        {
            if (state->mapEventMode == 3)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= 0x10;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 flags = obj->anim.resetHitboxFlags;
                    if ((flags & 0x10) != 0)
                    {
                        obj->anim.resetHitboxFlags = (u8)(flags & ~0x10);
                    }
                    if ((obj->anim.resetHitboxFlags & 4) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((obj->anim.resetHitboxFlags & 1) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                        state->sequenceStarted = 1;
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(0x8a2) != 0)
                {
                    (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                    GameBit_Set(state->promptGameBit, 0);
                    GameBit_Set(state->sequenceGameBit, 0);
                }
                else
                {
                    obj->anim.resetHitboxFlags &= ~8;
                }
            }
            else
            {
                obj->anim.resetHitboxFlags |= 8;
            }
        }
        else if (mapId == WMSPIRITPLACE_MAP_4)
        {
            if (state->mapEventMode == 4)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= 0x10;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 flags = obj->anim.resetHitboxFlags;
                    if ((flags & 0x10) != 0)
                    {
                        obj->anim.resetHitboxFlags = (u8)(flags & ~0x10);
                    }
                    if ((obj->anim.resetHitboxFlags & 4) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((obj->anim.resetHitboxFlags & 1) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                        state->sequenceStarted = 1;
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(0xc71) != 0)
                {
                    (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                    GameBit_Set(state->promptGameBit, 0);
                    GameBit_Set(state->sequenceGameBit, 0);
                }
                else
                {
                    obj->anim.resetHitboxFlags &= ~8;
                }
            }
            else
            {
                obj->anim.resetHitboxFlags |= 8;
            }
        }
        else if (mapId == WMSPIRITPLACE_MAP_5)
        {
            if (state->mapEventMode == 5)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= 0x10;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 flags = obj->anim.resetHitboxFlags;
                    if ((flags & 0x10) != 0)
                    {
                        obj->anim.resetHitboxFlags = (u8)(flags & ~0x10);
                    }
                    if ((obj->anim.resetHitboxFlags & 4) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((obj->anim.resetHitboxFlags & 1) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                        state->sequenceStarted = 1;
                        state->envFxPending = 1;
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(0xcb6) != 0)
                {
                    if (state->envFxPending)
                    {
                        state->envFxPending = 0;
                        GameBit_Set(state->promptGameBit, 0);
                        GameBit_Set(0xd1f, 1);
                        getEnvfxActImmediately(0, 0, 0x217, 0);
                        getEnvfxActImmediately((int)obj, (int)obj, 0x216, 0);
                        getEnvfxActImmediately((int)obj, (int)obj, 0x229, 0);
                        getEnvfxActImmediately((int)obj, (int)obj, 0x22a, 0);
                        (*gMapEventInterface)->setAnimEvent(obj->anim.mapEventSlot, 4, 1);
                        (*gMapEventInterface)->setAnimEvent(obj->anim.mapEventSlot, 10, 0);
                        (*gMapEventInterface)->setAnimEvent(obj->anim.mapEventSlot, 0xb, 1);
                    }
                }
                else
                {
                    obj->anim.resetHitboxFlags &= ~8;
                }
            }
            else
            {
                obj->anim.resetHitboxFlags |= 8;
            }
        }
        else if (mapId == WMSPIRITPLACE_MAP_6)
        {
            if (state->mapEventMode == 6)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= 0x10;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 flags = obj->anim.resetHitboxFlags;
                    if ((flags & 0x10) != 0)
                    {
                        obj->anim.resetHitboxFlags = (u8)(flags & ~0x10);
                    }
                    if ((obj->anim.resetHitboxFlags & 4) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((obj->anim.resetHitboxFlags & 1) != 0)
                    {
                        state->sequenceStarted = 1;
                        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(0xcb8) != 0)
                {
                    GameBit_Set(state->promptGameBit, 0);
                    GameBit_Set(state->sequenceGameBit, 1);
                }
                else
                {
                    obj->anim.resetHitboxFlags &= ~8;
                }
            }
            else
            {
                obj->anim.resetHitboxFlags |= 8;
            }
        }
        if (state->sequenceStarted)
        {
            obj->anim.resetHitboxFlags |= 8;
        }
    }
}

void wmspiritplace_init(GameObject* obj, WmSpiritPlaceMapData* placement)
{
    WmSpiritPlaceState* state;

    state = obj->extra;
    obj->animEventCallback = (void*)wmspiritplace_SeqFn;
    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->anim.rotY = (s16)(placement->rotYAngle << 8);
    state->heightOffset = ((f32)placement->heightOffset / 32767.0f) / 100.0f;
    state->unk_04 = 0;
    state->unk_08 = 0;
    state->unk_0A = 0;
    state->sequenceGameBit = placement->sequenceGameBit;
    state->promptGameBit = placement->promptGameBit;
    state->setupParam = placement->setupParam;
    state->sequenceStarted = 0;
    obj->objectFlags = (u16)(obj->objectFlags | 0x6000);
    state->mapEventMode = (*gMapEventInterface)->getMode(obj->anim.mapEventSlot);

    if (obj->anim.placement->mapId == WMSPIRITPLACE_MAP_2)
    {
        if (GameBit_Get(0x1fc) != 0 || GameBit_Get(0xeaf) != 0 || state->mapEventMode > 2)
        {
            obj->anim.localPosX -= 25.0f;
        }
    }
    else if (obj->anim.placement->mapId == WMSPIRITPLACE_MAP_6 && state->mapEventMode >= 6)
    {
        obj->anim.localPosX += 25.0f;
    }
}

void wmspiritplace_release(void)
{
}

void wmspiritplace_initialise(void)
{
}
