/*
 * wmspiritplace (DLL 0x20C) - the six Krazoa-spirit places at Krazoa
 * Palace (map 'warlock' = Dinosaur Planet's Warlock Mountain, hence
 * the WM dll prefix).
 * Each placed instance is tagged by its placement mapId
 * (WMSPIRITPLACE_MAP_N) and becomes interactive once the palace's
 * map-event mode reaches N: it raises the A-button prompt, runs trigger
 * sequence 0 when the player interacts, and once the sequence game bit
 * is granted runs follow-up sequence 1. Level locks/loads, map warps,
 * sky restores and spirit vision are driven from the sequence events
 * (wmspiritplace_SeqFn).
 *
 * The interaction prompt is driven through the INTERACT_FLAG_* bits in
 * anim.resetHitboxFlags (objanim_internal.h).
 */
#include "main/dll/WM/wm_shared.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
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
    u8 fxFlags;             /* 0x12: WMSPIRITPLACE_FX_ACTIVE */
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
   becomes active once the palace's map-event mode reaches N. */
enum
{
    WMSPIRITPLACE_MAP_1 = 0x2183,
    WMSPIRITPLACE_MAP_2 = 0x47295,
    WMSPIRITPLACE_MAP_3 = 0x49781,
    WMSPIRITPLACE_MAP_4 = 0x4A1C0,
    WMSPIRITPLACE_MAP_5 = 0x4A250,
    WMSPIRITPLACE_MAP_6 = 0x4A5E6
};

/* state->fxFlags: spawn the spirit particle fx each SeqFn tick */
#define WMSPIRITPLACE_FX_ACTIVE 0x1

#define WMSPIRITPLACE_OBJFLAG_HIDDEN 0x4000
#define WMSPIRITPLACE_OBJFLAG_HITDETECT_DISABLED 0x2000

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

/* game bits hardcoded by this DLL. Each place's gate bit lets the
   follow-up sequence 1 run once the place's sequence bit is also set;
   no other TU touches these five. The remaining literals at use sites
   (0x1FC/0xEAF/0xBFD/0xD1F) are cross-TU bits without established
   names. */
enum
{
    GAMEBIT_SPIRITPLACE_2_READY = 0x29B,
    GAMEBIT_SPIRITPLACE_3_READY = 0x8A2,
    GAMEBIT_SPIRITPLACE_4_READY = 0xC71,
    GAMEBIT_SPIRITPLACE_5_READY = 0xCB6,
    GAMEBIT_SPIRITPLACE_6_READY = 0xCB8
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

/* obj is a word here, not a pointer: the original signature was untyped
   (contrast update/init, which take typed pointers). */
int wmspiritplace_SeqFn(int obj, int unused, ObjAnimUpdateState* actor)
{
    int i;
    WmSpiritPlaceState* state;
    int mapId;
    u8 eventId;
    u8 fxPos[24];

    state = ((GameObject*)obj)->extra;
    if ((state->fxFlags & WMSPIRITPLACE_FX_ACTIVE) != 0)
    {
        (*gPartfxInterface)->spawnObject((void*)obj, 0x7d8, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x7d8, fxPos, 2, -1, NULL);
    }

    actor->sequenceEventActive = 0;
    ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
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
            state->fxFlags = (u8)(state->fxFlags | WMSPIRITPLACE_FX_ACTIVE);
            break;
        case WMSPIRITPLACE_SEQEV_FX_OFF:
            state->fxFlags = (u8)(state->fxFlags & ~WMSPIRITPLACE_FX_ACTIVE);
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
                (*gMapEventInterface)->setCharacter(1);
                break;
            case WMSPIRITPLACE_MAP_2:
                loadMapAndParent(0x42);
                lockLevel(mapGetDirIdx(0x42), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*gMapEventInterface)->setMapAct(0x42, 3);
                (*gMapEventInterface)->setMapAct(7, 4);
                break;
            case WMSPIRITPLACE_MAP_3:
                loadMapAndParent(0x42);
                lockLevel(mapGetDirIdx(0x42), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*gMapEventInterface)->setMapAct(0x42, 3);
                (*gMapEventInterface)->setMapAct(7, 5);
                break;
            case WMSPIRITPLACE_MAP_4:
                loadMapAndParent(0x42);
                lockLevel(mapGetDirIdx(0x42), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*gMapEventInterface)->setMapAct(0x42, 3);
                (*gMapEventInterface)->setMapAct(7, 7);
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
    if (obj->anim.hitVolumeTransforms != NULL)
    {
        objRenderFn_80041018((int)obj);
    }
}

void wmspiritplace_update(GameObject* obj)
{
    WmSpiritPlaceState* state;
    u32 mapId;

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
        state->fxFlags &= ~WMSPIRITPLACE_FX_ACTIVE;
        mapId = obj->anim.placement->mapId;
        if (mapId == WMSPIRITPLACE_MAP_2)
        {
            if (state->mapEventMode == 2)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 flags = obj->anim.resetHitboxFlags;
                    if ((flags & INTERACT_FLAG_PROMPT_SUPPRESSED) != 0)
                    {
                        obj->anim.resetHitboxFlags = (u8)(flags & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
                    }
                    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                        state->sequenceStarted = 1;
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(GAMEBIT_SPIRITPLACE_2_READY) != 0)
                {
                    (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                    GameBit_Set(state->promptGameBit, 0);
                    GameBit_Set(state->sequenceGameBit, 0);
                    GameBit_Set(0xbfd, 0);
                }
                else
                {
                    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                }
            }
            else
            {
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
        }
        else if (mapId == WMSPIRITPLACE_MAP_1)
        {
            if (state->mapEventMode == 1)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 flags = obj->anim.resetHitboxFlags;
                    if ((flags & INTERACT_FLAG_PROMPT_SUPPRESSED) != 0)
                    {
                        obj->anim.resetHitboxFlags = (u8)(flags & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
                    }
                    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
                    {
                        GameBit_Set(state->sequenceGameBit, 1);
                        GameBit_Set(state->promptGameBit, 0);
                    }
                }
                else
                {
                    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                }
            }
            else
            {
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
        }
        else if (mapId == WMSPIRITPLACE_MAP_3)
        {
            if (state->mapEventMode == 3)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 flags = obj->anim.resetHitboxFlags;
                    if ((flags & INTERACT_FLAG_PROMPT_SUPPRESSED) != 0)
                    {
                        obj->anim.resetHitboxFlags = (u8)(flags & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
                    }
                    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                        state->sequenceStarted = 1;
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(GAMEBIT_SPIRITPLACE_3_READY) != 0)
                {
                    (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                    GameBit_Set(state->promptGameBit, 0);
                    GameBit_Set(state->sequenceGameBit, 0);
                }
                else
                {
                    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                }
            }
            else
            {
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
        }
        else if (mapId == WMSPIRITPLACE_MAP_4)
        {
            if (state->mapEventMode == 4)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 flags = obj->anim.resetHitboxFlags;
                    if ((flags & INTERACT_FLAG_PROMPT_SUPPRESSED) != 0)
                    {
                        obj->anim.resetHitboxFlags = (u8)(flags & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
                    }
                    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                        state->sequenceStarted = 1;
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(GAMEBIT_SPIRITPLACE_4_READY) != 0)
                {
                    (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                    GameBit_Set(state->promptGameBit, 0);
                    GameBit_Set(state->sequenceGameBit, 0);
                }
                else
                {
                    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                }
            }
            else
            {
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
        }
        else if (mapId == WMSPIRITPLACE_MAP_5)
        {
            if (state->mapEventMode == 5)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 flags = obj->anim.resetHitboxFlags;
                    if ((flags & INTERACT_FLAG_PROMPT_SUPPRESSED) != 0)
                    {
                        obj->anim.resetHitboxFlags = (u8)(flags & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
                    }
                    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                        state->sequenceStarted = 1;
                        state->envFxPending = 1;
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(GAMEBIT_SPIRITPLACE_5_READY) != 0)
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
                        (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 4, 1);
                        (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 10, 0);
                        (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 0xb, 1);
                    }
                }
                else
                {
                    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                }
            }
            else
            {
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
        }
        else if (mapId == WMSPIRITPLACE_MAP_6)
        {
            if (state->mapEventMode == 6)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 flags = obj->anim.resetHitboxFlags;
                    if ((flags & INTERACT_FLAG_PROMPT_SUPPRESSED) != 0)
                    {
                        obj->anim.resetHitboxFlags = (u8)(flags & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
                    }
                    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
                    {
                        state->sequenceStarted = 1;
                        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(GAMEBIT_SPIRITPLACE_6_READY) != 0)
                {
                    GameBit_Set(state->promptGameBit, 0);
                    GameBit_Set(state->sequenceGameBit, 1);
                }
                else
                {
                    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                }
            }
            else
            {
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
        }
        if (state->sequenceStarted)
        {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        }
    }
}

void wmspiritplace_init(GameObject* obj, WmSpiritPlaceMapData* placement)
{
    WmSpiritPlaceState* state;

    state = obj->extra;
    obj->animEventCallback = wmspiritplace_SeqFn;
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
    obj->objectFlags = (u16)(obj->objectFlags | (WMSPIRITPLACE_OBJFLAG_HIDDEN | WMSPIRITPLACE_OBJFLAG_HITDETECT_DISABLED));
    state->mapEventMode = (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);

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
