/*
 * WM_spiritpl (DLL 0x020C) - the six Krazoa Spirit shrines at Warlock
 * Mountain on Dinosaur Planet.
 * Each placed instance is tagged by its placement ident
 * (WMSPIRITPLACE_IDENT_N) and becomes interactive once the palace's
 * map-event mode reaches N: it raises the A-button prompt, runs trigger
 * sequence 0 when the player interacts, and once the sequence game bit
 * is granted runs follow-up sequence 1. Level locks/loads, map warps,
 * sky restores and spirit vision are driven from the sequence events
 * (WM_spiritplace_SeqFn).
 *
 * The interaction prompt is driven through the INTERACT_FLAG_* bits in
 * anim.resetHitboxFlags (objanim_internal.h).
 */
#include "dlls/object_descriptor.h"
#include "main/dll/WM/dll_020C_wmspiritplace.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/tricky_api.h"
#include "main/gamebit_ids.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/map_load.h"
#include "main/objprint_render_api.h"
#include "main/objseq.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/render_envfx_api.h"
#include "main/sky_api.h"
#include "main/lightmap_render_control_api.h"

/* placement ident tags of the six spirit-place instances; place N
   becomes active once the palace's map-event mode reaches N. */
enum
{
    WMSPIRITPLACE_IDENT_1 = 0x2183,
    WMSPIRITPLACE_IDENT_2 = 0x47295,
    WMSPIRITPLACE_IDENT_3 = 0x49781,
    WMSPIRITPLACE_IDENT_4 = 0x4A1C0,
    WMSPIRITPLACE_IDENT_5 = 0x4A250,
    WMSPIRITPLACE_IDENT_6 = 0x4A5E6
};

/* Krazoa Palace map-event id (loaded/locked as spirit progress advances). */
#define WMSPIRITPLACE_MAPEVENT_KRAZOA 0x42

/* state->fxFlags: spawn the spirit particle fx each SeqFn tick */
#define WMSPIRITPLACE_FX_ACTIVE 0x1
#define WMSPIRITPLACE_PARTFX    0x7d8

/* Env-fx ids re-activated on the SKY_RESTORE seq event (getEnvfxAct 3rd arg) */
#define WMSPIRITPLACE_ENVFX_A 0x84
#define WMSPIRITPLACE_ENVFX_B 0x8a

/* sequence event opcodes consumed by WM_spiritplace_SeqFn */
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

ObjectDescriptor gWM_spiritplaceObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    WM_spiritplace_initialise,
    WM_spiritplace_release,
    0,
    (ObjectDescriptorCallback)WM_spiritplace_init,
    (ObjectDescriptorCallback)WM_spiritplace_update,
    (ObjectDescriptorCallback)WM_spiritplace_hitDetect,
    (ObjectDescriptorCallback)WM_spiritplace_render,
    WM_spiritplace_free,
    (ObjectDescriptorCallback)WM_spiritplace_getObjectTypeId,
    WM_spiritplace_getExtraSize,
};

void wmspiritplace_onSeqFree(void)
{
}

int WM_spiritplace_SeqFn(GameObject* obj, int unused, ObjSeqState* actor)
{
    int i;
    WmSpiritPlaceState* state;
    int ident;
    u8 eventId;
    PartFxSpawnParams fxPos;

    state = obj->extra;
    if ((state->fxFlags & WMSPIRITPLACE_FX_ACTIVE) != 0)
    {
        (*gPartfxInterface)->spawnEffect(obj, WMSPIRITPLACE_PARTFX, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnEffect(obj, WMSPIRITPLACE_PARTFX, &fxPos, 2, -1, NULL);
    }

    actor->movementState = 0;
    obj->anim.resetHitboxFlags =
        (u8)(obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
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
            ident = obj->anim.placement->ident;
            switch (ident)
            {
            case WMSPIRITPLACE_IDENT_2:
                warpToMap(0x7e, 0);
                break;
            case WMSPIRITPLACE_IDENT_3:
                warpToMap(0x7e, 0);
                break;
            case WMSPIRITPLACE_IDENT_4:
                warpToMap(0x7e, 0);
                break;
            }
            break;
        case WMSPIRITPLACE_SEQEV_SET_SEQUENCE_BIT:
            ident = obj->anim.placement->ident;
            switch (ident)
            {
            case WMSPIRITPLACE_IDENT_2:
            case WMSPIRITPLACE_IDENT_3:
            case WMSPIRITPLACE_IDENT_4:
            case WMSPIRITPLACE_IDENT_5:
            case WMSPIRITPLACE_IDENT_6:
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
            skySetSlotFlag80(7, 0);
            setDrawCloudsAndLights(1);
            getEnvfxAct(obj, obj, WMSPIRITPLACE_ENVFX_A, 0);
            getEnvfxAct(obj, obj, WMSPIRITPLACE_ENVFX_B, 0);
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
            ident = obj->anim.placement->ident;
            switch (ident)
            {
            case WMSPIRITPLACE_IDENT_1:
                lockLevel(mapGetDirIdx(0x41), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*gMapEventInterface)->setCharacter(1);
                break;
            case WMSPIRITPLACE_IDENT_2:
                loadMapAndParent(WMSPIRITPLACE_MAPEVENT_KRAZOA);
                lockLevel(mapGetDirIdx(WMSPIRITPLACE_MAPEVENT_KRAZOA), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*gMapEventInterface)->setMapAct(WMSPIRITPLACE_MAPEVENT_KRAZOA, 3);
                (*gMapEventInterface)->setMapAct(7, 4);
                break;
            case WMSPIRITPLACE_IDENT_3:
                loadMapAndParent(WMSPIRITPLACE_MAPEVENT_KRAZOA);
                lockLevel(mapGetDirIdx(WMSPIRITPLACE_MAPEVENT_KRAZOA), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*gMapEventInterface)->setMapAct(WMSPIRITPLACE_MAPEVENT_KRAZOA, 3);
                (*gMapEventInterface)->setMapAct(7, 5);
                break;
            case WMSPIRITPLACE_IDENT_4:
                loadMapAndParent(WMSPIRITPLACE_MAPEVENT_KRAZOA);
                lockLevel(mapGetDirIdx(WMSPIRITPLACE_MAPEVENT_KRAZOA), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*gMapEventInterface)->setMapAct(WMSPIRITPLACE_MAPEVENT_KRAZOA, 3);
                (*gMapEventInterface)->setMapAct(7, 7);
                break;
            }
            break;
        }
    }

    return 0;
}

int WM_spiritplace_getExtraSize(void)
{
    return sizeof(WmSpiritPlaceState);
}

int WM_spiritplace_getObjectTypeId(void)
{
    return 0x0;
}

void WM_spiritplace_free(void)
{
}

void WM_spiritplace_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0)
    {
        return;
    }
}

void WM_spiritplace_hitDetect(GameObject* obj)
{
    if (obj->anim.hitVolumeTransforms != NULL)
    {
        objUpdateHitVolumeTransforms(obj);
    }
}

void WM_spiritplace_update(GameObject* obj)
{
    WmSpiritPlaceState* state;
    u32 ident;

    state = obj->extra;
    if (state->transitionDelay != 0)
    {
        state->transitionDelay--;
        if (state->transitionDelay == 0)
        {
            mainSetBits(state->sequenceGameBit, 1);
        }
    }
    else
    {
        state->fxFlags &= ~WMSPIRITPLACE_FX_ACTIVE;
        ident = obj->anim.placement->ident;
        if (ident == WMSPIRITPLACE_IDENT_2)
        {
            if (state->mapEventMode == 2)
            {
                if (mainGetBit(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
                if (mainGetBit(state->promptGameBit) != 0)
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
                        mainSetBits(state->promptGameBit, 0);
                        state->sequenceStarted = 1;
                    }
                }
                else if (mainGetBit(state->sequenceGameBit) != 0 &&
                         mainGetBit(GAMEBIT_WM_SpiritPlace2Ready) != 0)
                {
                    (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                    mainSetBits(state->promptGameBit, 0);
                    mainSetBits(state->sequenceGameBit, 0);
                    mainSetBits(GAMEBIT_ITEM_TestCombatSpirit_Got, 0);
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
        else if (ident == WMSPIRITPLACE_IDENT_1)
        {
            if (state->mapEventMode == 1)
            {
                if (mainGetBit(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
                if (mainGetBit(state->promptGameBit) != 0)
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
                        mainSetBits(state->sequenceGameBit, 1);
                        mainSetBits(state->promptGameBit, 0);
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
        else if (ident == WMSPIRITPLACE_IDENT_3)
        {
            if (state->mapEventMode == 3)
            {
                if (mainGetBit(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
                if (mainGetBit(state->promptGameBit) != 0)
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
                        mainSetBits(state->promptGameBit, 0);
                        state->sequenceStarted = 1;
                    }
                }
                else if (mainGetBit(state->sequenceGameBit) != 0 &&
                         mainGetBit(GAMEBIT_WM_SpiritPlace3Ready) != 0)
                {
                    (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                    mainSetBits(state->promptGameBit, 0);
                    mainSetBits(state->sequenceGameBit, 0);
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
        else if (ident == WMSPIRITPLACE_IDENT_4)
        {
            if (state->mapEventMode == 4)
            {
                if (mainGetBit(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
                if (mainGetBit(state->promptGameBit) != 0)
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
                        mainSetBits(state->promptGameBit, 0);
                        state->sequenceStarted = 1;
                    }
                }
                else if (mainGetBit(state->sequenceGameBit) != 0 &&
                         mainGetBit(GAMEBIT_WM_SpiritPlace4Ready) != 0)
                {
                    (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                    mainSetBits(state->promptGameBit, 0);
                    mainSetBits(state->sequenceGameBit, 0);
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
        else if (ident == WMSPIRITPLACE_IDENT_5)
        {
            if (state->mapEventMode == 5)
            {
                if (mainGetBit(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
                if (mainGetBit(state->promptGameBit) != 0)
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
                        mainSetBits(state->promptGameBit, 0);
                        state->sequenceStarted = 1;
                        state->envFxPending = 1;
                    }
                }
                else if (mainGetBit(state->sequenceGameBit) != 0 &&
                         mainGetBit(GAMEBIT_WM_SpiritPlace5Ready) != 0)
                {
                    if (state->envFxPending)
                    {
                        state->envFxPending = 0;
                        mainSetBits(state->promptGameBit, 0);
                        mainSetBits(GAMEBIT_WMRelated0D1F, 1);
                        getEnvfxActImmediately(0, 0, 0x217, 0);
                        getEnvfxActImmediately(obj, obj, 0x216, 0);
                        getEnvfxActImmediately(obj, obj, 0x229, 0);
                        getEnvfxActImmediately(obj, obj, 0x22a, 0);
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
        else if (ident == WMSPIRITPLACE_IDENT_6)
        {
            if (state->mapEventMode == 6)
            {
                if (mainGetBit(state->promptGameBit) == 0)
                {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
                if (mainGetBit(state->promptGameBit) != 0)
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
                        mainSetBits(state->promptGameBit, 0);
                    }
                }
                else if (mainGetBit(state->sequenceGameBit) != 0 &&
                         mainGetBit(GAMEBIT_WM_SpiritPlace6Ready) != 0)
                {
                    mainSetBits(state->promptGameBit, 0);
                    mainSetBits(state->sequenceGameBit, 1);
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

void WM_spiritplace_init(GameObject* obj, WmSpiritPlaceMapData* placement)
{
    WmSpiritPlaceState* state;

    state = obj->extra;
    obj->animEventCallback = WM_spiritplace_SeqFn;
    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->anim.rotY = (s16)(placement->rotYAngle << 8);
    state->heightOffset = (placement->heightOffset / 32767.0f) / 100.0f;
    state->unk_04 = 0;
    state->unk_08 = 0;
    state->unk_0A = 0;
    state->sequenceGameBit = placement->sequenceGameBit;
    state->promptGameBit = placement->promptGameBit;
    state->setupParam = placement->setupParam;
    state->sequenceStarted = 0;
    obj->objectFlags =
        (u16)(obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED));
    state->mapEventMode = (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);

    if (obj->anim.placement->ident == WMSPIRITPLACE_IDENT_2)
    {
        if (mainGetBit(GAMEBIT_WM_FoundKrystal) != 0 || mainGetBit(GAMEBIT_WM_SpiritPlaceShifted0EAF) != 0 ||
            state->mapEventMode > 2)
        {
            obj->anim.localPosX -= 25.0f;
        }
    }
    else if (obj->anim.placement->ident == WMSPIRITPLACE_IDENT_6 && state->mapEventMode >= 6)
    {
        obj->anim.localPosX += 25.0f;
    }
}

void WM_spiritplace_release(void)
{
}

void WM_spiritplace_initialise(void)
{
}
