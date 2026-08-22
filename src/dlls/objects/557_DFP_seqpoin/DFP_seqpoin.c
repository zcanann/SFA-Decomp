/*
 * DragonRock Palace sequence point (DLL 0x22D; "DFP_seqpoint") - a
 * trigger volume: when the player enters its radius and the gate gamebit
 * is set it fires a trigger sequence, latches done, and sets the done
 * gamebit.
 */
#include "main/dll/DF/dll_022D_dfpseqpoint.h"
#include "main/dll/dfp_types.h"
#include "main/map_load.h"
#include "main/object_render_legacy.h"
#include "main/gamebits.h"
#include "game/objects/object_setup.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

/* Placement trigger-mode selector (DfpSeqPointState::triggerMode). */
#define DFPSEQPOINT_MODE_RADIUS           0 /* player within radius */
#define DFPSEQPOINT_MODE_GATE             1 /* gate gamebit set */
#define DFPSEQPOINT_MODE_RADIUS_AND_GATE  2 /* within radius and gate set */
#define DFPSEQPOINT_MODE_RADIUS_AND_UNSET 3 /* within radius and gate clear, then set gate */
#define DFPSEQPOINT_MODE_GATE_UNSET       4 /* gate clear, then set gate */
#define DFPSEQPOINT_MODE_GATE_REPEAT      5 /* gate set, fire every frame (no latch) */

STATIC_ASSERT(sizeof(DfpSeqPointState) == 0x10);

int DFP_seqpoint_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate)
{
    DfpSeqPointState* blob = obj->extra;
    DfpSeqPointPlacement* data = (DfpSeqPointPlacement*)obj->anim.placementData;
    int i;

    animUpdate->savedFlags = -1;
    animUpdate->movementState = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (blob->sequenceId)
        {
        case 1:
            switch (animUpdate->eventIds[i])
            {
            case 1:
                if ((*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot) == 1)
                {
                    (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 5, 0);
                    (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 6, 0);
                    (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 7, 0);
                }
                else if ((*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot) == 2)
                {
                    (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 5, 0);
                    (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 6, 0);
                    (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 7, 0);
                }
                break;
            }
            break;
        case 0xa:
            switch (animUpdate->eventIds[i])
            {
            case 0x14:
                if (*(u32*)&data->base.ident == 0x49de8)
                {
                    blob->flags0F.b80 = 1;
                }
                else
                {
                    if ((*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot) == 1 ||
                        (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot) == 2)
                    {
                        unlockLevel(0, 0, 1);
                        lockLevel(mapGetDirIdx(0x32), 0);
                        (*gMapEventInterface)->setMapAct(0x32, 2);
                        warpToMap(0x73, 0);
                    }
                }
                break;
            }
            break;
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}

int DFP_seqpoint_getExtraSize(void)
{
    return 0x10;
}
int DFP_seqpoint_getObjectTypeId(void)
{
    return 0x0;
}

void DFP_seqpoint_free(void)
{
}

void DFP_seqpoint_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void DFP_seqpoint_hitDetect(void)
{
}

void DFP_seqpoint_update(GameObject* obj)
{
    GameObject* self;
    GameObject* player;
    DfpSeqPointState* state;
    int gameBit;

    self = obj;
    player = Obj_GetPlayerObject();
    state = self->extra;
    if (state->flags0F.b80 != 0)
    {
        mainSetBits(0xef7, 1);
        state->flags0F.b80 = 0;
    }
    gameBit = state->disableGameBit;
    if (gameBit != -1)
    {
        if (state->doneLatch != 0)
        {
            if (mainGetBit(gameBit) != 0)
            {
                return;
            }
            mainSetBits(state->disableGameBit, 1);
            state->doneLatch = 1;
            return;
        }
        if (mainGetBit(gameBit) != 0)
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
    case DFPSEQPOINT_MODE_RADIUS:
        if (Vec_distance(&self->anim.worldPosX, &player->anim.worldPosX) < state->triggerRadius)
        {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
            state->doneLatch = 1;
        }
        break;
    case DFPSEQPOINT_MODE_GATE:
        gameBit = state->conditionGameBit;
        if (gameBit != -1 && mainGetBit(gameBit) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
            state->doneLatch = 1;
        }
        break;
    case DFPSEQPOINT_MODE_RADIUS_AND_GATE:
        if (Vec_distance(&self->anim.worldPosX, &player->anim.worldPosX) < state->triggerRadius)
        {
            gameBit = state->conditionGameBit;
            if (gameBit != -1 && mainGetBit(gameBit) != 0)
            {
                (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
                state->doneLatch = 1;
            }
        }
        break;
    case DFPSEQPOINT_MODE_RADIUS_AND_UNSET:
        if (Vec_distance(&self->anim.worldPosX, &player->anim.worldPosX) < state->triggerRadius)
        {
            gameBit = state->conditionGameBit;
            if (gameBit != -1 && mainGetBit(gameBit) == 0)
            {
                (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
                mainSetBits(state->conditionGameBit, 1);
                state->doneLatch = 1;
            }
        }
        break;
    case DFPSEQPOINT_MODE_GATE_UNSET:
        gameBit = state->conditionGameBit;
        if (gameBit != -1 && mainGetBit(gameBit) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
            mainSetBits(state->conditionGameBit, 1);
            state->doneLatch = 1;
        }
        break;
    case DFPSEQPOINT_MODE_GATE_REPEAT:
        gameBit = state->conditionGameBit;
        if (gameBit != -1 && mainGetBit(gameBit) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
        }
        break;
    }
}

void DFP_seqpoint_init(GameObject* obj, u8* init)
{
    DfpSeqPointState* sub;
    sub = obj->extra;
    obj->animEventCallback = DFP_seqpoint_SeqFn;
    obj->anim.rotX = (s16)(((DfpSeqPointPlacement*)init)->spawnRot << 8);
    sub->triggerRadius = (f32)(s32)((DfpSeqPointPlacement*)init)->triggerRadius;
    sub->sequenceId = ((DfpSeqPointPlacement*)init)->sequenceId;
    sub->triggerMode = ((DfpSeqPointPlacement*)init)->triggerMode;
    sub->conditionGameBit = ((DfpSeqPointPlacement*)init)->conditionGameBit;
    sub->disableGameBit = ((DfpSeqPointPlacement*)init)->disableGameBit;
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    sub->flags0F.b80 = 0;
}

void DFP_seqpoint_release(void)
{
}

void DFP_seqpoint_initialise(void)
{
}

ObjectDescriptor gDFP_seqpointObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DFP_seqpoint_initialise,
    (ObjectDescriptorCallback)DFP_seqpoint_release,
    0,
    (ObjectDescriptorCallback)DFP_seqpoint_init,
    (ObjectDescriptorCallback)DFP_seqpoint_update,
    (ObjectDescriptorCallback)DFP_seqpoint_hitDetect,
    (ObjectDescriptorCallback)DFP_seqpoint_render,
    (ObjectDescriptorCallback)DFP_seqpoint_free,
    (ObjectDescriptorCallback)DFP_seqpoint_getObjectTypeId,
    DFP_seqpoint_getExtraSize,
};
