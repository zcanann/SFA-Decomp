/* DLL 0x0221 */
#include "dlls/object_descriptor.h"
#include "dlls/objects/525_WM_seqpoint.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "game/objects/object_setup.h"
#include "main/map_load.h"
#include "main/rcp_dolphin_api.h"
#include "main/pi_dolphin_api.h"


typedef enum SeqPointMode
{
    SEQPOINT_MODE_RADIUS = 0,
    SEQPOINT_MODE_BIT = 1,
    SEQPOINT_MODE_RADIUS_AND_BIT = 2,
    SEQPOINT_MODE_RADIUS_BIT_ONCE = 3,
    SEQPOINT_MODE_BIT_ONCE = 4,
    SEQPOINT_MODE_BIT_REPEAT = 5
} SeqPointMode;

typedef struct SeqPointState
{
    f32 triggerRadius;
    s16 conditionGameBit;
    s16 disableGameBit;
    s16 sequenceId;
    u8 pad0A[3];
    u8 doneLatch;
    u8 triggerMode;
    u8 pad0F;
} SeqPointState;

STATIC_ASSERT(sizeof(SeqPointState) == 0x10);

int SeqPoint_SeqFn(GameObject* obj, int param2, ObjSeqState* ctx);
int SeqPoint_getExtraSize(void);
int SeqPoint_getObjectTypeId(void);
void SeqPoint_free(void);
void SeqPoint_render(GameObject* p1, int p2, int p3, int p4, int p5, s8 visible);
void SeqPoint_hitDetect(void);
void SeqPoint_update(GameObject* obj);
void SeqPoint_init(GameObject* obj, WmSeqPointMapData* data);
void SeqPoint_release(void);
void SeqPoint_initialise(void);

int SeqPoint_SeqFn(GameObject* obj, int param2, ObjSeqState* ctx)
{
    SeqPointState* state = obj->extra;
    int i;

    ctx->savedFlags = -1;
    ctx->movementState = 0;
    for (i = 0; i < ctx->eventCount; i++)
    {
        switch (state->sequenceId)
        {
        case 0:
            break;
        case 13:
            switch (ctx->eventIds[i])
            {
            case 20:
                mainSetBits(GAMEBIT_VFP_ObjGroups, 0);
                mainSetBits(GAMEBIT_VFPRelated0D72, 1);
                mainSetBits(GAMEBIT_VFPLightRelated0D44, 1);
                (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 1, 1);
                (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 2, 1);
                (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 22, 1);
                if ((*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot) == 1)
                {
                    unlockLevel(0, 0, 1);
                    lockLevel(mapGetDirIdx(70), 1);
                    lockLevel(mapGetDirIdx(4), 0);
                    loadMapAndParent(70);
                    (*gMapEventInterface)->setMapAct(18, 2);
                    warpToMap(124, 0);
                }
                else if ((*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot) == 2)
                {
                    unlockLevel(0, 0, 1);
                    lockLevel(mapGetDirIdx(70), 1);
                    lockLevel(mapGetDirIdx(4), 0);
                    loadMapAndParent(70);
                    (*gMapEventInterface)->setMapAct(11, 4);
                    (*gMapEventInterface)->setMapAct(8, 6);
                    warpToMap(124, 0);
                }
                break;
            }
            break;
        }
        ctx->eventIds[i] = 0;
    }
    return 0;
}

int SeqPoint_getExtraSize(void)
{
    return 0x10;
}

int SeqPoint_getObjectTypeId(void)
{
    return 0x0;
}

void SeqPoint_free(void)
{
}

void SeqPoint_render(GameObject* p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 isVisible = visible;
    if (isVisible != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void SeqPoint_hitDetect(void)
{
}

void SeqPoint_update(GameObject* obj)
{
    GameObject* player = Obj_GetPlayerObject();
    SeqPointState* self = obj->extra;
    int key = self->disableGameBit;

    if (key != -1)
    {
        if (self->doneLatch != 0)
        {
            if (mainGetBit(key) != 0)
                return;
            mainSetBits(self->disableGameBit, 1);
            self->doneLatch = 1;
            return;
        }
        if (mainGetBit(key) != 0)
        {
            self->doneLatch = 1;
            return;
        }
    }
    if (self->doneLatch != 0)
        return;
    switch (self->triggerMode)
    {
    case SEQPOINT_MODE_RADIUS:
        if (!(Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) <
              self->triggerRadius))
            return;
        (*gObjectTriggerInterface)->runSequence(self->sequenceId, obj, -1);
        self->doneLatch = 1;
        break;
    case SEQPOINT_MODE_BIT:
        if (self->conditionGameBit == -1)
            return;
        if (mainGetBit(self->conditionGameBit) == 0)
            return;
        (*gObjectTriggerInterface)->runSequence(self->sequenceId, obj, -1);
        self->doneLatch = 1;
        break;
    case SEQPOINT_MODE_RADIUS_AND_BIT:
        if (!(Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) <
              self->triggerRadius))
            return;
        if (self->conditionGameBit == -1)
            return;
        if (mainGetBit(self->conditionGameBit) == 0)
            return;
        (*gObjectTriggerInterface)->runSequence(self->sequenceId, obj, -1);
        self->doneLatch = 1;
        break;
    case SEQPOINT_MODE_RADIUS_BIT_ONCE:
        if (!(Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) <
              self->triggerRadius))
            return;
        if (self->conditionGameBit == -1)
            return;
        if (mainGetBit(self->conditionGameBit) != 0)
            return;
        (*gObjectTriggerInterface)->runSequence(self->sequenceId, obj, -1);
        mainSetBits(self->conditionGameBit, 1);
        self->doneLatch = 1;
        break;
    case SEQPOINT_MODE_BIT_ONCE:
        if (self->conditionGameBit == -1)
            return;
        if (mainGetBit(self->conditionGameBit) != 0)
            return;
        (*gObjectTriggerInterface)->runSequence(self->sequenceId, obj, -1);
        mainSetBits(self->conditionGameBit, 1);
        self->doneLatch = 1;
        break;
    case SEQPOINT_MODE_BIT_REPEAT:
        if (self->conditionGameBit == -1)
            return;
        if (mainGetBit(self->conditionGameBit) == 0)
            return;
        (*gObjectTriggerInterface)->runSequence(self->sequenceId, obj, -1);
        break;
    }
}

void SeqPoint_init(GameObject* obj, WmSeqPointMapData* data)
{
    WmSeqPointMapData* def = data;
    SeqPointState* state = obj->extra;
    obj->animEventCallback = SeqPoint_SeqFn;
    obj->anim.rotX = (((s32)def->rotXByte) << 8);
    state->triggerRadius = def->triggerRadius;
    state->sequenceId = def->sequenceId;
    state->triggerMode = def->triggerMode;
    state->conditionGameBit = def->conditionGameBit;
    state->disableGameBit = def->disableGameBit;
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void SeqPoint_release(void)
{
}

void SeqPoint_initialise(void)
{
}

ObjectDescriptor gSeqPointObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)SeqPoint_initialise,
    (ObjectDescriptorCallback)SeqPoint_release,
    0,
    (ObjectDescriptorCallback)SeqPoint_init,
    (ObjectDescriptorCallback)SeqPoint_update,
    (ObjectDescriptorCallback)SeqPoint_hitDetect,
    (ObjectDescriptorCallback)SeqPoint_render,
    (ObjectDescriptorCallback)SeqPoint_free,
    (ObjectDescriptorCallback)SeqPoint_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)SeqPoint_getExtraSize,
};
