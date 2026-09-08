/*
 * Ocean Force Point Temple object creator (DLL 0x22A; "DFP_ObjCreator") - a
 * spawner object that periodically creates child objects from a stored
 * placement template, gated by a gamebit and a spawn-period timer. Mode 7 creates DFP_WaterHi
 * objects with a 220-frame lifetime.
 */
#include "dlls/objects/554_DFP_ObjCrea.h"

#include "dlls/objects/298_CFCrate.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"

#define DFPOBJCREATOR_MODE_PERIODIC_WATER 7
#define DFPOBJCREATOR_CHILD_LINGER_FRAMES 220

int DFP_ObjCreator_getExtraSize(void)
{
    return sizeof(DfpObjCreatorState);
}
int DFP_ObjCreator_getObjectTypeId(void)
{
    return 0x0;
}

void DFP_ObjCreator_free(GameObject* obj, int flag)
{
    DfpObjCreatorState* state = obj->extra;
    if (flag == 0)
    {
        if (state->ownedObj != NULL)
        {
            Obj_FreeObject(state->ownedObj);
            state->ownedObj = NULL;
        }
    }
}

void DFP_ObjCreator_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0)
        return;
}

void DFP_ObjCreator_hitDetect(void)
{
}

void DFP_ObjCreator_update(GameObject* obj)
{

    DfpObjCreatorPlacementPrefix* data = (DfpObjCreatorPlacementPrefix*)obj->anim.placementData;
    DfpObjCreatorState* state = obj->extra;
    CFCratePlacement* setup;
    GameObject* newObj;
    u8 canSetupObject;

    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject > 0)
    {
        switch (data->behaviorMode)
        {
        case DFPOBJCREATOR_MODE_PERIODIC_WATER:
            state->spawnTimer -= (s16)timeDelta;
            if (state->spawnTimer <= 0 && mainGetBit(state->gameBit) != 0)
            {
                state->spawnTimer = state->spawnPeriod;
                setup = (CFCratePlacement*)Obj_AllocObjectSetup(sizeof(CFCratePlacement), CFCRATE_OBJ_DFP_WATER_HI);
                setup->base.posX = data->base.posX;
                setup->base.posY = data->base.posY;
                setup->base.posZ = data->base.posZ;
                setup->base.color[0] = data->base.color[0];
                setup->base.color[1] = data->base.color[1];
                setup->base.color[2] = data->base.color[2];
                setup->base.color[3] = data->base.color[3];
                setup->gameBitA = -1;
                setup->gameBitB = -1;
                setup->lingerFrames = DFPOBJCREATOR_CHILD_LINGER_FRAMES;
                newObj = objSetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                newObj->userData1 = data->parameter.childUserData1;
            }
            break;
        }
    }
}

void DFP_ObjCreator_init(GameObject* obj, DfpObjCreatorPlacementPrefix* def)
{
    DfpObjCreatorState* state = obj->extra;
    obj->anim.rotX = (s16)((s32)def->parameter.rotationHighByte << 8);
    state->gameBit = def->gameBit;
    state->spawnPeriod = def->spawnPeriod;
    state->spawnTimer = state->spawnPeriod;
    state->unk12 = (s16)(s32)def->unk1F;
    state->unk14 = (s16)((s32)def->unk20 << 1);
    state->unk16 = 100;
}

void DFP_ObjCreator_release(void)
{
}

void DFP_ObjCreator_initialise(void)
{
}

ObjectDescriptor gDFP_ObjCreatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DFP_ObjCreator_initialise,
    (ObjectDescriptorCallback)DFP_ObjCreator_release,
    0,
    (ObjectDescriptorCallback)DFP_ObjCreator_init,
    (ObjectDescriptorCallback)DFP_ObjCreator_update,
    (ObjectDescriptorCallback)DFP_ObjCreator_hitDetect,
    (ObjectDescriptorCallback)DFP_ObjCreator_render,
    (ObjectDescriptorCallback)DFP_ObjCreator_free,
    (ObjectDescriptorCallback)DFP_ObjCreator_getObjectTypeId,
    DFP_ObjCreator_getExtraSize,
};
