/*
 * DragonRock Shrine object creator (DLL 0x179; "DFSH_ObjCreator") - a
 * spawner that, once its gamebit arms, builds a SpiritPrize object setup
 * (object id 0x11) from its placement template and periodically spawns it
 * while loading is locked, playing the gem-run sfx.
 */
#include "main/obj_placement.h"
#include "main/dll/DF/dll_0179_dfshobjcreator.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/resource.h"
#include "main/object.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/object_descriptor.h"
#include "main/dll/foodbag.h"

/* Object id of the SpiritPrize object this creator spawns (docblock:
 * "builds a SpiritPrize object setup (object id 0x11)"). */
#define DFSHOBJCREATOR_SPIRITPRIZE_OBJ_ID 0x11
#define DFSHOBJCREATOR_DISABLE_GAMEBIT     0x589
#define DFSHOBJCREATOR_TRIGGER_GAMEBIT_BASE 0xF6
#define DFSHOBJCREATOR_REWARD_GAMEBIT      0xFC

int DFSH_ObjCreator_getExtraSize(void)
{
    return sizeof(DfshObjCreatorState);
}
int DFSH_ObjCreator_getObjectTypeId(void)
{
    return 0x0;
}

void DFSH_ObjCreator_free(void)
{
}

void DFSH_ObjCreator_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, gDfshObjCreatorRenderScale);
}

void DFSH_ObjCreator_hitDetect(void)
{
}

void DFSH_ObjCreator_update(GameObject* obj)
{

    DfshObjCreatorPlacement* placement = (DfshObjCreatorPlacement*)obj->anim.placement;
    DfshObjCreatorState* state = obj->extra;
    Dll82Interface** resource;
    DfshObjCreatorSpawnSetup* spawnSetup;

    if (mainGetBit(DFSHOBJCREATOR_DISABLE_GAMEBIT) != 0)
    {
        obj->userData2 = 0;
        return;
    }

    if (obj->userData2 == 0 &&
        mainGetBit(placement->triggerGameBitOffset + DFSHOBJCREATOR_TRIGGER_GAMEBIT_BASE) != 0)
    {
        resource = Resource_Acquire(0x82, 1);
        (*resource)->spawn(obj, 0, NULL, 1, -1, NULL);
        (*resource)->spawn(obj, 1, NULL, 1, -1, NULL);
        Sfx_PlayFromObject((int)obj, SFXTRIG_hitpos_6);
        Resource_Release(resource);
        state->spawnTimerStep = 1;
        obj->userData2 = 1;
    }

    if (state->spawnTimerStep != 0)
    {
        state->spawnTimer = (s16)(state->spawnTimer - state->spawnTimerStep * (int)timeDelta);
    }

    if (Obj_IsLoadingLocked() != 0 && state->spawnTimer <= 0)
    {
        spawnSetup = (DfshObjCreatorSpawnSetup*)Obj_AllocObjectSetup(sizeof(DfshObjCreatorSpawnSetup),
                                                                    DFSHOBJCREATOR_SPIRITPRIZE_OBJ_ID);
        spawnSetup->base.posX = placement->base.posX;
        spawnSetup->base.posY = placement->base.posY;
        spawnSetup->base.posZ = placement->base.posZ;
        spawnSetup->base.mapId = placement->base.mapId;
        spawnSetup->base.color[0] = placement->base.color[0];
        spawnSetup->base.color[1] = placement->base.color[1];
        spawnSetup->base.color[2] = placement->base.color[2];
        spawnSetup->base.color[3] = placement->base.color[3];
        spawnSetup->unk27 = 3;
        spawnSetup->unk18 = 0x1e7;
        spawnSetup->unk30 = -1;
        spawnSetup->unk1A = -1;
        spawnSetup->unk1C = -1;
        spawnSetup->rotByte = (s8)(obj->anim.rotX >> 8);
        spawnSetup->unk2B = 2;
        if (mainGetBit(DFSHOBJCREATOR_REWARD_GAMEBIT) != 0)
        {
            spawnSetup->unk22 = 0x49;
        }
        else
        {
            spawnSetup->unk22 = -1;
        }
        spawnSetup->unk29 = 0xff;
        spawnSetup->unk2E = -1;
        spawnSetup->unk34 = 0xffff;
        Obj_SetupObject(&spawnSetup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
        state->spawnTimer = 100;
        state->spawnTimerStep = 0;
    }
}

void DFSH_ObjCreator_init(GameObject* obj, DfshObjCreatorPlacement* placement)
{
    DfshObjCreatorState* state = obj->extra;
    obj->anim.rotX = (s16)((s32)placement->rotByte << 8);
    obj->userData2 = 0;
    state->spawnTimer = 100;
    state->spawnTimerStep = 0;
    obj->anim.renderAlpha = 0xFF;
    obj->anim.alpha = 0xFF;
}

void DFSH_ObjCreator_release(void)
{
}

void DFSH_ObjCreator_initialise(void)
{
}

ObjectDescriptor gDFSH_ObjCreatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DFSH_ObjCreator_initialise,
    (ObjectDescriptorCallback)DFSH_ObjCreator_release,
    0,
    (ObjectDescriptorCallback)DFSH_ObjCreator_init,
    (ObjectDescriptorCallback)DFSH_ObjCreator_update,
    (ObjectDescriptorCallback)DFSH_ObjCreator_hitDetect,
    (ObjectDescriptorCallback)DFSH_ObjCreator_render,
    (ObjectDescriptorCallback)DFSH_ObjCreator_free,
    (ObjectDescriptorCallback)DFSH_ObjCreator_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)DFSH_ObjCreator_getExtraSize,
};
