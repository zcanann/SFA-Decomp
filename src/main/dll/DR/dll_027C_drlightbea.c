/*
 * drlightbea (DLL 0x27C) - a lightning-beam effect that arcs from this
 * object to a target while its placement game bit (0x20) is set.
 *
 * The target is either another placed object (resolved by id via
 * dll_2E_func0A when the placement target byte at 0x19 is non-zero) or
 * the player. While active, render keeps the beam's endpoints synced to
 * the live source/target positions, advances its lifetime counter and
 * frees the beam once it expires. The extra state (0xc bytes) holds the
 * lightningCreate handle at offset 0 and the active/free bit flags at
 * offset 4.
 */
#include "main/dll/dll_002E_moveLib.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/mm.h"
#include "main/newclouds.h"
#include "main/object_api.h"
#include "main/obj_placement.h"
#include "main/vecmath.h"
#include "main/object_descriptor.h"

#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/lightningeffect.h"

#include "main/dll/DR/dll_027C_drlightbea.h"


int DR_LightBea_getExtraSize(void)
{
    return 0xc;
}

int DR_LightBea_getObjectTypeId(void)
{
    return 0;
}

void DR_LightBea_free(GameObject* obj)
{
    DrLightBeaState* state = obj->extra;
    LightningEffect* buffer = state->handle;

    if (buffer != NULL)
    {
        mm_free(buffer);
        state->handle = NULL;
    }
}

void DR_LightBea_render(GameObject* obj, int p2, int p3, int p4, int p5)
{
    DrLightBeaState* state = obj->extra;
    DrlightbeaPlacement* setup = (DrlightbeaPlacement*)obj->anim.placementData;
    GameObject* player;
    MoveLibTarget target;
    f32 sourcePos[3];
    f32 targetPos[3];

    if (state->flags.bit80)
    {
        state->handle->start[0] = (obj)->anim.localPosX;
        state->handle->start[1] = (obj)->anim.localPosY;
        state->handle->start[2] = (obj)->anim.localPosZ;
        if (setup->targetId == 0)
        {
            player = Obj_GetPlayerObject();
            state->handle->end[0] = player->anim.localPosX;
            state->handle->end[1] = 15.0f + player->anim.localPosY;
            state->handle->end[2] = player->anim.localPosZ;
        }
        lightningRenderLegacy(state->handle);
        state->handle->timer += 1;
        if (state->handle->timer >= state->handle->lifetime)
        {
            mm_free(state->handle);
            state->handle = NULL;
            state->flags.bit80 = 0;
            if ((u32)setup->base.mapId == 0xffffffff)
            {
                state->flags.bit40 = 1;
            }
        }
    }
    else
    {
        if (state->handle != NULL)
        {
            mm_free(state->handle);
            state->handle = NULL;
        }
        state->flags.bit80 = mainGetBit(setup->gameBit);
        if (state->flags.bit80)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_id_30f);
            sourcePos[0] = (obj)->anim.localPosX;
            sourcePos[1] = (obj)->anim.localPosY;
            sourcePos[2] = (obj)->anim.localPosZ;
            if (setup->targetId != 0 && dll_2E_func0A(setup->targetId, &target) != 0)
            {
                targetPos[0] = target.x;
                targetPos[1] = target.y;
                targetPos[2] = target.z;
            }
            else
            {
                player = Obj_GetPlayerObject();
                targetPos[0] = player->anim.localPosX;
                targetPos[1] = 15.0f + player->anim.localPosY;
                targetPos[2] = player->anim.localPosZ;
            }
            state->handle = lightningCreateU16Promoted((const Vec3f*)sourcePos, (const Vec3f*)targetPos,
                                                       0.05f, 0.1f, randomGetRange(5, 0xf), 0x60, 0);
        }
    }
}

void DR_LightBea_hitDetect(void)
{
}

void DR_LightBea_update(GameObject* obj)
{
    DrLightBeaState* state = obj->extra;
    if (state->flags.bit40)
    {
        Obj_FreeObject(obj);
    }
}

void DR_LightBea_init(GameObject* obj)
{
    DrLightBeaState* state = obj->extra;
    state->flags.bit80 = 0;
    state->handle = NULL;
    state->flags.bit40 = 0;
}

void DR_LightBea_release(void)
{
}

void DR_LightBea_initialise(void)
{
}

ObjectDescriptor gDrLightBeaObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DR_LightBea_initialise,
    (ObjectDescriptorCallback)DR_LightBea_release,
    0,
    (ObjectDescriptorCallback)DR_LightBea_init,
    (ObjectDescriptorCallback)DR_LightBea_update,
    (ObjectDescriptorCallback)DR_LightBea_hitDetect,
    (ObjectDescriptorCallback)DR_LightBea_render,
    (ObjectDescriptorCallback)DR_LightBea_free,
    (ObjectDescriptorCallback)DR_LightBea_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)DR_LightBea_getExtraSize,
};

u32 lbl_8032AD68[12] = {
    0xFFFFFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};
