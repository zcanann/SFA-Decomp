/*
 * DLL 0x157 - spirit door spirit; the last entry of the sandwormBoss
 * 10-DLL container (0x14A CFPowerBase .. 0x157 SpiritDoorSpirit) covering
 * [8019D578-801A0B14).
 *
 * A spirit-door spirit is a fade-in/fade-out apparition gated on a game
 * bit (placement->gateGameBit). While the bit is clear the spirit is "active":
 * it joins object group 0x4E, runs its idle effect (fn_80098B18), and
 * fades alpha up to 0xFF; once the bit is set it leaves the group and
 * fades alpha back to 0. It only renders while active.
 */
#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/objfx.h"
#include "main/object_render.h"
#include "main/gamebits.h"
#include "main/dll/dll_0157_spiritdoorspirit.h"
#include "main/object_descriptor.h"

f32 lbl_803DBE78 = 0.7f;

#define SPIRITDOORSPIRIT_OBJGROUP 0x4e


int spiritdoorspirit_getExtraSize(void)
{
    return 0x1;
}
int spiritdoorspirit_getObjectTypeId(void)
{
    return 0x0;
}

void spiritdoorspirit_free(GameObject* obj)
{
    ObjGroup_RemoveObject((int)obj, SPIRITDOORSPIRIT_OBJGROUP);
}


void spiritdoorspirit_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    SpiritDoorSpiritState* state = obj->extra;
    if (visible == 0 || state->active == 0)
    {
        return;
    }

    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void spiritdoorspirit_hitDetect(void)
{
}

void spiritdoorspirit_update(GameObject* obj)
{
    SpiritdoorspiritPlacement* def = *(SpiritdoorspiritPlacement**)&obj->anim.placementData;
    SpiritDoorSpiritState* state = obj->extra;
    u8 active;

    if (state->active == 0)
    {
        state->active = active = (u8)(mainGetBit(def->gateGameBit) == 0);
        if (active != 0)
        {
            ObjGroup_AddObject((int)obj, SPIRITDOORSPIRIT_OBJGROUP);
        }
        if (obj->anim.alpha != 0)
        {
            obj->anim.alpha--;
        }
    }
    else
    {
        fn_80098B18(obj, lbl_803DBE78, 5, 0, 0, NULL);
        state->active = active = (u8)(mainGetBit(def->gateGameBit) == 0);
        if (active == 0)
        {
            ObjGroup_RemoveObject((int)obj, SPIRITDOORSPIRIT_OBJGROUP);
        }
        if (obj->anim.alpha < 0xff)
        {
            obj->anim.alpha++;
        }
    }
}

void spiritdoorspirit_init(GameObject* obj)
{
    SpiritDoorSpiritState* state = obj->extra;
    state->active = 0;
    obj->anim.alpha = 0;
}


void spiritdoorspirit_release(void)
{
}

void spiritdoorspirit_initialise(void)
{
}

ObjectDescriptor gSpiritDoorSpiritObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)spiritdoorspirit_initialise,
    (ObjectDescriptorCallback)spiritdoorspirit_release,
    0,
    (ObjectDescriptorCallback)spiritdoorspirit_init,
    (ObjectDescriptorCallback)spiritdoorspirit_update,
    (ObjectDescriptorCallback)spiritdoorspirit_hitDetect,
    (ObjectDescriptorCallback)spiritdoorspirit_render,
    (ObjectDescriptorCallback)spiritdoorspirit_free,
    (ObjectDescriptorCallback)spiritdoorspirit_getObjectTypeId,
    spiritdoorspirit_getExtraSize,
};
