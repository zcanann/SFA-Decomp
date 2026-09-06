/*
 * KT_Fallingr (DLL 0x254) - a one-shot rockfall trigger that rains
 * particle effects down around the player.
 *
 * Each update tick it watches a placement game bit; when the bit is set
 * it snaps to the player's XZ position, spawns ten rock particle effects
 * scattered within +/-200 units, plays the rockfall sfx, then clears the
 * bit so the burst only fires once per trigger.
 */
#include "main/dll/DR/dll_0254_ktfallingrocks.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/expgfx_interface.h"
#include "main/gamebits.h"
#include "sys/objects.h"
#include "main/vecmath.h"

#include "main/audio/sfx_trigger_ids.h"

int ktfallingrocks_getExtraSize(void)
{
    return 0x0;
}

int ktfallingrocks_getObjectTypeId(void)
{
    return 0x0;
}

void ktfallingrocks_free(u8* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void ktfallingrocks_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    if (visible != 0)
    {
        return;
    }
}

void ktfallingrocks_hitDetect(void)
{
}

void ktfallingrocks_update(GameObject* obj)
{
    KtfallingrocksPlacement* placement = (KtfallingrocksPlacement*)obj->anim.placementData;
    MatrixTransform params;
    GameObject* player;
    int i;
    if (mainGetBit(placement->triggerBit) == 0)
    {
        return;
    }
    player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }
    obj->anim.localPosX = player->anim.localPosX;
    obj->anim.localPosZ = player->anim.localPosZ;
    for (i = 0; i < 10; i++)
    {
        params.x = obj->anim.localPosX + randomGetRange(-200, 200);
        params.y = obj->anim.localPosY;
        params.z = obj->anim.localPosZ + randomGetRange(-200, 200);
        (*gPartfxInterface)
            ->spawnObject((void*)obj, placement->effectId, &params, 0x200001, -1, NULL);
    }
    Sfx_PlayFromObject(obj, SFXTRIG_en_birdynight11);
    mainSetBits(placement->triggerBit, 0);
}

void ktfallingrocks_init(GameObject* obj)
{
    obj->animEventCallback = NULL;
}

void ktfallingrocks_release(void)
{
}

void ktfallingrocks_initialise(void)
{
}

ObjectDescriptor gKtFallingrocksObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)ktfallingrocks_initialise,
    (ObjectDescriptorCallback)ktfallingrocks_release,
    0,
    (ObjectDescriptorCallback)ktfallingrocks_init,
    (ObjectDescriptorCallback)ktfallingrocks_update,
    (ObjectDescriptorCallback)ktfallingrocks_hitDetect,
    (ObjectDescriptorCallback)ktfallingrocks_render,
    (ObjectDescriptorCallback)ktfallingrocks_free,
    (ObjectDescriptorCallback)ktfallingrocks_getObjectTypeId,
    ktfallingrocks_getExtraSize,
};
