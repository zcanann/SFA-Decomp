/*
 * ktfallingrocks (DLL 0x254) - a one-shot rockfall trigger that rains
 * particle effects down around the player.
 *
 * Each update tick it watches a placement game bit; when the bit is set
 * it snaps to the player's XZ position, spawns ten rock particle effects
 * scattered within +/-200 units, plays the rockfall sfx, then clears the
 * bit so the burst only fires once per trigger.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/expgfx_interface.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/vecmath.h"

#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/DR/dll_0254_ktfallingrocks.h"

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
    int placement = *(int*)&(obj)->anim.placementData;
    MatrixTransform params;
    GameObject* player;
    int i;
    if (mainGetBit(((KtfallingrocksPlacement*)placement)->triggerBit) == 0)
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
        params.x = (obj)->anim.localPosX + (f32)(int)randomGetRange(-200, 200);
        params.y = (obj)->anim.localPosY;
        params.z = (obj)->anim.localPosZ + (f32)(int)randomGetRange(-200, 200);
        (*gPartfxInterface)
            ->spawnObject((void*)obj, ((KtfallingrocksPlacement*)placement)->effectId, &params, 0x200001, -1, NULL);
    }
    Sfx_PlayFromObject((int)obj, SFXTRIG_en_birdynight11);
    mainSetBits(((KtfallingrocksPlacement*)placement)->triggerBit, 0);
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
