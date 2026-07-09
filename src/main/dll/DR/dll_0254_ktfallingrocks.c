/*
 * ktfallingrocks (DLL 0x254) - a one-shot rockfall trigger that rains
 * particle effects down around the player.
 *
 * Each update tick it watches a placement game bit; when the bit is set
 * it snaps to the player's XZ position, spawns ten rock particle effects
 * scattered within +/-200 units, plays the rockfall sfx, then clears the
 * bit so the burst only fires once per trigger.
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

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

void ktfallingrocks_update(int obj)
{
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    ObjPosParams params;
    char* player;
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
    ((GameObject*)obj)->anim.localPosX = ((GameObject*)player)->anim.localPosX;
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)player)->anim.localPosZ;
    for (i = 0; i < 10; i++)
    {
        params.x = ((GameObject*)obj)->anim.localPosX + (f32)(int)randomGetRange(-200, 200);
        params.y = ((GameObject*)obj)->anim.localPosY;
        params.z = ((GameObject*)obj)->anim.localPosZ + (f32)(int)randomGetRange(-200, 200);
        (*gPartfxInterface)
            ->spawnObject((void*)obj, ((KtfallingrocksPlacement*)placement)->effectId, &params, 0x200001, -1, NULL);
    }
    Sfx_PlayFromObject(obj, SFXTRIG_en_birdynight11);
    mainSetBits(((KtfallingrocksPlacement*)placement)->triggerBit, 0);
}

void ktfallingrocks_init(struct GameObject* obj)
{
    (obj)->animEventCallback = NULL;
}

void ktfallingrocks_release(void)
{
}

void ktfallingrocks_initialise(void)
{
}
