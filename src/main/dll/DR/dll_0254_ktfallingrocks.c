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

typedef struct KtfallingrocksPlacement
{
    u8 pad0[0x20 - 0x0];
    u16 effectId;        /* 0x20: particle effect id spawned per rock */
    u8 pad22[0x24 - 0x22];
    s16 triggerBit;      /* 0x24: game bit; fires the burst then is cleared */
    u8 pad26[0x28 - 0x26];
} KtfallingrocksPlacement;

STATIC_ASSERT(offsetof(KtfallingrocksPlacement, effectId) == 0x20);
STATIC_ASSERT(offsetof(KtfallingrocksPlacement, triggerBit) == 0x24);
STATIC_ASSERT(sizeof(KtfallingrocksPlacement) == 0x28);

int ktfallingrocks_getExtraSize(void) { return 0x0; }

int ktfallingrocks_getObjectTypeId(void) { return 0x0; }

void ktfallingrocks_hitDetect(void)
{
}

void ktfallingrocks_initialise(void)
{
}

void ktfallingrocks_release(void)
{
}

void ktfallingrocks_init(int obj)
{
    ((GameObject*)obj)->animEventCallback = NULL;
}

void ktfallingrocks_free(u8* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void ktfallingrocks_render(void* obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible)
{
    if (visible != 0)
    {
        return;
    }
}

void ktfallingrocks_update(int obj)
{
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    ObjPosParams params;
    char* player;
    int i;
    if (GameBit_Get(((KtfallingrocksPlacement*)placement)->triggerBit) == 0)
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
        (*gPartfxInterface)->spawnObject(
            (void*)obj, ((KtfallingrocksPlacement*)placement)->effectId, &params, 0x200001, -1, NULL);
    }
    Sfx_PlayFromObject(obj, SFXbaddie_haga_spin);
    GameBit_Set(((KtfallingrocksPlacement*)placement)->triggerBit, 0);
}
