#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"

typedef struct KtfallingrocksPlacement
{
    u8 pad0[0x20 - 0x0];
    u16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} KtfallingrocksPlacement;

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
    int q = *(int*)&((GameObject*)obj)->anim.placementData;
    ObjPosParams params;
    char* player;
    int i;
    if (GameBit_Get(((KtfallingrocksPlacement*)q)->unk24) == 0)
    {
        return;
    }
    player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }
    ((GameObject*)obj)->anim.localPosX = *(f32*)(player + 0xc);
    ((GameObject*)obj)->anim.localPosZ = *(f32*)(player + 0x14);
    for (i = 0; i < 10; i++)
    {
        params.x = ((GameObject*)obj)->anim.localPosX + (f32)(int)
        randomGetRange(-200, 200);
        params.y = ((GameObject*)obj)->anim.localPosY;
        params.z = ((GameObject*)obj)->anim.localPosZ + (f32)(int)
        randomGetRange(-200, 200);
        (*gPartfxInterface)->spawnObject(
            (void*)obj, ((KtfallingrocksPlacement*)q)->unk20, &params, 0x200001, -1, NULL);
    }
    Sfx_PlayFromObject(obj, SFXbaddie_haga_spin);
    GameBit_Set(((KtfallingrocksPlacement*)q)->unk24, 0);
}
