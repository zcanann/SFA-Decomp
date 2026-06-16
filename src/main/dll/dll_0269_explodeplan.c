#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

typedef struct CagecontrolPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
} CagecontrolPlacement;


void explodeplan_free(void)
{
}

int explodeplan_getExtraSize(void) { return 0x4; }

int explodeplan_getObjectTypeId(void) { return 0x0; }

void explodeplan_hitDetect(void)
{
}

void explodeplan_initialise(void)
{
}

void explodeplan_release(void)
{
}

void explodeplan_render(void* obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E69D0);
    }
}

void explodeplan_init(int obj, char* arg)
{
    ObjHits_EnableObject(obj);
    if (GameBit_Get(*(s16*)(arg + 0x1e)) != 0)
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject(obj);
    }
    ((GameObject*)obj)->anim.rotX = (s16)((s8)arg[0x18] << 8);
}

void explodeplan_update(int obj)
{
    int p = *(int*)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(((CagecontrolPlacement*)p)->unk1E) != 0)
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject(obj);
    }
    else
    {
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ObjHits_EnableObject(obj);
    }
}
