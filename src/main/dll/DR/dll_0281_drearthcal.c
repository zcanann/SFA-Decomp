#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#define DREARTHCAL_SETUP_YAW 0x18
#define DREARTHCAL_OBJECT_FLAGS_B0 0xb0
#define DREARTHCAL_INIT_FLAGS 0x6000

int drearthcal_setScale(void) { return 1; }

int drearthcal_getExtraSize(void) { return 1; }

int drearthcal_getObjectTypeId(void) { return 0; }

void drearthcal_free(void)
{
}

void drearthcal_render(void)
{
}

void drearthcal_hitDetect(void)
{
}

#pragma scheduling off
#pragma peephole off
void drearthcal_update(int obj)
{
    int player;
    int i;
    struct
    {
        f32 _pad[3];
        f32 vec[3];
    } part;
    f32 searchDist;

    player = Obj_GetPlayerObject();
    searchDist = lbl_803E6C08;
    if (fn_802972A8() != NULL)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x18;
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
        {
            setAButtonIcon(0x15);
        }
        if (ObjTrigger_IsSet(obj) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        if (0 < *(s8*)(*(int*)(obj + 0x58) + 0x10f))
        for (i = 0; i < *(s8*)(*(int*)(obj + 0x58) + 0x10f); i++)
        {
            {
                int elem = ((int*)*(int*)(obj + 0x58))[i + 0x40];
                if ((u32)elem == player)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                }
            }
        }
        if ((u32)ObjGroup_FindNearestObject(0xa, obj, &searchDist) == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
        {
            setAButtonIcon(0x14);
        }
        if (ObjTrigger_IsSet(obj) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
        }
    }
    if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
    {
        part.vec[0] = lbl_803E6C0C;
        part.vec[1] = lbl_803E6C10;
        part.vec[2] = lbl_803E6C0C;
        objfx_spawnArcedBurst(obj, 5, lbl_803E6C14, 2, 2, 0xf, lbl_803E6C18, *(f32*)&lbl_803E6C18,
                              lbl_803E6C1C, &part, 0);
    }
}

void drearthcal_init(int obj, int setup)
{
    ((GameObject*)obj)->anim.rotX = (s16)((s8) * (u8*)(setup + DREARTHCAL_SETUP_YAW) << 8);
    *(u16*)(obj + DREARTHCAL_OBJECT_FLAGS_B0) |= DREARTHCAL_INIT_FLAGS;
}
#pragma scheduling on
#pragma peephole on

void drearthcal_release(void)
{
}

void drearthcal_initialise(void)
{
}
