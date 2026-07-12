#include "main/dll/dll_80220608_shared.h"
#include "main/dll/DR/dll_0281_drearthcal.h"
#include "main/game_object.h"
#include "main/objfx.h"

#define DREARTHCAL_OBJFLAG_RENDERED 0x800

#define DREARTHCAL_INIT_FLAGS 0x6000

/* Mount object group: query nearest mount to gate the interact prompt. */
#define DREARTHCAL_MOUNT_OBJGROUP 0xa

int drearthcal_setScale(void)
{
    return 1;
}

int drearthcal_getExtraSize(void)
{
    return 1;
}

int drearthcal_getObjectTypeId(void)
{
    return 0;
}

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
void drearthcal_update(GameObject* obj)
{
    GameObject* player;
    int i;
    struct
    {
        f32 _pad[3];
        f32 vec[3];
    } part;
    f32 searchDist;

    player = Obj_GetPlayerObject();
    searchDist = lbl_803E6C08;
    if (playerGetFocusObject() != NULL)
    {
        obj->anim.resetHitboxFlags &= ~(INTERACT_FLAG_PROMPT_SUPPRESSED | INTERACT_FLAG_DISABLED);
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
        {
            setAButtonIcon(0x15);
        }
        if (ObjTrigger_IsSet((int)obj) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        }
    }
    else
    {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        if (0 < *(s8*)(*(int*)((int)obj + 0x58) + 0x10f))
            for (i = 0; i < *(s8*)(*(int*)((int)obj + 0x58) + 0x10f); i++)
            {
                {
                    int elem = ((int*)*(int*)((int)obj + 0x58))[i + 0x40];
                    if ((GameObject*)elem == player)
                    {
                        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                    }
                }
            }
        if ((u32)ObjGroup_FindNearestObject(DREARTHCAL_MOUNT_OBJGROUP, (int)obj, &searchDist) == 0)
        {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        else
        {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
        {
            setAButtonIcon(0x14);
        }
        if (ObjTrigger_IsSet((int)obj) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
        }
    }
    if ((obj->objectFlags & DREARTHCAL_OBJFLAG_RENDERED) != 0)
    {
        part.vec[0] = lbl_803E6C0C;
        part.vec[1] = lbl_803E6C10;
        part.vec[2] = lbl_803E6C0C;
        objfx_spawnArcedBurstLegacy((int)obj, 5, lbl_803E6C14, 2, 2, 0xf, lbl_803E6C18, *(f32*)&lbl_803E6C18,
                                   lbl_803E6C1C, &part,
                              0);
    }
}

void drearthcal_init(GameObject* obj, DREarthCalSetup* setup)
{
    obj->anim.rotX = (s16)(setup->yaw << 8);
    obj->objectFlags |= DREARTHCAL_INIT_FLAGS;
}
#pragma scheduling on
#pragma peephole on

void drearthcal_release(void)
{
}

void drearthcal_initialise(void)
{
}
