/* DLL 0x0121 — infotext. TU: 0x8018B9F0–0x8018BB00. */
#include "main/game_object.h"
#include "main/dll/DR/dll_80209FE0_shared.h"
extern void objRenderFn_80041018(int obj);

#define INFOTEXT_OBJFLAG_HIDDEN 0x4000
#define INFOTEXT_OBJFLAG_HITDETECT_DISABLED 0x2000

int infotext_getExtraSize(void) { return 0x4; }

void infotext_update(GameObject *obj)
{
    f32* sub = (obj)->extra;
    if (ObjTrigger_IsSet(obj) != 0 && isAreaNameTextActive() == 0)
    {
        *sub = 600.0f;
    }
    if (*sub > 0.0f)
    {
        if ((*(u8*)&(obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) == 0)
        {
            *sub = 0.0f;
        }
        else
        {
            *sub = *sub - timeDelta;
            showHelpText((obj)->anim.modelInstance->helpTextIds[(*(u8**)&(obj)->anim.placementData)[0x19]]);
        }
    }
    if ((((ObjAnimComponent*)obj)->modelInstance->flags & 1) != 0)
    {
        objRenderFn_80041018((int)obj);
    }
}

void infotext_init(GameObject *obj, s8* def)
{
    u32 flags;
    flags = (u32)(obj)->objectFlags | (INFOTEXT_OBJFLAG_HIDDEN | INFOTEXT_OBJFLAG_HITDETECT_DISABLED);
    (obj)->objectFlags = flags;
    (obj)->anim.rotX = (s16)((s32)(u8)def[0x18] << 8);
    objSetHintTextIdx(obj, (u8)def[0x19]);
}
