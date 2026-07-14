/* DLL 0x0121 — infotext. TU: 0x8018B9F0–0x8018BB00. */
#include "main/game_object.h"
#include "main/frame_timing.h"
#include "main/object_api.h"
#include "main/objprint_render_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/minimap_api.h"
#include "main/object_descriptor.h"

#define INFOTEXT_OBJFLAG_HIDDEN 0x4000
#define INFOTEXT_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct InfoTextPlacement
{
    u8 pad00[0x18];
    u8 rotByte;     /* 0x18 */
    u8 hintTextIdx; /* 0x19 */
} InfoTextPlacement;

int infotext_getExtraSize(void) { return 0x4; }

void infotext_update(int obj)
{
    f32* sub;
    GameObject* objReg = (GameObject*)obj;
    sub = objReg->extra;
    if (ObjTrigger_IsSet(obj) != 0 && isAreaNameTextActive() == 0)
    {
        *sub = 600.0f;
    }
    if (*sub > 0.0f)
    {
        if ((*(u8*)&(objReg)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) == 0)
        {
            *sub = 0.0f;
        }
        else
        {
            *sub = *sub - timeDelta;
            showHelpText((objReg)->anim.modelInstance->helpTextIds[(*(u8**)&(objReg)->anim.placementData)[0x19]]);
        }
    }
    if ((((ObjAnimComponent*)objReg)->modelInstance->flags & 1) != 0)
    {
        objRenderFn_80041018((GameObject*)objReg);
    }
}

void infotext_init(GameObject *obj, s8* def)
{
    u32 flags;
    InfoTextPlacement* p = (InfoTextPlacement*)def;
    flags = (u32)(obj)->objectFlags | (INFOTEXT_OBJFLAG_HIDDEN | INFOTEXT_OBJFLAG_HITDETECT_DISABLED);
    (obj)->objectFlags = flags;
    (obj)->anim.rotX = (s16)((s32)(u8)p->rotByte << 8);
    objSetHintTextIdx(obj, (u8)p->hintTextIdx);
}

ObjectDescriptor gInfoTextObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)infotext_init,
    (ObjectDescriptorCallback)infotext_update,
    0,
    0,
    0,
    0,
    infotext_getExtraSize,
};
