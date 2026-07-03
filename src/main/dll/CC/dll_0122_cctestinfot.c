/*
 * cctestinfot - Crystal Caves "test info" help-prompt object (DLL 0x0122;
 * descriptor gCCTestInfotObjDescriptor lives in CFtoggleswitch.h). The
 * object only reacts while the player is disguised: it caches the disguise
 * state, drives the model's hint-text index / active model from it, and -
 * once its ObjTrigger fires - shows help text from the model's helpTextIds
 * table for a hold time bounded by lbl_803E3C88 / lbl_803E3C8C.
 */
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
extern int ObjTrigger_IsSet();
extern int playerIsDisguised(void);
extern void Obj_SetActiveModelIndex(int *obj, int idx);
extern f32 timeDelta;
extern f32 lbl_803E3C88; /* hold-time reset value when the trigger fires */
extern f32 lbl_803E3C8C; /* hold-time ceiling / minimum to keep showing text */

#define CCTESTINFOT_OBJFLAG_HIDDEN 0x4000
#define CCTESTINFOT_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct CctestinfotState
{
    f32 holdTimer;  /* 0x00: counts down while help text is shown */
    u8 disguised;   /* 0x04: cached playerIsDisguised() result, hint-text index */
    u8 pad05[3];
} CctestinfotState;

STATIC_ASSERT(offsetof(CctestinfotState, disguised) == 0x4);
STATIC_ASSERT(sizeof(CctestinfotState) == 0x8);

int cctestinfot_getExtraSize(void) { return sizeof(CctestinfotState); }

void cctestinfot_init(int obj, s8 *def)
{
    u32 v;
    v = (u32)((GameObject*)obj)->objectFlags | (CCTESTINFOT_OBJFLAG_HIDDEN | CCTESTINFOT_OBJFLAG_HITDETECT_DISABLED);
    ((GameObject*)obj)->objectFlags = v;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)(u8)def[0x1A] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32)(u8)def[0x19] << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)((s32)(u8)def[0x18] << 8);
}

void cctestinfot_update(int *obj)
{
    CctestinfotState *state = ((GameObject*)obj)->extra;
    Obj_GetPlayerObject();
    if (state->disguised != 0)
    {
        if (playerIsDisguised() == 0)
        {
            state->disguised = 0;
        }
    }
    else
    {
        if (playerIsDisguised() != 0)
        {
            state->disguised = 1;
        }
    }
    objSetHintTextIdx((int)obj, state->disguised);
    Obj_SetActiveModelIndex(obj, state->disguised);
    if (ObjTrigger_IsSet((int)obj) != 0 && fn_801334E0() == 0)
    {
        state->holdTimer = lbl_803E3C88;
    }
    if (state->holdTimer > lbl_803E3C8C)
    {
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) == 0)
        {
            state->holdTimer = lbl_803E3C8C;
        }
        else
        {
            state->holdTimer = state->holdTimer - timeDelta;
            showHelpText(((GameObject*)obj)->anim.modelInstance->helpTextIds[state->disguised]);
        }
    }
}
