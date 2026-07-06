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
#include "main/object_descriptor.h"

extern void deathseq_getExtraSize(void);
extern void dll_127_getExtraSize_ret_0(void);
extern void kt_torch_getExtraSize(void);
extern void cfccrate_getExtraSize(void);
extern void fxemit_getExtraSize(void);

extern void deathseq_getObjectTypeId(void);
extern void dll_127_getObjectTypeId(void);
extern void kt_torch_getObjectTypeId(void);
extern void cfccrate_getObjectTypeId(void);
extern void fxemit_getObjectTypeId(void);

extern void deathseq_free(void);
extern void dll_127_free_nop(void);
extern void kt_torch_free(void);
extern void cfccrate_free(void);
extern void fxemit_free(void);

extern void deathseq_render(void);
extern void dll_127_render(void);
extern void campfire_getExtraSize(void);
extern void kt_torch_render(void);
extern void cfccrate_render(void);
extern void fxemit_render(void);

extern void fuelcell_getExtraSize(void);
extern void deathseq_hitDetect(void);
extern void dll_127_hitDetect_nop(void);
extern void campfire_getObjectTypeId(void);
extern void kt_torch_hitDetect(void);
extern void cfccrate_hitDetect(void);
extern void fxemit_hitDetect(void);

extern void deathgas_getExtraSize(void);
extern void fuelcell_free(void);
extern void deathseq_update(void);
extern void dll_127_update(void);
extern void campfire_free(void);
extern void kt_torch_update(void);
extern void cfccrate_update(void);
extern void fxemit_update(void);

extern void deathgas_free(void);
extern void fuelcell_render(void);
extern void deathseq_init(void);
extern void dll_127_init(void);
extern void campfire_render(void);
extern void kt_torch_init(void);
extern void cfccrate_init(void);
extern void fxemit_init(void);

extern void deathgas_update(void);
extern void fuelcell_update(void);
extern void deathseq_release(void);
extern void dll_127_release_nop(void);
extern void campfire_update(void);
extern void kt_torch_release(void);
extern void cfccrate_release(void);
extern void fxemit_release(void);

extern void deathgas_init(void);
extern void fuelcell_init(void);
extern void deathseq_initialise(void);
extern void dll_127_initialise_nop(void);
extern void campfire_init(void);
extern void kt_torch_initialise(void);
extern void cfccrate_initialise(void);
extern void fxemit_initialise(void);
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
    u32 flags;
    flags = (u32)((GameObject*)obj)->objectFlags | (CCTESTINFOT_OBJFLAG_HIDDEN | CCTESTINFOT_OBJFLAG_HITDETECT_DISABLED);
    ((GameObject*)obj)->objectFlags = flags;
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

ObjectDescriptor gCCTestInfotObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)cctestinfot_init,
    (ObjectDescriptorCallback)cctestinfot_update,
    0,
    0,
    0,
    0,
    cctestinfot_getExtraSize,
};

/* descriptor/ptr table auto 0x80321db0-0x80321f70 */
u32 gDeathGasObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)deathgas_init, (u32)deathgas_update, 0x00000000, 0x00000000, (u32)deathgas_free, 0x00000000, (u32)deathgas_getExtraSize };
u32 gFuelCellObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)fuelcell_init, (u32)fuelcell_update, 0x00000000, (u32)fuelcell_render, (u32)fuelcell_free, 0x00000000, (u32)fuelcell_getExtraSize };
u32 gDeathSeqObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)deathseq_initialise, (u32)deathseq_release, 0x00000000, (u32)deathseq_init, (u32)deathseq_update, (u32)deathseq_hitDetect, (u32)deathseq_render, (u32)deathseq_free, (u32)deathseq_getObjectTypeId, (u32)deathseq_getExtraSize };
u32 lbl_80321E58[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)dll_127_initialise_nop, (u32)dll_127_release_nop, 0x00000000, (u32)dll_127_init, (u32)dll_127_update, (u32)dll_127_hitDetect_nop, (u32)dll_127_render, (u32)dll_127_free_nop, (u32)dll_127_getObjectTypeId, (u32)dll_127_getExtraSize_ret_0 };
u32 gCampFireObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)campfire_init, (u32)campfire_update, 0x00000000, (u32)campfire_render, (u32)campfire_free, (u32)campfire_getObjectTypeId, (u32)campfire_getExtraSize };
u32 gKT_TorchObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)kt_torch_initialise, (u32)kt_torch_release, 0x00000000, (u32)kt_torch_init, (u32)kt_torch_update, (u32)kt_torch_hitDetect, (u32)kt_torch_render, (u32)kt_torch_free, (u32)kt_torch_getObjectTypeId, (u32)kt_torch_getExtraSize };
u32 gCFCrateObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)cfccrate_initialise, (u32)cfccrate_release, 0x00000000, (u32)cfccrate_init, (u32)cfccrate_update, (u32)cfccrate_hitDetect, (u32)cfccrate_render, (u32)cfccrate_free, (u32)cfccrate_getObjectTypeId, (u32)cfccrate_getExtraSize };
u32 gFXEmitObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)fxemit_initialise, (u32)fxemit_release, 0x00000000, (u32)fxemit_init, (u32)fxemit_update, (u32)fxemit_hitDetect, (u32)fxemit_render, (u32)fxemit_free, (u32)fxemit_getObjectTypeId, (u32)fxemit_getExtraSize };
