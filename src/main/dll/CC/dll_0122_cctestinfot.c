/*
 * cctestinfot - Cape Claw (mapId 47) "test info" help-prompt object (DLL 0x0122;
 * descriptor gCCTestInfotObjDescriptor is declared extern in CFtoggleswitch.h). The
 * object only reacts while the player is disguised: it caches the disguise
 * state, drives the model's hint-text index / active model from it, and -
 * once its ObjTrigger fires - shows help text from the model's helpTextIds
 * table for a hold time bounded by lbl_803E3C88 / lbl_803E3C8C.
 */
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/object_descriptor.h"
#include "main/frame_timing.h"
#include "main/dll/CC/dll_0122_cctestinfot.h"
#include "main/dll/dll_010E_deathseq.h"
#include "main/dll/DR/dll_0128_kttorch.h"

#define CCTESTINFOT_OBJFLAG_HIDDEN             0x4000
#define CCTESTINFOT_OBJFLAG_HITDETECT_DISABLED 0x2000

extern f32 lbl_803E3C88; /* hold-time reset value when the trigger fires */
extern f32 lbl_803E3C8C; /* hold-time ceiling / minimum to keep showing text */

extern void dll_127_getExtraSize_ret_0(void);
extern void CFCrate_getExtraSize(void);
extern void FxEmit_getExtraSize(void);

extern void dll_127_getObjectTypeId(void);
extern void CFCrate_getObjectTypeId(void);
extern void FxEmit_getObjectTypeId(void);

extern void dll_127_free_nop(void);
extern void CFCrate_free(void);
extern void FxEmit_free(void);

extern void dll_127_render(void);
extern void CampFire_getExtraSize(void);
extern void CFCrate_render(void);
extern void FxEmit_render(void);

extern void FuelCell_getExtraSize(void);
extern void dll_127_hitDetect_nop(void);
extern void CampFire_getObjectTypeId(void);
extern void CFCrate_hitDetect(void);
extern void FxEmit_hitDetect(void);

extern void DeathGas_getExtraSize(void);
extern void FuelCell_free(void);
extern void dll_127_update(void);
extern void CampFire_free(struct GameObject *);
extern void CFCrate_update(void);
extern void FxEmit_update(void);

extern void DeathGas_free(void);
extern void FuelCell_render(void);
extern void dll_127_init(void);
extern void CampFire_render(void);
extern void CFCrate_init(void);
extern void FxEmit_init(void);

extern void DeathGas_update(void);
extern void FuelCell_update(void);
extern void dll_127_release_nop(void);
extern void CampFire_update(void);
extern void CFCrate_release(void);
extern void FxEmit_release(void);

extern void DeathGas_init(void);
extern void FuelCell_init(void);
extern void dll_127_initialise_nop(void);
extern void CampFire_init(void);
extern void CFCrate_initialise(void);
extern void FxEmit_initialise(void);
extern int ObjTrigger_IsSet();
extern int playerIsDisguised(void);
extern void Obj_SetActiveModelIndex(int* obj, int idx);

int CCTestInfot_getExtraSize(void)
{
    return sizeof(CctestinfotState);
}

void CCTestInfot_update(int* obj)
{
    CctestinfotState* state = ((GameObject*)obj)->extra;
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
    if (ObjTrigger_IsSet((int)obj) != 0 && isAreaNameTextActive() == 0)
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

void CCTestInfot_init(struct GameObject *obj, s8* def)
{
    u32 flags;
    flags =
        (u32)(obj)->objectFlags | (CCTESTINFOT_OBJFLAG_HIDDEN | CCTESTINFOT_OBJFLAG_HITDETECT_DISABLED);
    (obj)->objectFlags = flags;
    (obj)->anim.rotX = (s16)((s32)(u8)def[0x1A] << 8);
    (obj)->anim.rotY = (s16)((s32)(u8)def[0x19] << 8);
    (obj)->anim.rotZ = (s16)((s32)(u8)def[0x18] << 8);
}

ObjectDescriptor gCCTestInfotObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)CCTestInfot_init,
    (ObjectDescriptorCallback)CCTestInfot_update,
    0,
    0,
    0,
    0,
    CCTestInfot_getExtraSize,
};

/* descriptor/ptr table auto 0x80321db0-0x80321f70 */
u32 gDeathGasObjDescriptor[14] = {0x00000000,           0x00000000,
                                  0x00000000,           0x00090000,
                                  0x00000000,           0x00000000,
                                  0x00000000,           (u32)DeathGas_init,
                                  (u32)DeathGas_update, 0x00000000,
                                  0x00000000,           (u32)DeathGas_free,
                                  0x00000000,           (u32)DeathGas_getExtraSize};
u32 gFuelCellObjDescriptor[14] = {0x00000000,           0x00000000,
                                  0x00000000,           0x00090000,
                                  0x00000000,           0x00000000,
                                  0x00000000,           (u32)FuelCell_init,
                                  (u32)FuelCell_update, 0x00000000,
                                  (u32)FuelCell_render, (u32)FuelCell_free,
                                  0x00000000,           (u32)FuelCell_getExtraSize};
u32 gDeathSeqObjDescriptor[14] = {0x00000000,
                                  0x00000000,
                                  0x00000000,
                                  0x00090000,
                                  (u32)DeathSeq_initialise,
                                  (u32)DeathSeq_release,
                                  0x00000000,
                                  (u32)DeathSeq_init,
                                  (u32)DeathSeq_update,
                                  (u32)DeathSeq_hitDetect,
                                  (u32)DeathSeq_render,
                                  (u32)DeathSeq_free,
                                  (u32)DeathSeq_getObjectTypeId,
                                  (u32)DeathSeq_getExtraSize};
u32 lbl_80321E58[14] = {0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00090000,
                        (u32)dll_127_initialise_nop,
                        (u32)dll_127_release_nop,
                        0x00000000,
                        (u32)dll_127_init,
                        (u32)dll_127_update,
                        (u32)dll_127_hitDetect_nop,
                        (u32)dll_127_render,
                        (u32)dll_127_free_nop,
                        (u32)dll_127_getObjectTypeId,
                        (u32)dll_127_getExtraSize_ret_0};
u32 gCampFireObjDescriptor[14] = {0x00000000,
                                  0x00000000,
                                  0x00000000,
                                  0x00090000,
                                  0x00000000,
                                  0x00000000,
                                  0x00000000,
                                  (u32)CampFire_init,
                                  (u32)CampFire_update,
                                  0x00000000,
                                  (u32)CampFire_render,
                                  (u32)CampFire_free,
                                  (u32)CampFire_getObjectTypeId,
                                  (u32)CampFire_getExtraSize};
u32 gKT_TorchObjDescriptor[14] = {0x00000000,
                                  0x00000000,
                                  0x00000000,
                                  0x00090000,
                                  (u32)KT_Torch_initialise,
                                  (u32)KT_Torch_release,
                                  0x00000000,
                                  (u32)KT_Torch_init,
                                  (u32)KT_Torch_update,
                                  (u32)KT_Torch_hitDetect,
                                  (u32)KT_Torch_render,
                                  (u32)KT_Torch_free,
                                  (u32)KT_Torch_getObjectTypeId,
                                  (u32)KT_Torch_getExtraSize};
u32 gCFCrateObjDescriptor[14] = {0x00000000,
                                 0x00000000,
                                 0x00000000,
                                 0x00090000,
                                 (u32)CFCrate_initialise,
                                 (u32)CFCrate_release,
                                 0x00000000,
                                 (u32)CFCrate_init,
                                 (u32)CFCrate_update,
                                 (u32)CFCrate_hitDetect,
                                 (u32)CFCrate_render,
                                 (u32)CFCrate_free,
                                 (u32)CFCrate_getObjectTypeId,
                                 (u32)CFCrate_getExtraSize};
u32 gFXEmitObjDescriptor[14] = {0x00000000,
                                0x00000000,
                                0x00000000,
                                0x00090000,
                                (u32)FxEmit_initialise,
                                (u32)FxEmit_release,
                                0x00000000,
                                (u32)FxEmit_init,
                                (u32)FxEmit_update,
                                (u32)FxEmit_hitDetect,
                                (u32)FxEmit_render,
                                (u32)FxEmit_free,
                                (u32)FxEmit_getObjectTypeId,
                                (u32)FxEmit_getExtraSize};
