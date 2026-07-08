/*
 * dimbossgut (DLL 0x1E1) - the DIM boss gut cavity object (interior mesh).
 * Advances the gut's idle animation each frame and renders it.
 * The animEventCallback is wired to DIM_BossGut_SeqFn to clear the
 * hit-volume pair and suppress sequence events.
 */
#include "main/dll/DIM/dll_01E1_dimbossgut.h"
#include "main/game_object.h"
#include "main/frame_timing.h"

extern f32 lbl_803E4C80;
extern f32 lbl_803E4C84;
extern f32 lbl_803E4C88;

extern void objSetSlot(u8* obj, s8 slot);
extern void objRenderModelAndHitVolumes(int obj, u32 p2, u32 p3, u32 p4, u32 p5, double scale);
extern void DIMbossspit_free(void);
extern void DIMbossspit_getExtraSize(void);
extern void DIMbossspit_getObjectTypeId(void);
extern void DIMbossspit_hitDetect(void);
extern void DIMbossspit_init(void);
extern void DIMbossspit_initialise(void);
extern void DIMbossspit_release(void);
extern void DIMbossspit_render(void);
extern void DIMbossspit_update(void);
extern void DIMbosstonsil_free(void);
extern void DIMbosstonsil_func0B(void);
extern void DIMbosstonsil_getExtraSize(void);
extern void DIMbosstonsil_getObjectTypeId(void);
extern void DIMbosstonsil_hitDetect(void);
extern void DIMbosstonsil_init(void);
extern void DIMbosstonsil_initialise(void);
extern void DIMbosstonsil_release(void);
extern void DIMbosstonsil_render(void);
extern void DIMbosstonsil_setScale(void);
extern void DIMbosstonsil_update(void);
extern void ccriverflow_free(void);
extern void ccriverflow_getExtraSize(void);
extern void ccriverflow_init(void);
extern void ccriverflow_render(void);
extern void ccriverflow_update(void);
extern void dfropenode_free(void);
extern void dfropenode_getWorldPosAtPhase(void);
extern void dfropenode_findNearestRopePoint(void);
extern void dfropenode_getAngle(void);
extern void dfropenode_setVisible(void);
extern void dfropenode_isVisible(void);
extern void dfropenode_setMinY(void);
extern void dfropenode_clearLinkedObj(void);
extern void dfropenode_getExtraSize(void);
extern void dfropenode_getObjectTypeId(void);
extern void dfropenode_hitDetect(void);
extern void dfropenode_init(void);
extern void dfropenode_initialise(void);
extern void dfropenode_advancePhaseByDistance(void);
extern void dfropenode_release(void);
extern void dfropenode_render(void);
extern void dfropenode_applyForceAtPhase(void);
extern void dfropenode_getPlaneEquation(void);
extern void dfropenode_update(void);
extern void DFSH_Door2Speci_free(void);
extern void DFSH_Door2Speci_getExtraSize(void);
extern void DFSH_Door2Speci_getObjectTypeId(void);
extern void DFSH_Door2Speci_hitDetect(void);
extern void DFSH_Door2Speci_init(void);
extern void DFSH_Door2Speci_initialise(void);
extern void DFSH_Door2Speci_release(void);
extern void DFSH_Door2Speci_render(void);
extern void DFSH_Door2Speci_update(void);
extern void DIMbosscrackpar_free(void);
extern void DIMbosscrackpar_getExtraSize(void);
extern void DIMbosscrackpar_getObjectTypeId(void);
extern void DIMbosscrackpar_hitDetect(void);
extern void DIMbosscrackpar_init(void);
extern void DIMbosscrackpar_initialise(void);
extern void DIMbosscrackpar_release(void);
extern void DIMbosscrackpar_render(void);
extern void DIMbosscrackpar_update(void);
extern void dimbossfire_free(void);
extern void dimbossfire_getExtraSize(void);
extern void dimbossfire_getObjectTypeId(void);
extern void dimbossfire_hitDetect(void);
extern void dimbossfire_init(void);
extern void dimbossfire_initialise(void);
extern void dimbossfire_release(void);
extern void dimbossfire_render(void);
extern void dimbossfire_update(void);
extern void DIM_BossGut2_free(void);
extern void DIM_BossGut2_func0B(void);
extern void DIM_BossGut2_getExtraSize(void);
extern void DIM_BossGut2_getObjectTypeId(void);
extern void DIM_BossGut2_hitDetect(void);
extern void DIM_BossGut2_init(void);
extern void DIM_BossGut2_initialise(void);
extern void DIM_BossGut2_release(void);
extern void DIM_BossGut2_render(void);
extern void DIM_BossGut2_setScale(void);
extern void DIM_BossGut2_update(void);
extern void magicmaker_free(void);
extern void magicmaker_getExtraSize(void);
extern void magicmaker_getObjectTypeId(void);
extern void magicmaker_hitDetect(void);
extern void magicmaker_init(void);
extern void magicmaker_initialise(void);
extern void magicmaker_release(void);
extern void magicmaker_render(void);
extern void magicmaker_update(void);

int DIM_BossGut_SeqFn(int obj, int runtime, ObjAnimUpdateState* animUpdate)
{
    animUpdate->hitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

int DIM_BossGut_getExtraSize(void)
{
    return 0x0;
}
int DIM_BossGut_getObjectTypeId(void)
{
    return 0x0;
}

void DIM_BossGut_free(void)
{
}

void DIM_BossGut_render(int obj, u32 p2, u32 p3, u32 p4, u32 p5, char shouldRender)
{
    int visible;

    visible = shouldRender;
    if (visible != 0)
    {
        ObjAnim_AdvanceCurrentMove(lbl_803E4C80, timeDelta, obj, NULL);
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E4C84);
    }
}

void DIM_BossGut_hitDetect(void)
{
}

void DIM_BossGut_update(void)
{
}

void DIM_BossGut_init(void* obj)
{
    int objArg;

    objSetSlot(obj, 0x5a);
    ((GameObject*)obj)->animEventCallback = DIM_BossGut_SeqFn;
    objArg = (int)obj;
    ObjAnim_SetCurrentMove(objArg, 0, lbl_803E4C88, 0);
    ((ObjAnimAdvanceObjectFirstFn)ObjAnim_AdvanceCurrentMove)(objArg, (double)lbl_803E4C80, (double)timeDelta, NULL);
}

void DIM_BossGut_release(void)
{
}

void DIM_BossGut_initialise(void)
{
}

ObjectDescriptor gDIM_BossGutObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DIM_BossGut_initialise,
    (ObjectDescriptorCallback)DIM_BossGut_release,
    0,
    (ObjectDescriptorCallback)DIM_BossGut_init,
    (ObjectDescriptorCallback)DIM_BossGut_update,
    (ObjectDescriptorCallback)DIM_BossGut_hitDetect,
    (ObjectDescriptorCallback)DIM_BossGut_render,
    (ObjectDescriptorCallback)DIM_BossGut_free,
    (ObjectDescriptorCallback)DIM_BossGut_getObjectTypeId,
    DIM_BossGut_getExtraSize,
};

/* auto 0x80325c30-0x80325f88 */
u32 gDIM_BossTonsilObjDescriptor[16] = {0x00000000,
                                        0x00000000,
                                        0x00000000,
                                        0x000b0000,
                                        (u32)DIMbosstonsil_initialise,
                                        (u32)DIMbosstonsil_release,
                                        0x00000000,
                                        (u32)DIMbosstonsil_init,
                                        (u32)DIMbosstonsil_update,
                                        (u32)DIMbosstonsil_hitDetect,
                                        (u32)DIMbosstonsil_render,
                                        (u32)DIMbosstonsil_free,
                                        (u32)DIMbosstonsil_getObjectTypeId,
                                        (u32)DIMbosstonsil_getExtraSize,
                                        (u32)DIMbosstonsil_setScale,
                                        (u32)DIMbosstonsil_func0B};
u32 gDIM_BossGut2ObjDescriptor[16] = {0x00000000,
                                      0x00000000,
                                      0x00000000,
                                      0x000b0000,
                                      (u32)DIM_BossGut2_initialise,
                                      (u32)DIM_BossGut2_release,
                                      0x00000000,
                                      (u32)DIM_BossGut2_init,
                                      (u32)DIM_BossGut2_update,
                                      (u32)DIM_BossGut2_hitDetect,
                                      (u32)DIM_BossGut2_render,
                                      (u32)DIM_BossGut2_free,
                                      (u32)DIM_BossGut2_getObjectTypeId,
                                      (u32)DIM_BossGut2_getExtraSize,
                                      (u32)DIM_BossGut2_setScale,
                                      (u32)DIM_BossGut2_func0B};
u32 gDIM_BossSpitObjDescriptor[14] = {0x00000000,
                                      0x00000000,
                                      0x00000000,
                                      0x00090000,
                                      (u32)DIMbossspit_initialise,
                                      (u32)DIMbossspit_release,
                                      0x00000000,
                                      (u32)DIMbossspit_init,
                                      (u32)DIMbossspit_update,
                                      (u32)DIMbossspit_hitDetect,
                                      (u32)DIMbossspit_render,
                                      (u32)DIMbossspit_free,
                                      (u32)DIMbossspit_getObjectTypeId,
                                      (u32)DIMbossspit_getExtraSize};
u32 lbl_80325CE8[3] = {0x02c402cd, 0x02ce02cf, 0x000b000b};
u32 gMAGICMakerObjDescriptor[15] = {0x00000000,
                                    0x00000000,
                                    0x00000000,
                                    0x00090000,
                                    (u32)magicmaker_initialise,
                                    (u32)magicmaker_release,
                                    0x00000000,
                                    (u32)magicmaker_init,
                                    (u32)magicmaker_update,
                                    (u32)magicmaker_hitDetect,
                                    (u32)magicmaker_render,
                                    (u32)magicmaker_free,
                                    (u32)magicmaker_getObjectTypeId,
                                    (u32)magicmaker_getExtraSize,
                                    0x00000000};
u32 gDIMbosscrackparObjDescriptor[14] = {0x00000000,
                                         0x00000000,
                                         0x00000000,
                                         0x00090000,
                                         (u32)DIMbosscrackpar_initialise,
                                         (u32)DIMbosscrackpar_release,
                                         0x00000000,
                                         (u32)DIMbosscrackpar_init,
                                         (u32)DIMbosscrackpar_update,
                                         (u32)DIMbosscrackpar_hitDetect,
                                         (u32)DIMbosscrackpar_render,
                                         (u32)DIMbosscrackpar_free,
                                         (u32)DIMbosscrackpar_getObjectTypeId,
                                         (u32)DIMbosscrackpar_getExtraSize};
u32 lbl_80325D68[10] = {0x43200000, 0x41f00000, 0x42dc0000, 0x43200000, 0x42a00000,
                        0x42200000, 0x42f00000, 0x42700000, 0x42f00000, 0x42f00000};
u32 gDIMbossfireObjDescriptor[14] = {0x00000000,
                                     0x00000000,
                                     0x00000000,
                                     0x00090000,
                                     (u32)dimbossfire_initialise,
                                     (u32)dimbossfire_release,
                                     0x00000000,
                                     (u32)dimbossfire_init,
                                     (u32)dimbossfire_update,
                                     (u32)dimbossfire_hitDetect,
                                     (u32)dimbossfire_render,
                                     (u32)dimbossfire_free,
                                     (u32)dimbossfire_getObjectTypeId,
                                     (u32)dimbossfire_getExtraSize};
u32 gCCriverflowObjDescriptor[14] = {0x00000000,
                                     0x00000000,
                                     0x00000000,
                                     0x00090000,
                                     0x00000000,
                                     0x00000000,
                                     0x00000000,
                                     (u32)ccriverflow_init,
                                     (u32)ccriverflow_update,
                                     0x00000000,
                                     (u32)ccriverflow_render,
                                     (u32)ccriverflow_free,
                                     0x00000000,
                                     (u32)ccriverflow_getExtraSize};
u32 lbl_80325E00[24] = {0x00000064, 0x00000000, 0x01000000, 0xffffffff, 0xff38ff9c, 0x00000000, 0x00000000, 0xffffffff,
                        0x00c8ff9c, 0x00000000, 0x02000000, 0xffffffff, 0x00000001, 0x00000000, 0x01000200, 0xffffffff,
                        0xff38ff9c, 0x00000000, 0x00000200, 0xffffffff, 0x00c8ff9c, 0x00000000, 0x02000200, 0xffffffff};
u32 lbl_80325E60[24] = {0x000000c8, 0x00000000, 0x00800000, 0xffffff80, 0xfe70ff38, 0x00000000, 0x00000000, 0xffffff80,
                        0x0190ff38, 0x00000000, 0x01000000, 0xffffff80, 0x000000c8, 0x00000000, 0x00800100, 0xffffff80,
                        0xfe70ff38, 0x00000000, 0x00000100, 0xffffff80, 0x0190ff38, 0x00000000, 0x01000100, 0xffffff80};
u32 gDFropenodeObjDescriptor[24] = {0x00000000,
                                    0x00000000,
                                    0x00000000,
                                    0x00130000,
                                    (u32)dfropenode_initialise,
                                    (u32)dfropenode_release,
                                    0x00000000,
                                    (u32)dfropenode_init,
                                    (u32)dfropenode_update,
                                    (u32)dfropenode_hitDetect,
                                    (u32)dfropenode_render,
                                    (u32)dfropenode_free,
                                    (u32)dfropenode_getObjectTypeId,
                                    (u32)dfropenode_getExtraSize,
                                    (u32)dfropenode_getPlaneEquation,
                                    (u32)dfropenode_getWorldPosAtPhase,
                                    (u32)dfropenode_advancePhaseByDistance,
                                    (u32)dfropenode_applyForceAtPhase,
                                    (u32)dfropenode_findNearestRopePoint,
                                    (u32)dfropenode_getAngle,
                                    (u32)dfropenode_setVisible,
                                    (u32)dfropenode_isVisible,
                                    (u32)dfropenode_setMinY,
                                    (u32)dfropenode_clearLinkedObj};
u32 lbl_80325F20[12] = {0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
u32 gDFSH_Door2SpeciObjDescriptor[14] = {0x00000000,
                                         0x00000000,
                                         0x00000000,
                                         0x00090000,
                                         (u32)DFSH_Door2Speci_initialise,
                                         (u32)DFSH_Door2Speci_release,
                                         0x00000000,
                                         (u32)DFSH_Door2Speci_init,
                                         (u32)DFSH_Door2Speci_update,
                                         (u32)DFSH_Door2Speci_hitDetect,
                                         (u32)DFSH_Door2Speci_render,
                                         (u32)DFSH_Door2Speci_free,
                                         (u32)DFSH_Door2Speci_getObjectTypeId,
                                         (u32)DFSH_Door2Speci_getExtraSize};
