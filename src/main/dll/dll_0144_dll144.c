/*
 * dll144 (DLL 0x144) - a near-empty front-end sequence object stub.
 *
 * The active object callbacks are all no-ops (free/hitDetect/update/
 * release/initialise do nothing; getExtraSize/getObjectTypeId return 0).
 * Its SeqFn just clears the per-frame sequenceEventActive flag and its
 * init zeroes anim.rotX (obj+0x00) and installs the SeqFn as the anim
 * event callback. render forwards a fixed scale (lbl_803E56C0) to the
 * shared objRenderFn_8003b8f4 when visible.
 *
 * The trailing gFElevControlObjDescriptor (the sibling FElevControl
 * elevator-control object, owned by DLL 0x142) is emitted here too.
 */
#include "main/object_descriptor.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/dll/VF/vf_shared.h"
extern f32 lbl_803E56C0;

int FElevControl_getExtraSize(void);
int FElevControl_getObjectTypeId(void);
void FElevControl_free(void);
void FElevControl_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void FElevControl_hitDetect(void);
void FElevControl_update(void);
void FElevControl_init(int x);
void FElevControl_release(void);
void FElevControl_initialise(void);

int dll_144_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int dll_144_getExtraSize(void);
int dll_144_getObjectTypeId(void);
void dll_144_free(void);
void dll_144_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_144_hitDetect(void);
void dll_144_update(void);
void dll_144_init(int obj);
void dll_144_release(void);
void dll_144_initialise(void);

int dll_144_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    animUpdate->sequenceEventActive = 0;
    return 0;
}

int dll_144_getExtraSize(void) { return 0x0; }
int dll_144_getObjectTypeId(void) { return 0x0; }

void dll_144_free(void)
{
}

void dll_144_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E56C0);
}

void dll_144_hitDetect(void)
{
}

void dll_144_update(void)
{
}

void dll_144_init(int obj)
{
    ((GameObject*)obj)->anim.rotX = 0;
    ((GameObject*)obj)->animEventCallback = dll_144_SeqFn;
}

void dll_144_release(void)
{
}

void dll_144_initialise(void)
{
}

ObjectDescriptor gFElevControlObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)FElevControl_initialise,
    (ObjectDescriptorCallback)FElevControl_release,
    0,
    (ObjectDescriptorCallback)FElevControl_init,
    (ObjectDescriptorCallback)FElevControl_update,
    (ObjectDescriptorCallback)FElevControl_hitDetect,
    (ObjectDescriptorCallback)FElevControl_render,
    (ObjectDescriptorCallback)FElevControl_free,
    (ObjectDescriptorCallback)FElevControl_getObjectTypeId,
    FElevControl_getExtraSize,
};
