/*
 * felevcontrol (DLL 0x142) - floating elevator control object for the
 * CloudRunner Fortress / Dinosaur Planet elevator sequences.
 *
 * This TU owns the FElevControl object descriptor and shares the static
 * FEseqobject_spawnEffect / FEseqobject_findControlObject helpers with
 * sibling DLLs 0x143 (feseqobject) and 0x144 (dll144). The render
 * function passes lbl_803E56B8 (the elevator's render scale / distance
 * threshold) to the common objRenderFn_8003b8f4.
 */
#include "main/dll/DB/DBrockfall.h"
#include "main/dll/feseqobjecteffectparams_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/VF/vf_shared.h"

#pragma scheduling on
#pragma peephole on

extern f32 lbl_803E56B8;

static void FEseqobject_spawnEffect(int obj, FEseqobjectEffectParams* params)
{
    (*gPartfxInterface)->spawnObject((void*)obj, 0x85, params, 1, -1, NULL);
}

static int FEseqobject_findControlObject(void)
{
    int count;
    int i;
    int found;
    int* objects;

    objects = (int*)ObjGroup_GetObjects(3, &count);
    found = 0;
    for (i = 0; i < count; i++)
    {
        int obj = objects[i];
        if (((GameObject*)obj)->anim.seqId == 0xf7) /* elevator control object's anim sequence id */
        {
            found = obj;
            i = count;
        }
    }
    return found;
}

#pragma peephole off
void FElevControl_free(void)
{
}

void FElevControl_hitDetect(void)
{
}

void FElevControl_update(void)
{
}

void FElevControl_release(void)
{
}

void FElevControl_initialise(void)
{
}

int FElevControl_getExtraSize(void) { return 0x0; }
int FElevControl_getObjectTypeId(void) { return 0x0; }

void FElevControl_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) objRenderFn_8003b8f4(lbl_803E56B8);
}

void FElevControl_init(int x) { ObjMsg_AllocQueue(x, 0x2); }

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
