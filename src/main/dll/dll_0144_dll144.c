#include "main/dll/DB/DBrockfall.h"
#include "main/dll/feseqobjecteffectparams_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"


#pragma scheduling on
#pragma peephole on
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E56C0;

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
        if (((GameObject*)obj)->anim.seqId == 0xf7)
        {
            found = obj;
            i = count;
        }
    }
    return found;
}







#pragma scheduling off
#pragma peephole off
void dll_144_free(void)
{
}

void dll_144_hitDetect(void)
{
}

void dll_144_update(void)
{
}

void dll_144_release(void)
{
}

void dll_144_initialise(void)
{
}

int dll_144_getExtraSize(void) { return 0x0; }
int dll_144_getObjectTypeId(void) { return 0x0; }


void dll_144_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E56C0);
}


/*
 * Function: FEseqobject_init
 * EN v1.0 Address: 0x801DF8F4
 * EN v1.0 Size: 56b
 */

/*
 * Function: FEseqobject_update
 * EN v1.0 Address: 0x801DF894
 * EN v1.0 Size: 96b
 */

/*
 * Function: dll_144_SeqFn
 * EN v1.0 Address: 0x801DF9AC
 * EN v1.0 Size: 16b
 */
int dll_144_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    animUpdate->sequenceEventActive = 0;
    return 0;
}

/*
 * Function: dll_144_init
 * EN v1.0 Address: 0x801DFA08
 * EN v1.0 Size: 24b
 */
void dll_144_init(int obj)
{
    *(short*)obj = 0;
    ((GameObject*)obj)->animEventCallback = (void*)dll_144_SeqFn;
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
