#include "main/dll/DB/DBrockfall.h"
#include "main/dll/feseqobjecteffectparams_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern f32 lbl_803E56B0;
extern f32 lbl_803E56B4;

#pragma scheduling on
#pragma peephole on
extern void objRenderFn_8003b8f4(f32);

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
int FEseqobject_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    FEseqobjectEffectParams effect;
    register int self = obj;
    register ObjAnimUpdateState* anim = animUpdate;
    register int controlObj;
    int i;
    int msg;
    uint sender;
    uint param;
    f32 one;
    f32 zero;

    controlObj = 0;
    i = 0;
    one = lbl_803E56B4;
    zero = lbl_803E56B0;
    for (; i < anim->eventCount; i++)
    {
        effect.x = zero;
        effect.y = zero;
        effect.z = zero;
        effect.scale = one;
        effect.yRot = 0;
        effect.xRot = 0;
        effect.variant = 0;

        switch (anim->eventIds[i])
        {
        case 1:
            GameBit_Set(0x75, 1);
            break;
        case 2:
            effect.variant = 0;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case 3:
            effect.variant = 1;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case 4:
            effect.variant = 2;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case 5:
            effect.variant = 3;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case 6:
            effect.variant = 4;
            FEseqobject_spawnEffect(self, &effect);
            break;
        }
    }

    while (ObjMsg_Pop((void*)self, (uint*)&msg, &sender, &param) != 0)
    {
        if ((((u8*)anim)[0x90] & 0x80) == 0)
        {
            switch (msg)
            {
            case 0xf000b:
                controlObj = FEseqobject_findControlObject();
                if (controlObj != 0)
                {
                    ObjMsg_SendToObject((void*)controlObj, 0x130001, (void*)self, 0);
                }
                break;
            case 0xf000c:
                controlObj = FEseqobject_findControlObject();
                if (controlObj != 0)
                {
                    ObjMsg_SendToObject((void*)controlObj, 0x130002, (void*)self, 0);
                }
                break;
            case 0xf000d:
                controlObj = FEseqobject_findControlObject();
                if (controlObj != 0)
                {
                    ObjMsg_SendToObject((void*)controlObj, 0x130003, (void*)self, 0);
                }
                break;
            }
        }
    }
    anim->sequenceEventActive = 0;
    return 0;
}

void FEseqobject_free(void)
{
}

void FEseqobject_hitDetect(void)
{
}

void FEseqobject_release(void)
{
}

void FEseqobject_initialise(void)
{
}






int FEseqobject_getExtraSize(void) { return 0x1; }
int FEseqobject_getObjectTypeId(void) { return 0x0; }

void FEseqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E56B4);
}



/*
 * Function: FEseqobject_init
 * EN v1.0 Address: 0x801DF8F4
 * EN v1.0 Size: 56b
 */
void FEseqobject_init(int obj)
{
    *(short*)obj = 0;
    ((GameObject*)obj)->animEventCallback = (void*)FEseqobject_SeqFn;
    ObjMsg_AllocQueue((void*)obj, 0xa);
}

/*
 * Function: FEseqobject_update
 * EN v1.0 Address: 0x801DF894
 * EN v1.0 Size: 96b
 */
void FEseqobject_update(int obj)
{
    register int self = obj;
    *(short*)self = 0x2000;
    if (GameBit_Get(0x75) == 0)
    {
        (*gObjectTriggerInterface)->runSequence(0, (void*)self, -1);
    }
}

/*
 * Function: dll_144_SeqFn
 * EN v1.0 Address: 0x801DF9AC
 * EN v1.0 Size: 16b
 */

/*
 * Function: dll_144_init
 * EN v1.0 Address: 0x801DFA08
 * EN v1.0 Size: 24b
 */

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
