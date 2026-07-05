/*
 * feseqobject (DLL 0x143) - the front-end sequence-driven prop object.
 *
 * FEseqobject_SeqFn runs the object's animation-event track: event 1 sets
 * game bit 0x75 (sequence-complete latch read in update), events 2..6 spawn
 * partfx 0x85 with effect variant 0..4. It also drains its object message
 * queue, relaying messages 0xF000B/C/D to the seqId-0xF7 control object
 * (found via ObjGroup_GetObjects group 3) as 0x130001/2/3, but only while
 * the sequence-control "suppressed" flag (OBJSEQ_CONTROL_SUPPRESS_MSG) is
 * clear.
 *
 * FEseqobject_update kicks sequence 0 once per frame until bit 0x75 is set.
 * This TU also emits the trailing gFElevControlObjDescriptor (the sibling
 * 0x142 elevator-control descriptor); its FElevControl_* callbacks live in
 * dll_0142_felevcontrol.c.
 */
#include "main/dll/DB/DBrockfall.h"
#include "main/dll/feseqobjecteffectparams_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/objseq.h"
#include "main/dll/VF/vf_shared.h"
extern f32 lbl_803E56B0; /* 0.0f effect-position seed */
extern f32 lbl_803E56B4; /* 1.0f effect scale / render distance */

#pragma scheduling on
#pragma peephole on

/* anim-event opcodes consumed by FEseqobject_SeqFn */
enum
{
    FESEQOBJECT_EVENT_SET_BIT = 1,
    FESEQOBJECT_EVENT_FX_0 = 2,
    FESEQOBJECT_EVENT_FX_1 = 3,
    FESEQOBJECT_EVENT_FX_2 = 4,
    FESEQOBJECT_EVENT_FX_3 = 5,
    FESEQOBJECT_EVENT_FX_4 = 6
};

/* object messages relayed to the seqId-0xF7 control object */
enum
{
    FESEQOBJECT_MSG_IN_1 = 0xf000b,
    FESEQOBJECT_MSG_IN_2 = 0xf000c,
    FESEQOBJECT_MSG_IN_3 = 0xf000d,
    FESEQOBJECT_MSG_OUT_1 = 0x130001,
    FESEQOBJECT_MSG_OUT_2 = 0x130002,
    FESEQOBJECT_MSG_OUT_3 = 0x130003
};

#define FESEQOBJECT_SEQUENCE_BIT 0x75
#define FESEQOBJECT_CONTROL_SEQ_ID 0xf7
#define FESEQOBJECT_CONTROL_GROUP 3
#define OBJSEQ_CONTROL_SUPPRESS_MSG 0x80

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

    objects = (int*)ObjGroup_GetObjects(FESEQOBJECT_CONTROL_GROUP, &count);
    found = 0;
    for (i = 0; i < count; i++)
    {
        int obj = objects[i];
        if (((GameObject*)obj)->anim.seqId == FESEQOBJECT_CONTROL_SEQ_ID)
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
    int controlObj;
    int i;
    u32 sender;
    int msg;
    u32 param;
    int count;
    int* objects;
    f32 one;
    f32 zero;

    controlObj = 0;
    i = 0;
    zero = lbl_803E56B0;
    one = lbl_803E56B4;
    for (; i < animUpdate->eventCount; i++)
    {
        effect.x = zero;
        effect.y = zero;
        effect.z = zero;
        effect.scale = one;
        effect.yRot = 0;
        effect.xRot = 0;
        effect.variant = 0;

        switch (animUpdate->eventIds[i])
        {
        case FESEQOBJECT_EVENT_SET_BIT:
            GameBit_Set(FESEQOBJECT_SEQUENCE_BIT, 1);
            break;
        case FESEQOBJECT_EVENT_FX_0:
            effect.variant = 0;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case FESEQOBJECT_EVENT_FX_1:
            effect.variant = 1;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case FESEQOBJECT_EVENT_FX_2:
            effect.variant = 2;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case FESEQOBJECT_EVENT_FX_3:
            effect.variant = 3;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case FESEQOBJECT_EVENT_FX_4:
            effect.variant = 4;
            FEseqobject_spawnEffect(self, &effect);
            break;
        }
    }

    while (ObjMsg_Pop((void*)self, &msg, &sender, &param) != 0)
    {
        if ((animUpdate->sequenceControlFlags & OBJSEQ_CONTROL_SUPPRESS_MSG) == 0)
        {
            switch (msg)
            {
            case FESEQOBJECT_MSG_IN_1:
                objects = (int*)ObjGroup_GetObjects(FESEQOBJECT_CONTROL_GROUP, &count);
                for (i = 0; i < count; i++)
                {
                    if (((GameObject*)objects[i])->anim.seqId == FESEQOBJECT_CONTROL_SEQ_ID)
                    {
                        controlObj = objects[i];
                        i = count;
                    }
                }
                if ((void*)controlObj != NULL)
                {
                    ObjMsg_SendToObject((void*)controlObj, FESEQOBJECT_MSG_OUT_1, self, 0);
                }
                break;
            case FESEQOBJECT_MSG_IN_2:
                objects = (int*)ObjGroup_GetObjects(FESEQOBJECT_CONTROL_GROUP, &count);
                for (i = 0; i < count; i++)
                {
                    if (((GameObject*)objects[i])->anim.seqId == FESEQOBJECT_CONTROL_SEQ_ID)
                    {
                        controlObj = objects[i];
                        i = count;
                    }
                }
                if ((void*)controlObj != NULL)
                {
                    ObjMsg_SendToObject((void*)controlObj, FESEQOBJECT_MSG_OUT_2, self, 0);
                }
                break;
            case FESEQOBJECT_MSG_IN_3:
                objects = (int*)ObjGroup_GetObjects(FESEQOBJECT_CONTROL_GROUP, &count);
                for (i = 0; i < count; i++)
                {
                    if (((GameObject*)objects[i])->anim.seqId == FESEQOBJECT_CONTROL_SEQ_ID)
                    {
                        controlObj = objects[i];
                        i = count;
                    }
                }
                if ((void*)controlObj != NULL)
                {
                    ObjMsg_SendToObject((void*)controlObj, FESEQOBJECT_MSG_OUT_3, self, 0);
                }
                break;
            }
        }
    }
    animUpdate->sequenceEventActive = 0;
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
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E56B4);
}

/*
 * Function: FEseqobject_init
 * EN v1.0 Address: 0x801DF8F4
 * EN v1.0 Size: 56b
 */
void FEseqobject_init(int obj)
{
    *(short*)obj = 0;
    ((GameObject*)obj)->animEventCallback = FEseqobject_SeqFn;
    ObjMsg_AllocQueue((void*)obj, 0xa);
}

void FEseqobject_update(int obj)
{
    register int self = obj;
    *(short*)self = 0x2000;
    if (GameBit_Get(FESEQOBJECT_SEQUENCE_BIT) == 0)
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
