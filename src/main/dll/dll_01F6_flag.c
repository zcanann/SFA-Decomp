/*
 * DLL 0x01F6 - Flag (decorative flag object). TU: 0x801E5DC4-0x801E5F74.
 *
 * A passive cloth/flag prop animated through ObjAnim moves. Behaviour is
 * selected by the object's current animation seqId:
 *   0x187  - advance the idle flutter move by framesThisStep.
 *   0x803  - "tied" flag: track the linked parent object. While the parent
 *            holds object flag 0x1000 the flag stays slack (velocityX from
 *            0.0f); otherwise it swings, deriving velocityX from the
 *            parent's rotZ and integrating it into its own rotZ.
 *   other  - advance the default flutter move by framesThisStep.
 * init seeds rotX from the placement byte and starts the flutter move for
 * everything except the tied (0x803) variant. render draws the model when
 * visible.
 */
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/frame_timing.h"
#include "main/object_render_legacy.h"
#include "main/dll/dll_01F6_flag.h"
#include "main/object_descriptor.h"

enum
{
    FLAG_SEQ_FLUTTER = 0x187,
    FLAG_SEQ_TIED = 0x803
};

#define FLAG_PARENT_SLACK_FLAG 0x1000

/* placement-record byte seeding the flag's initial rotX */
#define FLAG_MAPDATA_ROT_X_BYTE_OFF 0x18


int Flag_getExtraSize(void)
{
    return 0x0;
}
int Flag_getObjectTypeId(void)
{
    return 0x0;
}

void Flag_free(void)
{
}

static void flag_updateTiedSwing(GameObject* obj, GameObject* parent)
{
    if ((parent->objectFlags & FLAG_PARENT_SLACK_FLAG) != 0)
    {
        obj->anim.velocityX = 0.0f;
    }
    else
    {
        f32 swingScale = 0.5f;
        obj->anim.velocityX = (f32)parent->anim.rotZ * swingScale;
        obj->anim.rotZ = (s16)((f32)obj->anim.rotZ + obj->anim.velocityX);
    }
}

void Flag_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void Flag_hitDetect(void)
{
}

void Flag_update(int obj)
{
    int linkedObj;

    if (((GameObject*)obj)->anim.seqId == FLAG_SEQ_FLUTTER)
    {
        ObjAnim_AdvanceCurrentMove((int)obj, 0.007f, (f32)(u32)framesThisStep, NULL);
    }
    else if (((GameObject*)obj)->anim.seqId == FLAG_SEQ_TIED)
    {
        Obj_GetPlayerObject();
        linkedObj = *(int*)&((GameObject*)obj)->anim.parent;
        flag_updateTiedSwing((GameObject*)obj, (GameObject*)linkedObj);
    }
    else
    {
        ObjAnim_AdvanceCurrentMove((int)obj, 0.02f, (f32)(u32)framesThisStep, NULL);
    }
}

void Flag_init(int* obj, int* def)
{
    if (((GameObject*)obj)->anim.seqId != FLAG_SEQ_TIED)
    {
        ((GameObject*)obj)->anim.rotX = (s16)((s32) * (s8*)((char*)def + FLAG_MAPDATA_ROT_X_BYTE_OFF) << 8);
        ObjAnim_SetCurrentMove((int)obj, 0, 0.0f, 0);
    }
}

void Flag_release(void)
{
}

void Flag_initialise(void)
{
}

ObjectDescriptor gFlagObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)Flag_initialise,
    (ObjectDescriptorCallback)Flag_release,
    0,
    (ObjectDescriptorCallback)Flag_init,
    (ObjectDescriptorCallback)Flag_update,
    (ObjectDescriptorCallback)Flag_hitDetect,
    (ObjectDescriptorCallback)Flag_render,
    (ObjectDescriptorCallback)Flag_free,
    (ObjectDescriptorCallback)Flag_getObjectTypeId,
    Flag_getExtraSize,
};
