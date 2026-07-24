#ifndef MAIN_OBJPRINT_INTERNAL_H_
#define MAIN_OBJPRINT_INTERNAL_H_

#include "main/game_object.h"
#include "main/objtexture.h"

#define OBJPRINT_OBJECT(obj)            ((ObjAnimComponent*)(obj))
#define OBJPRINT_MODEL_INSTANCE(obj)    (OBJPRINT_OBJECT(obj)->modelInstance)
#define OBJPRINT_BANK_TABLE(obj)        ((int**)OBJPRINT_OBJECT(obj)->banks)
#define OBJPRINT_ACTIVE_BANK_INDEX(obj) (OBJPRINT_OBJECT(obj)->bankIndex)
#define OBJPRINT_ACTIVE_BANK(obj)       ((int*)OBJPRINT_BANK_TABLE(obj)[OBJPRINT_ACTIVE_BANK_INDEX(obj)])
#define OBJPRINT_MODEL_COUNT(model)     (((ObjDef*)(model))->modelCount)
#define OBJPRINT_JOINT_COUNT(model)     (((ObjDef*)(model))->jointCount)

extern f32 gObjPrintDegToAngle;

/*
 * Per-joint pose scratch written by the head/eye/tail tracking helpers in
 * this file: anim.jointPoseData is an array of these, one per jointData
 * record, stride 0x12.  v[0]/v[1]/v[2] of each vector are the s16 angle
 * deltas (pitch/yaw/roll) applied on top of the animated joint.
 */
typedef struct
{
    s16 v[9];
} ObjJointPose18;

/*
 * ObjDef.jointData (+0x10) is a packed joint-binding table scanned by every
 * finder loop in this file: jointCount (+0x5A) records, each
 * (1 + modelCount (+0x55)) bytes:
 *   byte 0             - joint key (0 = head, 1 = jaw, ...; see the key list
 *                        at lbl_802CAE88 used by objMathFn_8003a380)
 *   byte 1 + bankIndex - joint index in that bank's model, 0xFF = the joint
 *                        does not exist in that bank
 * The record's ordinal selects the matching ObjJointPose18 in
 * anim.jointPoseData (poseOffset advances by 0x12 per record).  The stride
 * is runtime-variable, so the record cannot be a fixed C struct; the raw
 * byte walk below is the original access pattern.
 */
static inline s16* objFindJointVecByKey(GameObject* obj, int key)
{
    int i;
    int k;
    ObjDef* table;
    s16* found;

    found = NULL;
    table = (obj)->anim.modelInstance;
    if (table != NULL)
    {
        i = 0;
        for (k = 0; k < (s32)(u32)table->jointCount; k++)
        {
            if ((int)*(u8*)(*(int*)&table->jointData + OBJPRINT_ACTIVE_BANK_INDEX(obj) + i + 1) != 0xff &&
                (int)*(u8*)(*(int*)&table->jointData + i) == key)
            {
                found = (s16*)&((ObjJointPose18*)(obj)->anim.jointPoseData)[k];
            }
            i = i + table->modelCount + 1;
        }
    }
    return found;
}

static inline ObjTextureRuntimeSlot* characterFindEyeJoint(GameObject* obj, int kind)
{
    ObjTextureSlotDef* list;
    int n;
    int k;
    ObjDef* modelDef;
    ObjTextureRuntimeSlot* found;

    found = NULL;
    modelDef = obj->anim.modelInstance;
    if (modelDef != NULL)
    {
        list = modelDef->textureSlotDefs;
        if (list == NULL)
        {
            return NULL;
        }
        n = (s32)(u32)modelDef->textureSlotCount;
        for (k = 0; k < n; k++)
        {
            if (list->tag == kind)
            {
                found = &obj->anim.textureSlots[k];
            }
            list++;
        }
    }
    return found;
}

#endif
