#ifndef MAIN_JOINT_POSE_H_
#define MAIN_JOINT_POSE_H_

#include "global.h"

/* Additive adjustments to the animated pose, one record per ObjDef joint binding. */
typedef struct ObjJointPose {
    s16 rotation[3];
    s16 scale[3];
    s16 translation[3];
} ObjJointPose;

STATIC_ASSERT(sizeof(ObjJointPose) == 0x12);
STATIC_ASSERT(offsetof(ObjJointPose, rotation) == 0x00);
STATIC_ASSERT(offsetof(ObjJointPose, scale) == 0x06);
STATIC_ASSERT(offsetof(ObjJointPose, translation) == 0x0C);

#endif
