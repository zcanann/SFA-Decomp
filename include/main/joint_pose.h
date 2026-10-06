#ifndef MAIN_JOINT_POSE_H_
#define MAIN_JOINT_POSE_H_

#include "global.h"

/* Packed ObjDef binding: one tag followed by modelCount joint indices.
 * Records have variable width; their ordinal selects the ObjJointPose. */
typedef struct ObjJointBinding {
    u8 tag;
    u8 modelJoints[];
} ObjJointBinding;

#define OBJ_JOINT_BINDING_MISSING 0xFF

STATIC_ASSERT(sizeof(ObjJointBinding) == 1);
STATIC_ASSERT(offsetof(ObjJointBinding, tag) == 0);
STATIC_ASSERT(offsetof(ObjJointBinding, modelJoints) == 1);

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

/* Decoded poses are interleaved within each 64-byte joint workspace, starting
 * at byte 0x1C. Adjustment offsets are relative to the selected rotation row. */
typedef struct ModelJointPosePair {
    s16 rotation[2][3];
    u16 scale[2][3];
    s16 translation[2][3];
} ModelJointPosePair;

STATIC_ASSERT(sizeof(ModelJointPosePair) == 0x24);
STATIC_ASSERT(offsetof(ModelJointPosePair, rotation) == 0x00);
STATIC_ASSERT(offsetof(ModelJointPosePair, scale) == 0x0C);
STATIC_ASSERT(offsetof(ModelJointPosePair, translation) == 0x18);

/* One additive component for each animation channel. A terminal record only
 * initializes byteOffsets; the renderer stops before reading its deltas. */
typedef struct ModelJointAdjustment {
    u16 byteOffsets[2];
    s16 deltas[2];
} ModelJointAdjustment;

#define MODEL_JOINT_ADJUSTMENT_END 0x1000

STATIC_ASSERT(sizeof(ModelJointAdjustment) == 0x08);
STATIC_ASSERT(offsetof(ModelJointAdjustment, byteOffsets[0]) == 0x00);
STATIC_ASSERT(offsetof(ModelJointAdjustment, byteOffsets[1]) == 0x02);
STATIC_ASSERT(offsetof(ModelJointAdjustment, deltas[0]) == 0x04);
STATIC_ASSERT(offsetof(ModelJointAdjustment, deltas[1]) == 0x06);

/* The producer appends halfwords; the decoder walks eight-byte records.
 * Leave room for the two-word terminator when filling the 0x140-byte buffer. */
typedef union ModelJointAdjustmentBuffer {
    s16 words[0xA0];
    ModelJointAdjustment entries[40];
} ModelJointAdjustmentBuffer;

STATIC_ASSERT(sizeof(ModelJointAdjustmentBuffer) == 0x140);

#endif
