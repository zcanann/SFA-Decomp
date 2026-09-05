#ifndef DLLS_OBJECTS_557_DFP_SEQPOIN_H_
#define DLLS_OBJECTS_557_DFP_SEQPOIN_H_

#include "game/objects/object.h"
#include "main/objseq.h"
#include "game/objects/object_setup.h"
#include "dlls/object_descriptor.h"

typedef struct DfpSeqPointPlacement {
    ObjPlacement base;
    s8 spawnRot;
    u8 triggerMode;
    s16 triggerRadius;
    s16 sequenceId;
    s16 conditionGameBit;
    s16 disableGameBit;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DfpSeqPointPlacement;

STATIC_ASSERT(offsetof(DfpSeqPointPlacement, spawnRot) == 0x18);
STATIC_ASSERT(offsetof(DfpSeqPointPlacement, disableGameBit) == 0x20);
STATIC_ASSERT(sizeof(DfpSeqPointPlacement) == 0x30);

typedef struct DfpFlags7 {
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 rest : 5;
} DfpFlags7;

typedef struct DfpSeqPointState {
    f32 triggerRadius;    /* def+0x1A */
    s16 conditionGameBit; /* 0x04: def+0x1E */
    s16 disableGameBit;   /* 0x06: def+0x20 */
    s16 sequenceId;       /* 0x08: def+0x1C */
    u8 unk0A[3];
    u8 doneLatch;   /* 0x0D */
    u8 triggerMode; /* 0x0E: def+0x19 */
    DfpFlags7 flags0F;
} DfpSeqPointState;

STATIC_ASSERT(sizeof(DfpSeqPointState) == 0x10);

int DFP_seqpoint_getExtraSize(void);
int DFP_seqpoint_getObjectTypeId(void);
void DFP_seqpoint_free(void);
void DFP_seqpoint_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void DFP_seqpoint_hitDetect(void);
void DFP_seqpoint_update(GameObject* obj);
void DFP_seqpoint_init(GameObject* obj, u8* init);
int DFP_seqpoint_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate);
void DFP_seqpoint_release(void);
void DFP_seqpoint_initialise(void);

extern ObjectDescriptor gDFP_seqpointObjDescriptor;

#endif /* DLLS_OBJECTS_557_DFP_SEQPOIN_H_ */
