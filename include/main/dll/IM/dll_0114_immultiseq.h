#ifndef MAIN_DLL_IM_DLL_0114_IMMULTISEQ_H_
#define MAIN_DLL_IM_DLL_0114_IMMULTISEQ_H_

#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct IMMultiSeqPlacement
{
    ObjPlacement base;
    s16 completionGameBits[4];
    s16 activeGameBits[4];
    u8 initialYaw;
    u8 pad29;
    u8 modelBankIndex;
    u8 pad2B;
    s8 triggerIds[4];
    u8 polarityMask;
    u8 pad31[3];
} IMMultiSeqPlacement;

typedef struct IMMultiSeqState
{
    u8 step;
    u8 flags;
} IMMultiSeqState;

/* 8-aligned so MWCC emits the retail pad before the descriptor table. */
typedef union IMMultiSeqDescriptorAlign8
{
    ObjectDescriptor desc;
    u64 align8;
} IMMultiSeqDescriptorAlign8;

extern IMMultiSeqDescriptorAlign8 gIMMultiSeqObjDescriptor;

int IMMultiSeq_getExtraSize(void);
int IMMultiSeq_getObjectTypeId(void);
void IMMultiSeq_free(int obj);
void IMMultiSeq_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void IMMultiSeq_hitDetect(void);
void IMMultiSeq_update(int* obj);
void IMMultiSeq_init(int* obj, IMMultiSeqPlacement* params);
void IMMultiSeq_release(void);
void IMMultiSeq_initialise(void);
int IMMultiSeq_SeqFn(int* obj, int* anim, ObjAnimUpdateState* animUpdate);

#endif /* MAIN_DLL_IM_DLL_0114_IMMULTISEQ_H_ */
