#ifndef MAIN_OBJSEQ_API_H_
#define MAIN_OBJSEQ_API_H_

#include "types.h"
#include "dolphin/gx/GXStruct.h"

int getCurSeqNo(void);
void ObjSeq_copyDefaultColor(GXColor* colorOut);

extern struct GameObject* focusedNpc;
extern u8 curSeqNo;
extern s16 seqGlobal1;
extern s16 seqGlobal2;
extern int objSeqObjs;
extern int gObjSeqStreamSuppressed;
extern GXColor gObjSeqDefaultColor;
extern s16 gObjSeqSlotSeqIdTable[];
extern f32 gObjSeqSlotStreamTimeTable[];
extern f32 objSeqOverridePos[];
extern char sEndObjSequenceMaxFreesError[];

#endif /* MAIN_OBJSEQ_API_H_ */
