#ifndef MAIN_OBJSEQ_H_
#define MAIN_OBJSEQ_H_

#include "global.h"

/*
 * ObjSeqState - per-object sequence playback state, stored in the obj+0xB8
 * extra block of sequence-driven objects (seq = *(u8 **)(obj + 0xb8) in
 * objseq.c). Only fields with read/write evidence in objseq.c are named;
 * everything else is padded.
 */
typedef void (*ObjSeqFreeCallback)(void *ctx, u8 *obj);

typedef struct ObjSeqState {
    void *targetObj;
    u8 unk04[8];
    f32 unk0C;
    f32 unk10;
    s16 rotStepX;  /* added to obj rotation each step */
    s16 rotStepY;
    s16 rotStepZ;
    s16 heading;
    u8 unk1C[4];
    f32 fade;
    f32 posOffsetDecay; /* posOffsetScale -= posOffsetDecay * timeDelta */
    s32 curveId;
    void *curveInterp; /* RomCurveInterpState* */
    s16 sfxTimer[4]; /* slot 3 = -1 while looped sfx active */
    s16 sfxId[4];
    f32 posOffsetX; /* seqObj pos = posOffset * posOffsetScale + base */
    f32 posOffsetY;
    f32 posOffsetZ;
    f32 posOffsetScale;
    s16 rotOffsetX; /* scaled by posOffsetScale, added to base rotation */
    s16 rotOffsetY;
    s16 rotOffsetZ;
    u8 movementState;
    u8 slot; /* index into per-slot seq globals */
    s16 curFrame;
    s16 prevFrame;
    s16 endFrame;
    s16 unk5E;
    s16 unk60;
    s16 cmdCount;
    s16 animCount;
    s16 cmdCursor;
    s16 unk68;
    s16 unk6A;
    s16 unk6C;
    s16 flags;
    s16 unk70;
    u8 unk72[2];
    s32 unk74;
    u8 unk78;
    u8 unk79;
    u8 unk7A;
    u8 unk7B;
    u8 unk7C;
    u8 unk7D;
    u8 unk7E;
    u8 unk7F;
    u8 unk80;
    u8 unk81[0xA];
    u8 unk8B;
    u8 unk8C;
    u8 unk8D;
    u8 unk8E;
    u8 unk8F;
    u8 unk90;
    u8 unk91[3];
    u8 *cmds;        /* 4-byte command records */
    u8 *animEntries; /* 8-byte anim records */
    s16 trackAnimStart[19];
    s16 trackRunLength[19];
    ObjSeqFreeCallback freeCallback;
    u8 unkEC[0x20];
    s32 unk10C;
    void *unk110;
    s16 unk114;
    s16 unk116;
    s16 unk118[10];
    u8 unk12C[10];
    u8 unk136[2];
} ObjSeqState;

STATIC_ASSERT(sizeof(ObjSeqState) == 0x138);
STATIC_ASSERT(offsetof(ObjSeqState, curFrame) == 0x58);
STATIC_ASSERT(offsetof(ObjSeqState, cmds) == 0x94);
STATIC_ASSERT(offsetof(ObjSeqState, trackRunLength) == 0xC2);
STATIC_ASSERT(offsetof(ObjSeqState, unk12C) == 0x12C);

#endif
