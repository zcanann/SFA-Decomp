#ifndef MAIN_OBJSEQ_H_
#define MAIN_OBJSEQ_H_

#include "global.h"
#include "main/objanim_internal.h"
#include "main/objseq_control.h"

/*
 * ObjSeqState - per-object sequence playback state, stored in the obj+0xB8
 * extra block of sequence-driven objects (seq = *(u8 **)(obj + 0xb8) in
 * objseq.c). Only fields with read/write evidence in objseq.c are named;
 * everything else is padded.
 */
typedef struct ObjSeqState ObjSeqState;

typedef struct ObjectTriggerInterface {
    void *unusedSlot02;
    void (*onMapSetup)(void);
    void (*addBgCommand)(int index, int xrot, int yrot);
    void (*setFlag)(int index, int value);
    int (*getBool)(int index);
    int (*update)(u8 *obj, f32 timeStep);
    void (*updateCamera)(void);
    void (*loadAnimData)(u8 *seq, u8 *obj);
    void (*initState)(u8 *seq);
    void (*freeState)(u8 *seq);
    void (*run)(void);
    int (*resolveAndAssignTargetObject)(u8 *obj);
    int (*func14Ret0)(void);
    int (*func15Ret1)(void);
    int (*getGlobal4)(void);
    void (*setGlobal4)(int value);
    int (*func18Ret0)(void);
    void (*func19Nop)(void);
    int (*runSequence)(int seqIndex, void *obj, int flags);
    void (*endSequence)(int seqIndex);
    void (*setCamVars)(int camA, int camB, int camC, int camD);
    void (*preempt)(int obj, int triggerId);
    void (*yield)(ObjSeqState *seq, int value);
    u8 (*getGlobal3)(void);
    void (*setGlobal3)(u8 value);
    s16 (*getGlobal1)(void);
    void (*setGlobal1)(s16 value);
    s16 (*getGlobal2)(void);
    void (*setGlobal2)(s16 value);
    void (*setXrot)(int index, int xrot);
    int (*func20)(void *obj, u8 *seq, int cmd, int maxCount, int paramOffset, int arg5,
                  int arg6);
    int (*setObjects)(int a, int b, int c);
    int (*setOverridePos)(f32 x, f32 y, f32 z);
    int (*setRunSequenceWorldSpace)(int unused, int mode);
} ObjectTriggerInterface;

extern ObjectTriggerInterface **gObjectTriggerInterface;

STATIC_ASSERT(offsetof(ObjectTriggerInterface, onMapSetup) == 0x04);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, addBgCommand) == 0x08);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, setFlag) == 0x0C);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, getBool) == 0x10);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, update) == 0x14);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, updateCamera) == 0x18);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, loadAnimData) == 0x1C);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, initState) == 0x20);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, freeState) == 0x24);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, run) == 0x28);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, resolveAndAssignTargetObject) == 0x2C);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, func14Ret0) == 0x30);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, func15Ret1) == 0x34);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, getGlobal4) == 0x38);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, setGlobal4) == 0x3C);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, func18Ret0) == 0x40);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, func19Nop) == 0x44);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, runSequence) == 0x48);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, endSequence) == 0x4C);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, setCamVars) == 0x50);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, preempt) == 0x54);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, yield) == 0x58);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, getGlobal3) == 0x5C);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, setGlobal3) == 0x60);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, getGlobal1) == 0x64);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, setGlobal1) == 0x68);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, getGlobal2) == 0x6C);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, setGlobal2) == 0x70);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, setXrot) == 0x74);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, func20) == 0x78);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, setObjects) == 0x7C);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, setOverridePos) == 0x80);
STATIC_ASSERT(offsetof(ObjectTriggerInterface, setRunSequenceWorldSpace) == 0x84);

struct ObjSeqState {
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
    u8 slot; /* index into per-slot seq globals; commonly interpreted as s8 */
    s16 curFrame;
    s16 prevFrame;
    s16 endFrame;
    s16 unk5E;
    s16 seqCounter; /* signed script register: set/added by sequence opcodes, sign-tested by ObjSeq_EvaluateCondition */
    s16 cmdCount;
    s16 animCount;
    s16 cmdCursor;
    s16 retriggerFrame; /* curFrame threshold for a repeating command; advances by cmd stride */
    s16 gameBit;
    s16 moveId; /* masked to 0xfff; compared to anim.currentMove; passed to ObjAnim_SetCurrentMove */
    s16 flags;
    s16 savedFlags; /* snapshot of flags, restored on state transitions */
    u8 unk72[2];
    s32 savedFrame; /* saved frame value restored into curFrame */
    u8 unk78;
    u8 unk79;
    u8 unk7A;
    u8 unk7B;
    u8 unk7C;
    u8 unk7D;
    u8 unk7E;
    u8 unk7F;
    u8 unk80;
    u8 eventIds[0xA];
    u8 eventCount;
    u8 unk8C;
    u8 unk8D;
    u8 unk8E;
    u8 unk8F;
    u8 sequenceControlFlags;
    u8 unk91[3];
    u8 *cmds;        /* 4-byte command records */
    u8 *animEntries; /* 8-byte anim records */
    s16 trackAnimStart[19];
    s16 trackRunLength[19];
    ObjAnimSequenceFreeCallback freeCallback;
    ObjAnimSequenceConditionCallback conditionCallback;
    ObjAnimEventList animEvents;
    s32 targetObjId; /* object id resolved via ObjList_FindObjectById into targetObj */
    void *callbackContext;
    s16 baseRotY; /* base rotation added to interpolated curve angle (vec[1]) */
    s16 baseRotX; /* base rotation added to interpolated curve angle (vec[0]) */
    s16 conditionFrames[10];
    u8 conditionOpcodes[10];
    u8 flags136[2]; /* 0x136 flags byte; bit 0x04 = record a save-point on free */
};

STATIC_ASSERT(sizeof(ObjSeqState) == 0x138);
STATIC_ASSERT(offsetof(ObjSeqState, curFrame) == 0x58);
STATIC_ASSERT(offsetof(ObjSeqState, eventIds) == 0x81);
STATIC_ASSERT(offsetof(ObjSeqState, eventCount) == 0x8B);
STATIC_ASSERT(offsetof(ObjSeqState, sequenceControlFlags) == 0x90);
STATIC_ASSERT(offsetof(ObjSeqState, cmds) == 0x94);
STATIC_ASSERT(offsetof(ObjSeqState, trackRunLength) == 0xC2);
STATIC_ASSERT(offsetof(ObjSeqState, freeCallback) == 0xE8);
STATIC_ASSERT(offsetof(ObjSeqState, conditionCallback) == 0xEC);
STATIC_ASSERT(offsetof(ObjSeqState, animEvents) == 0xF0);
STATIC_ASSERT(offsetof(ObjSeqState, callbackContext) == 0x110);
STATIC_ASSERT(offsetof(ObjSeqState, conditionFrames) == 0x118);
STATIC_ASSERT(offsetof(ObjSeqState, conditionOpcodes) == 0x12C);

#endif
