#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/objHitReact.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"

extern undefined4 FUN_800723a0();
extern void ObjAnim_LoadCachedMove(int animId,int moveIndex,u8 *cache,ObjAnimDef *animDef);
extern void ObjAnim_LoadMoveEvents(int objAnim,int objType,ObjAnimEventTable *eventTable,u32 moveId,
                                   int async);

extern f64 gObjAnimU32ToDoubleBias;
extern f64 gObjAnimS32ToDoubleBias;
extern f32 gObjAnimProgressOne;
extern f32 gObjAnimProgressZero;
extern f32 gObjAnimEventStepScale;
extern f32 gObjAnimEventFrameScale;
extern f32 lbl_803DE908;
extern f32 lbl_803DE90C;

/*
 * --INFO--
 *
 * Function: ObjAnim_SetBlendMove
 * EN v1.0 Address: 0x8002EB54
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x8002EC4C
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Retail string evidence labels this source-side path as objanim.c/setBlendMove.
 */
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void ObjAnim_SetBlendMove(ObjAnimComponent *objAnim,ObjAnimDef *animDef,ObjAnimState *state,
                          uint moveId,s16 eventState)
{
  register int preservedEventState;
  int moveIndex;
  ObjAnimMoveData *moveData;
  int frameType;
  float frameValue;

  asm { mr preservedEventState, r7 }
  moveIndex =
      animDef->moveGroupBaseIndices[(s32)moveId >> OBJANIM_MOVE_GROUP_SHIFT] +
      (moveId & OBJANIM_MOVE_INDEX_MASK);
  if (moveIndex >= animDef->moveCount) {
    moveIndex = animDef->moveCount - 1;
  }
  if (moveIndex < 0) {
    moveIndex = 0;
  }
  if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0) {
    if (state->lastBlendMoveIndex != moveIndex) {
      state->blendCacheSlot = (u16)state->blendToggle;
      state->prevBlendCacheSlot = (u16)(OBJANIM_MOVE_CACHE_SLOT_COUNT - 1 - state->blendToggle);
      if (animDef->cachedAnimIds[moveIndex] == OBJANIM_MISSING_MOVE_ID) {
        OSReport(gObjAnimSetBlendMoveMissingAnimWarning,animDef->modNo);
        moveIndex = 0;
      }
      ObjAnim_LoadCachedMove((int)animDef->cachedAnimIds[moveIndex],(int)(s16)moveIndex,
                             state->blendMoveCache[state->blendCacheSlot],animDef);
      state->lastBlendMoveIndex = (s16)moveIndex;
    }
    moveData =
        (ObjAnimMoveData *)(state->blendMoveCache[state->blendCacheSlot] +
                            OBJANIM_CACHED_MOVE_DATA_OFFSET);
  }
  else {
    state->blendCacheSlot = (u16)moveIndex;
    moveData = (ObjAnimMoveData *)animDef->moveData[state->blendCacheSlot];
  }
  state->frameCmd = moveData->frameCmd;
  frameType = moveData->frameInfo & OBJANIM_FRAME_TYPE_MASK;
  if (frameType != state->frameType) {
    state->eventState = 0;
  }
  else {
    frameValue = (float)state->frameCmd[1];
    if (frameType == OBJANIM_FRAME_TYPE_CLAMPED) {
      frameValue = frameValue - gObjAnimProgressOne;
    }
    if (frameValue != state->segmentLength) {
      state->eventState = 0;
    }
    else {
      state->eventState = (u16)preservedEventState;
    }
  }
  return;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: Object_ObjAnimSetPrimaryBlendMove
 * EN v1.0 Address: 0x8002ED18
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x8002EE10
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void Object_ObjAnimSetPrimaryBlendMove(ObjAnimComponent *objAnim,uint moveId,int eventState)
{
  ObjAnimBank *bank;

  bank = ObjAnim_GetActiveBank(objAnim);
  if (bank->animDef->moveCount != 0) {
    ObjAnim_SetBlendMove(objAnim,bank->animDef,bank->activeState,moveId,(s16)eventState);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: Object_ObjAnimSetSecondaryBlendMove
 * EN v1.0 Address: 0x8002ED6C
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x8002EE64
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Object_ObjAnimSetSecondaryBlendMove(ObjAnimComponent *objAnim,uint moveId,int eventState)
{
  ObjAnimBank *bank;

  bank = ObjAnim_GetActiveBank(objAnim);
  if (bank->animDef->moveCount != 0) {
    ObjAnim_SetBlendMove(objAnim,bank->animDef,bank->currentState,moveId,(s16)eventState);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: Object_ObjAnimAdvanceMove
 * EN v1.0 Address: 0x8002EDC0
 * EN v1.0 Size: 1100b
 * EN v1.1 Address: 0x8002EEB8
 * EN v1.1 Size: 1100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
asm int Object_ObjAnimAdvanceMove(f32 moveStepScale,f32 deltaTime,int objAnimArg,ObjAnimEventList *events)
{
  nofralloc
  stwu r1,-0x50(r1)
  stw r31,0x4c(r1)
  stw r30,0x48(r1)
  stw r29,0x44(r1)
  li r0,0
  lwz r6,0x7c(r3)
  lbz r5,0xad(r3)
  extsb r5,r5
  slwi r5,r5,2
  lwzx r6,r6,r5
  lwz r5,0(r6)
  lhz r5,0xec(r5)
  cmplwi r5,0
  bne Object_ObjAnimAdvanceMove_hasMoves
  li r3,0
  b Object_ObjAnimAdvanceMove_done
Object_ObjAnimAdvanceMove_hasMoves:
  lwz r7,0x30(r6)
  lfs f0,0x14(r7)
  fmuls f0,f1,f0
  stfs f0,0xc(r7)
  lhz r5,0x58(r7)
  cmplwi r5,0
  beq Object_ObjAnimAdvanceMove_progress
  lbz r5,0x63(r7)
  extsb r5,r5
  rlwinm r5,r5,0,28,28
  cmpwi r5,0
  beq Object_ObjAnimAdvanceMove_savedStepReady
  lfs f0,0xc(r7)
  stfs f0,0x10(r7)
Object_ObjAnimAdvanceMove_savedStepReady:
  lfs f3,0x10(r7)
  lfs f0,8(r7)
  fmadds f0,f3,f2,f0
  stfs f0,8(r7)
  lfs f4,0x18(r7)
  lbz r5,0x61(r7)
  extsb r5,r5
  cmpwi r5,0
  beq Object_ObjAnimAdvanceMove_clampPrevProgress
  lfs f0,8(r7)
  lfs f3,gObjAnimProgressZero
  fcmpo cr0,f0,f3
  bge Object_ObjAnimAdvanceMove_checkPrevUpper
  b Object_ObjAnimAdvanceMove_wrapPrevLowCheck
Object_ObjAnimAdvanceMove_wrapPrevLow:
  lfs f0,8(r7)
  fadds f0,f0,f4
  stfs f0,8(r7)
Object_ObjAnimAdvanceMove_wrapPrevLowCheck:
  lfs f0,8(r7)
  fcmpo cr0,f0,f3
  blt Object_ObjAnimAdvanceMove_wrapPrevLow
Object_ObjAnimAdvanceMove_checkPrevUpper:
  lfs f0,8(r7)
  fcmpo cr0,f0,f4
  cror 2,1,2
  bne Object_ObjAnimAdvanceMove_updateCountdown
  b Object_ObjAnimAdvanceMove_wrapPrevHighCheck
Object_ObjAnimAdvanceMove_wrapPrevHigh:
  lfs f0,8(r7)
  fsubs f0,f0,f4
  stfs f0,8(r7)
Object_ObjAnimAdvanceMove_wrapPrevHighCheck:
  lfs f0,8(r7)
  fcmpo cr0,f0,f4
  cror 2,1,2
  beq Object_ObjAnimAdvanceMove_wrapPrevHigh
  b Object_ObjAnimAdvanceMove_updateCountdown
Object_ObjAnimAdvanceMove_clampPrevProgress:
  lfs f3,8(r7)
  lfs f0,gObjAnimProgressZero
  fcmpo cr0,f3,f0
  bge Object_ObjAnimAdvanceMove_clampPrevUpper
  b Object_ObjAnimAdvanceMove_storePrevClamp
Object_ObjAnimAdvanceMove_clampPrevUpper:
  fcmpo cr0,f3,f4
  ble Object_ObjAnimAdvanceMove_prevWithin
  fmr f0,f4
  b Object_ObjAnimAdvanceMove_storePrevClamp
Object_ObjAnimAdvanceMove_prevWithin:
  fmr f0,f3
Object_ObjAnimAdvanceMove_storePrevClamp:
  stfs f0,8(r7)
Object_ObjAnimAdvanceMove_updateCountdown:
  lbz r5,0x63(r7)
  extsb r5,r5
  rlwinm r5,r5,0,30,30
  cmpwi r5,0
  bne Object_ObjAnimAdvanceMove_countdownChecked
  lhz r5,0x5e(r7)
  lfd f3,gObjAnimU32ToDoubleBias
  stw r5,0xc(r1)
  lis r6,0x4330
  stw r6,8(r1)
  lfd f0,8(r1)
  fsubs f3,f0,f3
  lhz r5,0x58(r7)
  lfd f4,gObjAnimS32ToDoubleBias
  xoris r5,r5,0x8000
  stw r5,0x14(r1)
  stw r6,0x10(r1)
  lfd f0,0x10(r1)
  fsubs f0,f0,f4
  fnmsubs f0,f3,f2,f0
  fctiwz f0,f0
  stfd f0,0x18(r1)
  lwz r5,0x1c(r1)
  cmpwi r5,0
  bge Object_ObjAnimAdvanceMove_countdownNonnegative
  lfs f3,gObjAnimProgressZero
  b Object_ObjAnimAdvanceMove_storeCountdown
Object_ObjAnimAdvanceMove_countdownNonnegative:
  xoris r5,r5,0x8000
  stw r5,0x24(r1)
  stw r6,0x20(r1)
  lfd f0,0x20(r1)
  fsubs f0,f0,f4
  lfs f3,gObjAnimEventStepScale
  fcmpo cr0,f0,f3
  ble Object_ObjAnimAdvanceMove_countdownWithinStep
  b Object_ObjAnimAdvanceMove_storeCountdown
Object_ObjAnimAdvanceMove_countdownWithinStep:
  stw r5,0x2c(r1)
  stw r6,0x28(r1)
  lfd f0,0x28(r1)
  fsubs f3,f0,f4
Object_ObjAnimAdvanceMove_storeCountdown:
  fctiwz f0,f3
  stfd f0,0x30(r1)
  lwz r5,0x34(r1)
  clrlwi r5,r5,16
  sth r5,0x58(r7)
Object_ObjAnimAdvanceMove_countdownChecked:
  lhz r5,0x58(r7)
  cmplwi r5,0
  bne Object_ObjAnimAdvanceMove_progress
  li r5,0
  sth r5,0x5c(r7)
Object_ObjAnimAdvanceMove_progress:
  lfs f3,0x9c(r3)
  fmuls f4,f1,f2
  fadds f0,f3,f4
  stfs f0,0x9c(r3)
  lfs f0,0x9c(r3)
  lfs f2,gObjAnimProgressOne
  fcmpo cr0,f0,f2
  cror 2,1,2
  bne Object_ObjAnimAdvanceMove_checkProgressLow
  lbz r0,0x60(r7)
  extsb r0,r0
  cmpwi r0,0
  beq Object_ObjAnimAdvanceMove_clampHigh
  b Object_ObjAnimAdvanceMove_wrapHighCheck
Object_ObjAnimAdvanceMove_wrapHigh:
  lfs f0,0x9c(r3)
  fsubs f0,f0,f2
  stfs f0,0x9c(r3)
Object_ObjAnimAdvanceMove_wrapHighCheck:
  lfs f0,0x9c(r3)
  fcmpo cr0,f0,f2
  cror 2,1,2
  beq Object_ObjAnimAdvanceMove_wrapHigh
  b Object_ObjAnimAdvanceMove_setWrapped
Object_ObjAnimAdvanceMove_clampHigh:
  stfs f2,0x9c(r3)
Object_ObjAnimAdvanceMove_setWrapped:
  li r0,1
  b Object_ObjAnimAdvanceMove_events
Object_ObjAnimAdvanceMove_checkProgressLow:
  lfs f1,gObjAnimProgressZero
  fcmpo cr0,f0,f1
  bge Object_ObjAnimAdvanceMove_events
  lbz r0,0x60(r7)
  extsb r0,r0
  cmpwi r0,0
  beq Object_ObjAnimAdvanceMove_clampLow
  b Object_ObjAnimAdvanceMove_wrapLowCheck
Object_ObjAnimAdvanceMove_wrapLow:
  lfs f0,0x9c(r3)
  fadds f0,f0,f2
  stfs f0,0x9c(r3)
Object_ObjAnimAdvanceMove_wrapLowCheck:
  lfs f0,0x9c(r3)
  fcmpo cr0,f0,f1
  blt Object_ObjAnimAdvanceMove_wrapLow
  b Object_ObjAnimAdvanceMove_setWrappedLow
Object_ObjAnimAdvanceMove_clampLow:
  stfs f1,0x9c(r3)
Object_ObjAnimAdvanceMove_setWrappedLow:
  li r0,1
Object_ObjAnimAdvanceMove_events:
  cmplwi r4,0
  bne Object_ObjAnimAdvanceMove_hasEventList
  mr r3,r0
  b Object_ObjAnimAdvanceMove_done
Object_ObjAnimAdvanceMove_hasEventList:
  li r6,0
  stb r6,0x12(r4)
  lwz r5,0x60(r3)
  cmplwi r5,0
  beq Object_ObjAnimAdvanceMove_returnWrapped
  stb r6,0x1b(r4)
  lwz r5,0x60(r3)
  lwz r5,0(r5)
  srawi r6,r5,1
  cmpwi r6,0
  beq Object_ObjAnimAdvanceMove_returnWrapped
  lfs f1,gObjAnimEventFrameScale
  fmuls f0,f1,f3
  fctiwz f0,f0
  stfd f0,0x30(r1)
  lwz r8,0x34(r1)
  lfs f0,0x9c(r3)
  fmuls f0,f1,f0
  fctiwz f0,f0
  stfd f0,0x28(r1)
  lwz r9,0x2c(r1)
  li r10,0
  cmpw r9,r8
  bge Object_ObjAnimAdvanceMove_checkReverse
  ori r10,r10,1
Object_ObjAnimAdvanceMove_checkReverse:
  lfs f0,gObjAnimProgressZero
  fcmpo cr0,f4,f0
  bge Object_ObjAnimAdvanceMove_scanSetup
  ori r10,r10,2
Object_ObjAnimAdvanceMove_scanSetup:
  li r7,0
  li r5,0
  b Object_ObjAnimAdvanceMove_scanTest
Object_ObjAnimAdvanceMove_scanLoop:
  lwz r11,0x60(r3)
  lwz r11,4(r11)
  lhax r11,r11,r5
  clrlwi r29,r11,23
  rlwinm r30,r11,23,25,31
  cmpwi r30,0x7f
  beq Object_ObjAnimAdvanceMove_nextEvent
  cmpwi r10,0
  bne Object_ObjAnimAdvanceMove_scanWrapped
  cmpw r29,r8
  blt Object_ObjAnimAdvanceMove_scanWrapped
  cmpw r29,r9
  bge Object_ObjAnimAdvanceMove_scanWrapped
  extsb r31,r30
  lbz r12,0x1b(r4)
  addi r11,r12,1
  stb r11,0x1b(r4)
  extsb r11,r12
  addi r11,r11,0x13
  stbx r31,r4,r11
Object_ObjAnimAdvanceMove_scanWrapped:
  cmpwi r10,1
  bne Object_ObjAnimAdvanceMove_scanReverseWrapped
  cmpw r29,r8
  bge Object_ObjAnimAdvanceMove_emitWrapped
  cmpw r29,r9
  bge Object_ObjAnimAdvanceMove_scanReverseWrapped
Object_ObjAnimAdvanceMove_emitWrapped:
  extsb r31,r30
  lbz r12,0x1b(r4)
  addi r11,r12,1
  stb r11,0x1b(r4)
  extsb r11,r12
  addi r11,r11,0x13
  stbx r31,r4,r11
Object_ObjAnimAdvanceMove_scanReverseWrapped:
  cmpwi r10,3
  bne Object_ObjAnimAdvanceMove_scanReverse
  cmpw r29,r9
  ble Object_ObjAnimAdvanceMove_scanReverse
  cmpw r29,r8
  bgt Object_ObjAnimAdvanceMove_scanReverse
  extsb r31,r30
  lbz r12,0x1b(r4)
  addi r11,r12,1
  stb r11,0x1b(r4)
  extsb r11,r12
  addi r11,r11,0x13
  stbx r31,r4,r11
Object_ObjAnimAdvanceMove_scanReverse:
  cmpwi r10,2
  bne Object_ObjAnimAdvanceMove_nextEvent
  cmpw r29,r9
  bgt Object_ObjAnimAdvanceMove_emitReverse
  cmpw r29,r8
  bgt Object_ObjAnimAdvanceMove_nextEvent
Object_ObjAnimAdvanceMove_emitReverse:
  extsb r31,r30
  lbz r12,0x1b(r4)
  addi r11,r12,1
  stb r11,0x1b(r4)
  extsb r11,r12
  addi r11,r11,0x13
  stbx r31,r4,r11
Object_ObjAnimAdvanceMove_nextEvent:
  addi r5,r5,2
  addi r7,r7,1
Object_ObjAnimAdvanceMove_scanTest:
  cmpw r7,r6
  bge Object_ObjAnimAdvanceMove_returnWrapped
  lbz r11,0x1b(r4)
  extsb r11,r11
  cmpwi r11,8
  blt Object_ObjAnimAdvanceMove_scanLoop
Object_ObjAnimAdvanceMove_returnWrapped:
  mr r3,r0
Object_ObjAnimAdvanceMove_done:
  lwz r31,0x4c(r1)
  lwz r30,0x48(r1)
  lwz r29,0x44(r1)
  addi r1,r1,0x50
  blr
}

/*
 * --INFO--
 *
 * Function: Object_ObjAnimSetMoveProgress
 * EN v1.0 Address: 0x8002F20C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x8002F304
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int Object_ObjAnimSetMoveProgress(f32 moveProgress,ObjAnimComponent *objAnim)
{
  if (moveProgress > lbl_803DE908) {
    moveProgress = lbl_803DE908;
  }
  else if (moveProgress < gObjAnimProgressZero) {
    moveProgress = gObjAnimProgressZero;
  }
  objAnim->activeMoveProgress = moveProgress;
  return 0;
}

/*
 * --INFO--
 *
 * Function: Object_ObjAnimSetMove
 * EN v1.0 Address: 0x8002F23C
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x8002F334
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int
Object_ObjAnimSetMove(f32 moveProgress,int objAnimArg,int moveId,int flags)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
  short previousMove;
  u8 moveChanged;
  int frameStep;
  ObjAnimMoveData *moveData;
  float eventStepFrames;
  objAnim = (ObjAnimComponent *)objAnimArg;
  if (moveProgress > gObjAnimProgressOne) {
    moveProgress = gObjAnimProgressOne;
  }
  else if (moveProgress < gObjAnimProgressZero) {
    moveProgress = gObjAnimProgressZero;
  }
  objAnim->activeMoveProgress = moveProgress;
  bank = ObjAnim_GetActiveBank(objAnim);
  animDef = bank->animDef;
  if (animDef->moveCount == 0) {
    return 0;
  }
  state = bank->activeState;
  state->flags = (s8)flags;
  state->prevMoveCacheSlot = state->moveCacheSlot;
  state->progress = state->speed;
  state->prevSegmentLength = state->segmentLength;
  state->savedStep = state->step;
  state->prevFrameData = state->frameData;
  state->prevFrameType = state->frameType;
  state->prevBlendCacheSlot = state->blendCacheSlot;
  state->prevFrameCmd = state->frameCmd;
  state->prevEventState = state->eventState;
  state->eventState = 0;
  state->lastBlendMoveIndex = OBJANIM_BLEND_MOVE_INDEX_INVALID;
  previousMove = objAnim->activeMove;
  moveChanged = previousMove != moveId;
  objAnim->activeMove = (s16)moveId;
  moveId = ObjAnim_ResolveMoveIndex(animDef,moveId);
  if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0) {
    if (moveChanged != 0) {
      state->blendToggle = OBJANIM_MOVE_CACHE_SLOT_COUNT - 1 - state->blendToggle;
      state->moveCacheSlot = (u16)state->blendToggle;
      if (animDef->cachedAnimIds[moveId] == OBJANIM_MISSING_MOVE_ID) {
        OSReport(gObjAnimSetBlendMoveMissingAnimWarning,animDef->modNo);
        moveId = 0;
      }
      ObjAnim_LoadCachedMove((int)animDef->cachedAnimIds[moveId],(int)(s16)moveId,
                             state->moveCache[state->moveCacheSlot],animDef);
    }
    moveData =
        (ObjAnimMoveData *)(state->moveCache[state->moveCacheSlot] +
                            OBJANIM_CACHED_MOVE_DATA_OFFSET);
  }
  else {
    state->moveCacheSlot = (u16)moveId;
    moveData = (ObjAnimMoveData *)animDef->moveData[state->moveCacheSlot];
  }
  state->frameData = moveData->frameCmd;
  state->frameType = moveData->frameInfo & OBJANIM_FRAME_TYPE_MASK;
  state->segmentLength = (float)state->frameData[1];
  if (state->frameType == OBJANIM_FRAME_TYPE_CLAMPED) {
    state->segmentLength = state->segmentLength - gObjAnimProgressOne;
  }
  frameStep = moveData->frameInfo & OBJANIM_FRAME_STEP_MASK;
  if (frameStep != 0) {
    state->savedStep = state->step;
    eventStepFrames = gObjAnimEventStepScale / (float)frameStep;
    state->eventStep = eventStepFrames;
    state->eventCountdown = OBJANIM_EVENT_COUNTDOWN_RESET;
  }
  state->step = gObjAnimProgressZero;
  state->speed = moveProgress * state->segmentLength;
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjAnim_GetCurrentEventCountdown
 * EN v1.0 Address: 0x8002F50C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8002F604
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
u16 ObjAnim_GetCurrentEventCountdown(ObjAnimComponent *objAnim)
{
  return ObjAnim_GetCurrentState(objAnim)->eventCountdown;
}

/*
 * --INFO--
 *
 * Function: ObjAnim_WriteStateWord
 * EN v1.0 Address: 0x8002F52C
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x8002F624
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjAnim_WriteStateWord(ObjAnimComponent *objAnim,int stateIndex,short wordIndex,int value)
{
  ObjAnimBank *bank;
  ObjAnimState *state;
  u16 stateWord;

  bank = ObjAnim_GetActiveBank(objAnim);
  if (bank == (ObjAnimBank *)0x0) {
    return;
  }
  stateWord = value;
  if (stateIndex != 0) {
    state = bank->activeState;
  }
  else {
    state = bank->currentState;
  }
  state = (ObjAnimState *)((u8 *)state + wordIndex * 2);
  state->eventCountdown = stateWord;
}

/*
 * --INFO--
 *
 * Function: ObjAnim_SetCurrentEventStepFrames
 * EN v1.0 Address: 0x8002F574
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x8002F66C
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjAnim_SetCurrentEventStepFrames(ObjAnimComponent *objAnim,uint frameCount)
{
  ObjAnimBank *bank;
  float eventStepFrames;

  bank = ObjAnim_GetActiveBank(objAnim);
  if (bank != (ObjAnimBank *)0x0) {
    eventStepFrames = gObjAnimEventStepScale / (float)(s32)frameCount;
    bank->currentState->eventStep = eventStepFrames;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjAnim_SampleRootCurvePhase
 * EN v1.0 Address: 0x8002F5D4
 * EN v1.0 Size: 1140b
 * EN v1.1 Address: 0x8002F6CC
 * EN v1.1 Size: 1140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
asm int ObjAnim_SampleRootCurvePhase(f32 distance,ObjAnimComponent *objAnim,float *phaseOut)
{
  nofralloc
  stwu r1, -0x30(r1)
  lwz r5, 0x7c(r3)
  lbz r0, 0xad(r3)
  extsb r0, r0
  slwi r0, r0, 2
  lwzx r5, r5, r0
  lwz r7, 0x0(r5)
  lhz r0, 0xec(r7)
  cmplwi r0, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F604
  li r3, 0x0
  b ObjAnim_SampleRootCurvePhase_L_8002FA40
ObjAnim_SampleRootCurvePhase_L_8002F604:
  lwz r8, 0x2c(r5)
  lfs f3, 0x8(r3)
  lwz r5, 0x50(r3)
  lfs f0, 0x4(r5)
  fdivs f0, f3, f0
  fmuls f2, f1, f0
  li r6, 0x0
  lhz r0, 0x5a(r8)
  cmplwi r0, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F6E4
  lfd f1, gObjAnimU32ToDoubleBias
  stw r0, 0xc(r1)
  lis r0, 0x4330
  stw r0, 0x8(r1)
  lfd f0, 0x8(r1)
  fsubs f1, f0, f1
  lfs f0, gObjAnimEventStepScale
  fdivs f7, f1, f0
  lfs f0, gObjAnimProgressOne
  fsubs f8, f0, f7
  lhz r0, 0x2(r7)
  rlwinm r0, r0, 0, 25, 25
  cmpwi r0, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F67C
  lhz r0, 0x48(r8)
  slwi r0, r0, 2
  add r5, r8, r0
  lwz r5, 0x24(r5)
  addi r5, r5, 0x80
  b ObjAnim_SampleRootCurvePhase_L_8002F68C
ObjAnim_SampleRootCurvePhase_L_8002F67C:
  lwz r5, 0x64(r7)
  lhz r0, 0x48(r8)
  slwi r0, r0, 2
  lwzx r5, r5, r0
ObjAnim_SampleRootCurvePhase_L_8002F68C:
  lha r0, 0x4(r5)
  cmpwi r0, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F6E4
  add r6, r5, r0
  lfs f0, 0x0(r6)
  fmuls f6, f0, f3
  addi r6, r6, 0x6
  lha r0, 0x0(r6)
  cmpwi r0, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F6D8
  addi r6, r6, 0x2
  lha r0, 0x0(r6)
  cmpwi r0, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F6D8
  addi r6, r6, 0x2
  lha r0, 0x0(r6)
  cmpwi r0, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F6D8
  li r6, 0x0
ObjAnim_SampleRootCurvePhase_L_8002F6D8:
  cmplwi r6, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F6E4
  addi r6, r6, 0x2
ObjAnim_SampleRootCurvePhase_L_8002F6E4:
  lhz r0, 0x2(r7)
  rlwinm r0, r0, 0, 25, 25
  cmpwi r0, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F70C
  lhz r0, 0x44(r8)
  slwi r0, r0, 2
  add r5, r8, r0
  lwz r5, 0x1c(r5)
  addi r5, r5, 0x80
  b ObjAnim_SampleRootCurvePhase_L_8002F71C
ObjAnim_SampleRootCurvePhase_L_8002F70C:
  lwz r5, 0x64(r7)
  lhz r0, 0x44(r8)
  slwi r0, r0, 2
  lwzx r5, r5, r0
ObjAnim_SampleRootCurvePhase_L_8002F71C:
  lha r0, 0x4(r5)
  cmpwi r0, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002FA3C
  add r5, r5, r0
  lfs f0, 0x0(r5)
  fmuls f5, f0, f3
  lha r7, 0x4(r5)
  subi r0, r7, 0x1
  addi r5, r5, 0x6
  li r8, 0x0
  lha r7, 0x0(r5)
  cmpwi r7, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F754
  li r8, 0x1
ObjAnim_SampleRootCurvePhase_L_8002F754:
  cmpwi r7, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F760
  addi r5, r5, 0x2
ObjAnim_SampleRootCurvePhase_L_8002F760:
  cmpwi r8, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F778
  lha r7, 0x0(r5)
  cmpwi r7, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F778
  addi r5, r5, 0x2
ObjAnim_SampleRootCurvePhase_L_8002F778:
  lha r7, 0x0(r5)
  cmpwi r7, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002FA3C
  slwi r8, r0, 1
  add r7, r5, r8
  lha r7, 0x2(r7)
  cmpwi r7, 0x0
  bge ObjAnim_SampleRootCurvePhase_L_8002F79C
  fneg f5, f5
ObjAnim_SampleRootCurvePhase_L_8002F79C:
  cmpwi r7, 0x0
  bne ObjAnim_SampleRootCurvePhase_L_8002F7AC
  li r3, 0x0
  b ObjAnim_SampleRootCurvePhase_L_8002FA40
ObjAnim_SampleRootCurvePhase_L_8002F7AC:
  lfd f3, gObjAnimS32ToDoubleBias
  xoris r7, r0, 0x8000
  stw r7, 0xc(r1)
  lis r9, 0x4330
  stw r9, 0x8(r1)
  lfd f0, 0x8(r1)
  fsubs f1, f0, f3
  lfs f0, gObjAnimProgressOne
  fdivs f4, f0, f1
  lfs f0, 0x98(r3)
  fmuls f1, f1, f0
  fctiwz f0, f1
  stfd f0, 0x10(r1)
  lwz r3, 0x14(r1)
  xoris r7, r3, 0x8000
  stw r7, 0x1c(r1)
  stw r9, 0x18(r1)
  lfd f0, 0x18(r1)
  fsubs f0, f0, f3
  fsubs f10, f1, f0
  cmplwi r6, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F8AC
  lhax r7, r6, r8
  cmpwi r7, 0x0
  bge ObjAnim_SampleRootCurvePhase_L_8002F814
  fneg f6, f6
ObjAnim_SampleRootCurvePhase_L_8002F814:
  slwi r10, r3, 1
  add r9, r5, r10
  lha r7, 0x2(r9)
  lfd f9, gObjAnimS32ToDoubleBias
  xoris r7, r7, 0x8000
  stw r7, 0x1c(r1)
  lis r8, 0x4330
  stw r8, 0x18(r1)
  lfd f0, 0x18(r1)
  fsubs f0, f0, f9
  fmuls f0, f8, f0
  fmuls f0, f5, f0
  lhax r7, r6, r10
  xoris r7, r7, 0x8000
  stw r7, 0x14(r1)
  stw r8, 0x10(r1)
  lfd f1, 0x10(r1)
  fsubs f1, f1, f9
  fmuls f1, f7, f1
  fmadds f0, f6, f1, f0
  lha r7, 0x4(r9)
  xoris r7, r7, 0x8000
  stw r7, 0xc(r1)
  stw r8, 0x8(r1)
  lfd f1, 0x8(r1)
  fsubs f1, f1, f9
  fmuls f1, f8, f1
  fmuls f1, f5, f1
  add r7, r6, r10
  lha r7, 0x2(r7)
  xoris r7, r7, 0x8000
  stw r7, 0x24(r1)
  stw r8, 0x20(r1)
  lfd f3, 0x20(r1)
  fsubs f3, f3, f9
  fmuls f3, f7, f3
  fmadds f1, f6, f3, f1
  b ObjAnim_SampleRootCurvePhase_L_8002F8EC
ObjAnim_SampleRootCurvePhase_L_8002F8AC:
  slwi r7, r3, 1
  add r8, r5, r7
  lha r7, 0x2(r8)
  xoris r7, r7, 0x8000
  stw r7, 0x24(r1)
  stw r9, 0x20(r1)
  lfd f0, 0x20(r1)
  fsubs f0, f0, f3
  fmuls f0, f5, f0
  lha r7, 0x4(r8)
  xoris r7, r7, 0x8000
  stw r7, 0x1c(r1)
  stw r9, 0x18(r1)
  lfd f1, 0x18(r1)
  fsubs f1, f1, f3
  fmuls f1, f5, f1
ObjAnim_SampleRootCurvePhase_L_8002F8EC:
  fsubs f3, f1, f0
  fmadds f3, f10, f3, f0
  fadds f2, f2, f3
  fnmsubs f3, f4, f10, f4
  li r11, 0x0
ObjAnim_SampleRootCurvePhase_L_8002F900:
  fcmpo cr0, f1, f2
  ble ObjAnim_SampleRootCurvePhase_L_8002F924
  fsubs f9, f1, f2
  fmuls f10, f4, f9
  fsubs f9, f1, f0
  fdivs f9, f10, f9
  fsubs f3, f3, f9
  li r11, 0x1
  b ObjAnim_SampleRootCurvePhase_L_8002FA20
ObjAnim_SampleRootCurvePhase_L_8002F924:
  addi r3, r3, 0x1
  cmpw r3, r0
  blt ObjAnim_SampleRootCurvePhase_L_8002F934
  li r3, 0x0
ObjAnim_SampleRootCurvePhase_L_8002F934:
  fmr f0, f1
  cmplwi r6, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F9D4
  slwi r9, r3, 1
  add r10, r5, r9
  lha r7, 0x4(r10)
  lfd f12, gObjAnimS32ToDoubleBias
  xoris r7, r7, 0x8000
  stw r7, 0x24(r1)
  lis r8, 0x4330
  stw r8, 0x20(r1)
  lfd f9, 0x20(r1)
  fsubs f10, f9, f12
  lha r7, 0x2(r10)
  xoris r7, r7, 0x8000
  stw r7, 0x1c(r1)
  stw r8, 0x18(r1)
  lfd f9, 0x18(r1)
  fsubs f9, f9, f12
  fsubs f9, f10, f9
  fmuls f11, f5, f9
  add r9, r6, r9
  lha r7, 0x2(r9)
  xoris r7, r7, 0x8000
  stw r7, 0x14(r1)
  stw r8, 0x10(r1)
  lfd f9, 0x10(r1)
  fsubs f10, f9, f12
  lha r7, 0x0(r9)
  xoris r7, r7, 0x8000
  stw r7, 0xc(r1)
  stw r8, 0x8(r1)
  lfd f9, 0x8(r1)
  fsubs f9, f9, f12
  fsubs f9, f10, f9
  fmuls f9, f6, f9
  fmuls f9, f9, f7
  fmadds f9, f11, f8, f9
  fadds f1, f1, f9
  b ObjAnim_SampleRootCurvePhase_L_8002FA1C
ObjAnim_SampleRootCurvePhase_L_8002F9D4:
  slwi r7, r3, 1
  add r9, r5, r7
  lha r7, 0x4(r9)
  lfd f11, gObjAnimS32ToDoubleBias
  xoris r7, r7, 0x8000
  stw r7, 0x24(r1)
  lis r8, 0x4330
  stw r8, 0x20(r1)
  lfd f9, 0x20(r1)
  fsubs f10, f9, f11
  lha r7, 0x2(r9)
  xoris r7, r7, 0x8000
  stw r7, 0x1c(r1)
  stw r8, 0x18(r1)
  lfd f9, 0x18(r1)
  fsubs f9, f9, f11
  fsubs f9, f10, f9
  fmadds f1, f5, f9, f1
ObjAnim_SampleRootCurvePhase_L_8002FA1C:
  fadds f3, f3, f4
ObjAnim_SampleRootCurvePhase_L_8002FA20:
  cmpwi r11, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002F900
  cmplwi r4, 0x0
  beq ObjAnim_SampleRootCurvePhase_L_8002FA34
  stfs f3, 0x0(r4)
ObjAnim_SampleRootCurvePhase_L_8002FA34:
  li r3, 0x1
  b ObjAnim_SampleRootCurvePhase_L_8002FA40
ObjAnim_SampleRootCurvePhase_L_8002FA3C:
  li r3, 0x0
ObjAnim_SampleRootCurvePhase_L_8002FA40:
  addi r1, r1, 0x30
  blr
}

/*
 * --INFO--
 *
 * Function: ObjAnim_AdvanceCurrentMove
 * EN v1.0 Address: 0x8002FA48
 * EN v1.0 Size: 2236b
 * EN v1.1 Address: 0x8002FB40
 * EN v1.1 Size: 2236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int ObjAnim_AdvanceCurrentMove(f32 moveStepScale,f32 deltaTime,int objAnimArg,
                               ObjAnimEventList *events)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
  double dVar1;
  char cVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  uint uVar15;
  uint uVar16;
  undefined uVar17;
  undefined4 uVar18;
  int iVar21;
  int iVar23;
  int iVar24;
  int iVar25;
  int iVar26;
  float *pfVar27;
  short *axisSamples;
  byte eventScanFlags;
  int iVar30;
  double dVar31;
  undefined8 local_48;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_20;
  ObjAnimEventList *eventList;
  float *rootDeltaOut;

  eventList = events;
  rootDeltaOut = (float *)events;
  dVar31 = (double)lbl_803DE90C;
  uVar18 = 0;
  if ((dVar31 <= moveStepScale) &&
     (dVar31 = moveStepScale, (double)gObjAnimProgressOne < moveStepScale)) {
    dVar31 = (double)gObjAnimProgressOne;
  }
  objAnim = (ObjAnimComponent *)objAnimArg;
  bank = ObjAnim_GetActiveBank(objAnim);
  animDef = bank->animDef;
  if ((animDef->moveCount != 0) &&
     (state = bank->currentState, iVar24 = (int)state, iVar24 != 0)) {
    state->step = (float)(dVar31 * (double)state->segmentLength);
    if (state->eventCountdown != 0) {
      if ((state->flags & OBJANIM_STATE_FLAG_REFRESH_SAVED_STEP) != 0) {
        state->savedStep = state->step;
      }
      state->progress =
           (float)((double)state->savedStep * deltaTime + (double)state->progress);
      fVar4 = gObjAnimProgressZero;
      fVar3 = state->prevSegmentLength;
      if (state->prevFrameType != OBJANIM_FRAME_TYPE_CLAMPED) {
        if (state->progress < gObjAnimProgressZero) {
          while (state->progress < fVar4) {
            state->progress = state->progress + fVar3;
          }
        }
        if (fVar3 <= state->progress) {
          while (fVar3 <= state->progress) {
            state->progress = state->progress - fVar3;
          }
        }
      }
      else {
        fVar4 = state->progress;
        fVar5 = gObjAnimProgressZero;
        if ((gObjAnimProgressZero <= fVar4) && (fVar5 = fVar4, fVar3 < fVar4)) {
          fVar5 = fVar3;
        }
        state->progress = fVar5;
      }
      if ((state->flags & OBJANIM_STATE_FLAG_HOLD_EVENT_COUNTDOWN) == 0) {
        uVar15 = (uint)-(float)((ObjAnim_U32AsDouble(state->eventStep) - gObjAnimU32ToDoubleBias) *
                                    deltaTime -
                                (ObjAnim_U32AsDouble(state->eventCountdown ^
                                                     OBJANIM_S32_DOUBLE_BIAS_XOR) -
                                 gObjAnimS32ToDoubleBias));
        fVar3 = gObjAnimProgressZero;
        if ((-1 < (int)uVar15) &&
           (uVar15 = uVar15 ^ OBJANIM_S32_DOUBLE_BIAS_XOR, fVar3 = gObjAnimEventStepScale,
           (float)((double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,uVar15) - gObjAnimS32ToDoubleBias) <= gObjAnimEventStepScale)) {
          local_38 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,uVar15);
          fVar3 = (float)(local_38 - gObjAnimS32ToDoubleBias);
        }
        state->eventCountdown = (short)(int)fVar3;
      }
      if (state->eventCountdown == 0) {
        state->prevEventState = 0;
      }
    }
    fVar4 = objAnim->currentMoveProgress;
    fVar3 = (float)(dVar31 * deltaTime);
    objAnim->currentMoveProgress = fVar4 + fVar3;
    fVar6 = gObjAnimProgressZero;
    fVar5 = gObjAnimProgressOne;
    if (objAnim->currentMoveProgress >= gObjAnimProgressOne) {
      if (state->frameType == OBJANIM_FRAME_TYPE_CLAMPED) {
        objAnim->currentMoveProgress = gObjAnimProgressOne;
      }
      else {
        while (fVar5 <= objAnim->currentMoveProgress) {
          objAnim->currentMoveProgress = objAnim->currentMoveProgress - fVar5;
        }
      }
      uVar18 = 1;
    }
    else if (objAnim->currentMoveProgress < gObjAnimProgressZero) {
      if (state->frameType == OBJANIM_FRAME_TYPE_CLAMPED) {
        objAnim->currentMoveProgress = gObjAnimProgressZero;
      }
      else {
        while (objAnim->currentMoveProgress < fVar6) {
          objAnim->currentMoveProgress = objAnim->currentMoveProgress + fVar5;
        }
      }
      uVar18 = 1;
    }
    if (eventList != (ObjAnimEventList *)0x0) {
      eventList->rootCurveValid = 0;
      fVar5 = gObjAnimProgressZero;
      eventList->rootDeltaZ = gObjAnimProgressZero;
      eventList->rootDeltaY = fVar5;
      eventList->rootDeltaX = fVar5;
      if (objAnim->eventTable != (ObjAnimEventTable *)0x0) {
        eventList->triggerCount = 0;
        iVar23 = objAnim->eventTable->byteCount >> 1;
        if (iVar23 != 0) {
          iVar30 = (int)(gObjAnimEventFrameScale * fVar4);
          iVar26 = (int)(gObjAnimEventFrameScale * objAnim->currentMoveProgress);
          eventScanFlags = iVar26 < iVar30;
          if (fVar3 < gObjAnimProgressZero) {
            eventScanFlags = eventScanFlags | 2;
          }
          iVar25 = 0;
          iVar21 = 0;
          while ((iVar25 < iVar23 &&
                  (eventList->triggerCount < OBJANIM_EVENT_TRIGGER_CAPACITY))) {
            uVar16 = (uint)*(short *)((u8 *)objAnim->eventTable->entries + iVar21);
            uVar15 = uVar16 & OBJANIM_EVENT_FRAME_MASK;
            uVar16 = uVar16 >> OBJANIM_EVENT_ID_SHIFT & OBJANIM_EVENT_ID_MASK;
            if (uVar16 != OBJANIM_EVENT_ID_NONE) {
              uVar17 = (undefined)uVar16;
              if (((eventScanFlags == OBJANIM_EVENT_SCAN_FORWARD) && (iVar30 <= (int)uVar15)) &&
                  ((int)uVar15 < iVar26)) {
                cVar2 = eventList->triggerCount;
                eventList->triggerCount = cVar2 + '\x01';
                eventList->triggeredIds[(u8)cVar2] = uVar17;
              }
              if ((eventScanFlags == OBJANIM_EVENT_SCAN_WRAPPED) &&
                  ((iVar30 <= (int)uVar15 || ((int)uVar15 < iVar26)))) {
                cVar2 = eventList->triggerCount;
                eventList->triggerCount = cVar2 + '\x01';
                eventList->triggeredIds[(u8)cVar2] = uVar17;
              }
              if (((eventScanFlags == OBJANIM_EVENT_SCAN_REVERSE_WRAPPED) &&
                  (iVar26 < (int)uVar15)) && ((int)uVar15 <= iVar30)) {
                cVar2 = eventList->triggerCount;
                eventList->triggerCount = cVar2 + '\x01';
                eventList->triggeredIds[(u8)cVar2] = uVar17;
              }
              if ((eventScanFlags == OBJANIM_EVENT_SCAN_REVERSE) &&
                  ((iVar26 < (int)uVar15 || ((int)uVar15 <= iVar30)))) {
                cVar2 = eventList->triggerCount;
                eventList->triggerCount = cVar2 + '\x01';
                eventList->triggeredIds[(u8)cVar2] = uVar17;
              }
            }
            iVar21 = iVar21 + 2;
            iVar25 = iVar25 + 1;
          }
        }
      }
      if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) == 0) {
        iVar23 = (int)animDef->moveData[state->moveCacheSlot];
      }
      else {
        iVar23 = (int)state->moveCache[state->moveCacheSlot] + OBJANIM_CACHED_MOVE_DATA_OFFSET;
      }
      if (*(short *)(iVar23 + OBJANIM_MOVE_ROOT_CURVE_OFFSET) == 0) {
        eventList->rootCurveValid = 0;
      }
      else {
        eventList->rootCurveValid = 1;
        pfVar27 = (float *)(iVar23 + *(short *)(iVar23 + OBJANIM_MOVE_ROOT_CURVE_OFFSET));
        fVar5 = *pfVar27;
        fVar6 = objAnim->rootMotionScale;
        iVar23 = (int)*(short *)(pfVar27 + 1);
        axisSamples = (short *)((int)pfVar27 + OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET);
        local_30 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,iVar23 - 1U ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
        fVar7 = (float)(local_30 - gObjAnimS32ToDoubleBias) * fVar4;
        uVar15 = (uint)fVar7;
        dVar31 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,uVar15 ^ OBJANIM_S32_DOUBLE_BIAS_XOR) - gObjAnimS32ToDoubleBias;
        fVar8 = (float)(local_30 - gObjAnimS32ToDoubleBias) * objAnim->currentMoveProgress;
        uVar16 = (uint)fVar8;
        dVar1 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,uVar16 ^ OBJANIM_S32_DOUBLE_BIAS_XOR) - gObjAnimS32ToDoubleBias;
        iVar30 = 0;
        fVar11 = gObjAnimProgressZero;
        fVar13 = gObjAnimProgressOne;
        if (state->eventState != 0) {
          local_30 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,(uint)state->eventState);
          fVar11 = (float)(local_30 - gObjAnimU32ToDoubleBias) / gObjAnimEventStepScale;
          if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) == 0) {
            iVar24 = (int)animDef->moveData[state->blendCacheSlot];
          }
          else {
            iVar24 = (int)state->blendMoveCache[state->blendCacheSlot] +
                     OBJANIM_CACHED_MOVE_DATA_OFFSET;
          }
          iVar30 = iVar24 + *(short *)(iVar24 + OBJANIM_MOVE_ROOT_CURVE_OFFSET) +
                   OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET;
          fVar13 = gObjAnimProgressOne - fVar11;
        }
        iVar26 = 0;
        iVar24 = (iVar23 - 1U) * 2;
        pfVar27 = rootDeltaOut;
        do {
          if (*axisSamples == 0) {
            axisSamples = axisSamples + 1;
            if (iVar30 != 0) {
              iVar30 = iVar30 + 2;
            }
            if (iVar26 < OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT) {
              *rootDeltaOut = gObjAnimProgressZero;
            }
            else {
              *(undefined2 *)((int)pfVar27 + 6) = 0;
            }
          }
          else {
            if (iVar30 != 0) {
              iVar30 = iVar30 + 2;
            }
            local_30 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,(int)axisSamples[uVar15 + 1] ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
            fVar9 = fVar13 * (float)(local_30 - gObjAnimS32ToDoubleBias);
            if (iVar30 != 0) {
              local_38 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                          (int)*(short *)(uVar15 * 2 + iVar30) ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
              fVar9 = fVar11 * (float)(local_38 - gObjAnimS32ToDoubleBias) + fVar9;
            }
            fVar10 = fVar13 * (float)((double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                                       (int)(axisSamples + uVar15 + 1)[1] ^ OBJANIM_S32_DOUBLE_BIAS_XOR)
                                     - gObjAnimS32ToDoubleBias);
            if (iVar30 != 0) {
              local_48 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                          (int)*(short *)(uVar15 * 2 + iVar30 + 2) ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
              fVar10 = fVar11 * (float)(local_48 - gObjAnimS32ToDoubleBias) + fVar10;
            }
            fVar12 = fVar13 * (float)((double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                                       (int)axisSamples[uVar16 + 1] ^ OBJANIM_S32_DOUBLE_BIAS_XOR) -
                                     gObjAnimS32ToDoubleBias);
            if (iVar30 != 0) {
              fVar12 = fVar11 * (float)((double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                                         (int)*(short *)(uVar16 * 2 + iVar30) ^
                                                         OBJANIM_S32_DOUBLE_BIAS_XOR) - gObjAnimS32ToDoubleBias) + fVar12;
            }
            fVar14 = fVar13 * (float)((double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                                       (int)(axisSamples + uVar16 + 1)[1] ^ OBJANIM_S32_DOUBLE_BIAS_XOR)
                                     - gObjAnimS32ToDoubleBias);
            if (iVar30 != 0) {
              local_20 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                          (int)*(short *)(uVar16 * 2 + iVar30 + 2) ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
              fVar14 = fVar11 * (float)(local_20 - gObjAnimS32ToDoubleBias) + fVar14;
            }
            fVar12 = (fVar8 - (float)dVar1) * (fVar14 - fVar12) + fVar12;
            if (fVar3 <= gObjAnimProgressZero) {
              if (fVar4 < objAnim->currentMoveProgress) {
                local_20 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,(int)axisSamples[iVar23] ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
                fVar12 = -(fVar13 * (float)(local_20 - gObjAnimS32ToDoubleBias) - fVar12);
                if (iVar30 != 0) {
                  local_20 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,
                                              (int)*(short *)(iVar24 + iVar30) ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
                  fVar12 = fVar11 * (float)(local_20 - gObjAnimS32ToDoubleBias) + fVar12;
                }
              }
            }
            else if (objAnim->currentMoveProgress < fVar4) {
              local_20 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,(int)axisSamples[iVar23] ^ OBJANIM_S32_DOUBLE_BIAS_XOR);
              fVar12 = fVar13 * (float)(local_20 - gObjAnimS32ToDoubleBias) + fVar12;
              if (iVar30 != 0) {
                local_20 = (double)CONCAT44(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD,(int)*(short *)(iVar24 + iVar30) ^ OBJANIM_S32_DOUBLE_BIAS_XOR
                                           );
                fVar12 = fVar11 * (float)(local_20 - gObjAnimS32ToDoubleBias) + fVar12;
              }
            }
            fVar12 = fVar12 - ((fVar7 - (float)dVar31) * (fVar10 - fVar9) + fVar9);
            if (iVar26 < OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT) {
              *rootDeltaOut = fVar12 * fVar5 * fVar6;
            }
            else {
              *(short *)((int)pfVar27 + 6) = (short)(int)fVar12;
            }
            axisSamples = axisSamples + iVar23 + 1;
            if (iVar30 != 0) {
              iVar30 = iVar30 + iVar23 * 2;
            }
          }
          rootDeltaOut = rootDeltaOut + 1;
          pfVar27 = (float *)((int)pfVar27 + 2);
          iVar26 = iVar26 + 1;
        } while (iVar26 < OBJANIM_ROOT_CURVE_AXIS_COUNT);
      }
    }
  }
  return uVar18;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjAnim_SetMoveProgress
 * EN v1.0 Address: 0x80030304
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x800303FC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjAnim_SetMoveProgress(f32 moveProgress,ObjAnimComponent *objAnim)
{
  if (moveProgress > lbl_803DE908) {
    moveProgress = lbl_803DE908;
  }
  else if (moveProgress < gObjAnimProgressZero) {
    moveProgress = gObjAnimProgressZero;
  }
  objAnim->currentMoveProgress = moveProgress;
  return 0;
}

/*
 * --INFO--
 *
 * Function: ObjAnim_SetCurrentMove
 * EN v1.0 Address: 0x80030334
 * EN v1.0 Size: 852b
 * EN v1.1 Address: 0x8003042C
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int ObjAnim_SetCurrentMove(int objAnimArg,int moveId,f32 moveProgress,int flags)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
  s16 previousMove;
  u8 moveChanged;
  int requestedMoveId;
  int frameStep;
  ObjAnimMoveData *moveData;
  float eventStepFrames;
  ObjHitReactState *hitState;

  objAnim = (ObjAnimComponent *)objAnimArg;
  requestedMoveId = moveId;
  if (moveProgress > gObjAnimProgressOne) {
    moveProgress = gObjAnimProgressOne;
  }
  else if (moveProgress < gObjAnimProgressZero) {
    moveProgress = gObjAnimProgressZero;
  }
  objAnim->currentMoveProgress = moveProgress;
  bank = ObjAnim_GetActiveBank(objAnim);
  if (bank == (ObjAnimBank *)0x0) {
    return 0;
  }
  animDef = bank->animDef;
  if (animDef->moveCount == 0) {
    return 0;
  }
  state = bank->currentState;
  state->flags = (s8)flags;
  state->prevMoveCacheSlot = state->moveCacheSlot;
  state->progress = state->speed;
  state->prevSegmentLength = state->segmentLength;
  state->savedStep = state->step;
  state->prevFrameData = state->frameData;
  state->prevFrameType = state->frameType;
  state->prevBlendCacheSlot = state->blendCacheSlot;
  state->prevFrameCmd = state->frameCmd;
  state->prevEventState = state->eventState;
  state->eventState = 0;
  state->lastBlendMoveIndex = OBJANIM_BLEND_MOVE_INDEX_INVALID;
  hitState = objAnim->hitReactState;
  if ((hitState != (ObjHitReactState *)0x0) && (hitState->entries != (ObjHitReactEntry *)0x0)) {
    ObjHitReact_LoadMoveEntries(objAnimArg,bank,(int)objAnim->objType,hitState,requestedMoveId,0);
  }
  if (objAnim->eventTable != (ObjAnimEventTable *)0x0) {
    ObjAnim_LoadMoveEvents(objAnimArg,(int)objAnim->objType,objAnim->eventTable,requestedMoveId,0);
  }
  previousMove = objAnim->currentMove;
  moveChanged = previousMove != requestedMoveId;
  objAnim->currentMove = (s16)requestedMoveId;
  moveId =
      animDef->moveGroupBaseIndices[(s32)requestedMoveId >> OBJANIM_MOVE_GROUP_SHIFT] +
      (requestedMoveId & OBJANIM_MOVE_INDEX_MASK);
  if (moveId >= animDef->moveCount) {
    moveId = animDef->moveCount - 1;
  }
  if (moveId < 0) {
    moveId = 0;
  }
  if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0) {
    if (moveChanged != 0) {
      state->blendToggle = OBJANIM_MOVE_CACHE_SLOT_COUNT - 1 - state->blendToggle;
      state->moveCacheSlot = (u16)state->blendToggle;
      if (animDef->cachedAnimIds[moveId] == OBJANIM_MISSING_MOVE_ID) {
        OSReport(gObjAnimSetBlendMoveMissingAnimWarning,animDef->modNo);
        moveId = 0;
      }
      ObjAnim_LoadCachedMove((int)animDef->cachedAnimIds[moveId],(int)(s16)moveId,
                             state->moveCache[state->moveCacheSlot],animDef);
    }
    moveData =
        (ObjAnimMoveData *)(state->moveCache[state->moveCacheSlot] +
                            OBJANIM_CACHED_MOVE_DATA_OFFSET);
  }
  else {
    state->moveCacheSlot = (u16)moveId;
    moveData = (ObjAnimMoveData *)animDef->moveData[state->moveCacheSlot];
  }
  state->frameData = moveData->frameCmd;
  state->frameType = moveData->frameInfo & OBJANIM_FRAME_TYPE_MASK;
  state->segmentLength = (float)state->frameData[1];
  if (state->frameType == OBJANIM_FRAME_TYPE_CLAMPED) {
    state->segmentLength = state->segmentLength - gObjAnimProgressOne;
  }
  frameStep = moveData->frameInfo & OBJANIM_FRAME_STEP_MASK;
  if ((frameStep != 0) && (((u8)flags & OBJANIM_SET_MOVE_FLAG_SKIP_EVENT_COUNTDOWN) == 0)) {
    state->savedStep = state->step;
    eventStepFrames = gObjAnimEventStepScale / (float)frameStep;
    state->eventStep = eventStepFrames;
    state->eventCountdown = OBJANIM_EVENT_COUNTDOWN_RESET;
  }
  else {
    state->eventCountdown = 0;
  }
  state->step = gObjAnimProgressZero;
  state->speed = moveProgress * state->segmentLength;
  return 0;
}
#pragma peephole reset
#pragma scheduling reset
