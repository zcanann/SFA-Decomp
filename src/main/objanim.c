#include "ghidra_import.h"
#include "main/objanim.h"

extern undefined4 FUN_8001786c();
extern undefined4 FUN_800723a0();

extern f64 DOUBLE_803df568;
extern f64 DOUBLE_803df580;
extern f32 FLOAT_803df560;
extern f32 FLOAT_803df570;
extern f32 FLOAT_803df574;
extern f32 FLOAT_803df578;
extern f32 FLOAT_803df588;

/*
 * Shared state used by the object-animation helpers in this file.
 * Most names are descriptive placeholders, but the layout itself is stable
 * enough to stop repeating raw offsets everywhere.
 */
typedef struct ObjAnimDef {
  u8 pad00[2];
  u16 flags;
  u8 pad04[0x64 - 4];
  u8 **moveData;
  u8 pad68[4];
  s16 *blendMoveIds;
  u8 pad70[0xEC - 0x70];
  u16 moveCount;
} ObjAnimDef;

typedef struct ObjAnimState {
  u8 pad00[4];
  f32 speed;
  f32 progress;
  f32 step;
  f32 savedStep;
  f32 segmentLength;
  f32 prevSegmentLength;
  u8 *moveCache[2];
  u8 *blendMoveCache[2];
  u8 pad2c[8];
  u8 *frameData;
  u8 *prevFrameData;
  u8 *frameCmd;
  u8 *prevFrameCmd;
  u16 moveCacheSlot;
  u16 prevMoveCacheSlot;
  u16 blendCacheSlot;
  u16 prevBlendCacheSlot;
  u8 pad4c[0x58 - 0x4C];
  u16 eventCountdown;
  u16 eventState;
  u16 prevEventState;
  u16 eventStep;
  u8 frameType;
  u8 prevFrameType;
  s8 blendToggle;
  u8 flags;
  s16 lastBlendMoveIndex;
} ObjAnimState;

typedef struct ObjAnimBank {
  ObjAnimDef *animDef;
  u8 pad04[0x2C - 4];
  ObjAnimState *secondaryState;
  ObjAnimState *primaryState;
} ObjAnimBank;

typedef struct ObjAnimComponent {
  u8 pad00[0x60];
  void *eventTable;
  u8 pad64[0x7C - 0x64];
  ObjAnimBank **banks;
  u8 pad80[0x9C - 0x80];
  f32 moveProgress;
  u8 padA0[2];
  s16 activeMove;
  u8 padA4[0xAD - 0xA4];
  s8 bankIndex;
} ObjAnimComponent;

typedef struct ObjAnimEventList {
  u8 pad00[0x12];
  u8 resetFlag;
  u8 triggeredIds[8];
  u8 count;
} ObjAnimEventList;

static ObjAnimBank *ObjAnim_GetActiveBank(ObjAnimComponent *objAnim) {
  return objAnim->banks[objAnim->bankIndex];
}

static s16 *ObjAnim_GetMoveBaseTable(ObjAnimDef *animDef) {
  return (s16 *)((u8 *)animDef + 0x70);
}

static s32 ObjAnim_ResolveMoveIndex(ObjAnimDef *animDef, u32 moveId) {
  s32 moveIndex = ObjAnim_GetMoveBaseTable(animDef)[moveId >> 8] + (moveId & 0xFF);

  if ((u32)animDef->moveCount <= moveIndex) {
    moveIndex = animDef->moveCount - 1;
  }
  if (moveIndex < 0) {
    moveIndex = 0;
  }
  return moveIndex;
}

/*
 * --INFO--
 *
 * Function: ObjAnim_SetBlendMove
 * EN v1.0 Address: 0x8002EBA8
 * EN v1.0 Size: 540b
 * EN v1.1 Address: 0x8002EC4C
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjAnim_SetBlendMove(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                          undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                          undefined4 param_9,int param_10,int param_11,uint param_12,
                          undefined2 param_13)
{
  ObjAnimDef *animDef;
  ObjAnimState *state;
  float frameValue;
  uint frameType;
  int moveData;
  int moveIndex;
  
  animDef = (ObjAnimDef *)param_10;
  state = (ObjAnimState *)param_11;
  moveIndex = ObjAnim_ResolveMoveIndex(animDef, param_12);
  if ((animDef->flags & 0x40) == 0) {
    state->blendCacheSlot = (u16)moveIndex;
    moveData = (int)animDef->moveData[state->blendCacheSlot];
  }
  else {
    if (state->lastBlendMoveIndex != moveIndex) {
      state->blendCacheSlot = (u16)state->blendToggle;
      state->prevBlendCacheSlot = (u16)(1 - state->blendToggle);
      if (animDef->blendMoveIds[moveIndex] == -1) {
        param_1 = FUN_800723a0();
        moveIndex = 0;
      }
      FUN_8001786c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)animDef->blendMoveIds[moveIndex],(int)(s16)moveIndex,
                   (undefined4)state->blendMoveCache[state->blendCacheSlot],param_10);
      state->lastBlendMoveIndex = (s16)moveIndex;
    }
    moveData = (int)state->blendMoveCache[state->blendCacheSlot] + 0x80;
  }
  state->frameCmd = (u8 *)(moveData + 6);
  frameType = (uint)*(s8 *)(moveData + 1) & 0xf0;
  if (frameType == state->frameType) {
    frameValue = (float)((double)CONCAT44(0x43300000,(uint)state->frameCmd[1]) - DOUBLE_803df568);
    if (frameType == 0) {
      frameValue = frameValue - FLOAT_803df560;
    }
    if (frameValue == state->segmentLength) {
      state->eventState = param_13;
    }
    else {
      state->eventState = 0;
    }
  }
  else {
    state->eventState = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8002EE10
 * EN v1.0 Address: 0x8002EDC4
 * EN v1.0 Size: 568b
 * EN v1.1 Address: 0x8002EE10
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8002EE10(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,uint param_10,undefined2 param_11)
{
  ObjAnimBank *bank;
  
  bank = ObjAnim_GetActiveBank((ObjAnimComponent *)param_9);
  if (bank->animDef->moveCount != 0) {
    ObjAnim_SetBlendMove(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         (int)bank->animDef,(int)bank->primaryState,param_10,param_11);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8002EE64
 * EN v1.0 Address: 0x8002EFFC
 * EN v1.0 Size: 568b
 * EN v1.1 Address: 0x8002EE64
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8002EE64(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,uint param_10,undefined2 param_11)
{
  ObjAnimBank *bank;
  
  bank = ObjAnim_GetActiveBank((ObjAnimComponent *)param_9);
  if (bank->animDef->moveCount != 0) {
    ObjAnim_SetBlendMove(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         (int)bank->animDef,(int)bank->secondaryState,param_10,param_11);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8002EEB8
 * EN v1.0 Address: 0x8002F234
 * EN v1.0 Size: 1168b
 * EN v1.1 Address: 0x8002EEB8
 * EN v1.1 Size: 1100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 fn_8002EEB8(double param_1,double param_2,int param_3,int param_4)
{
  ObjAnimComponent *objAnim;
  ObjAnimEventList *events;
  ObjAnimBank *bank;
  ObjAnimState *state;
  int iVar1;
  int iVar2;
  char cVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  undefined4 uVar7;
  uint uVar8;
  int iVar9;
  int *piVar10;
  int iVar11;
  int iVar12;
  byte bVar13;
  uint uVar14;
  undefined uVar15;
  undefined8 local_28;
  
  objAnim = (ObjAnimComponent *)param_3;
  events = (ObjAnimEventList *)param_4;
  uVar7 = 0;
  bank = ObjAnim_GetActiveBank(objAnim);
  piVar10 = (int *)bank;
  if (bank->animDef->moveCount == 0) {
    uVar7 = 0;
  }
  else {
    state = bank->primaryState;
    iVar11 = (int)state;
    state->step = (float)(param_1 * (double)state->segmentLength);
    if (state->eventCountdown != 0) {
      if ((state->flags & 8) != 0) {
        state->savedStep = state->step;
      }
      state->progress = (float)((double)state->savedStep * param_2 + (double)state->progress);
      fVar5 = FLOAT_803df570;
      fVar4 = state->prevSegmentLength;
      if (state->prevFrameType == '\0') {
        fVar5 = state->progress;
        fVar6 = FLOAT_803df570;
        if ((FLOAT_803df570 <= fVar5) && (fVar6 = fVar5, fVar4 < fVar5)) {
          fVar6 = fVar4;
        }
        state->progress = fVar6;
      }
      else {
        if (state->progress < FLOAT_803df570) {
          while (state->progress < fVar5) {
            state->progress = state->progress + fVar4;
          }
        }
        if (fVar4 <= state->progress) {
          while (fVar4 <= state->progress) {
            state->progress = state->progress - fVar4;
          }
        }
      }
      if ((state->flags & 2) == 0) {
        uVar8 = (uint)-(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                (uint)state->eventStep) -
                                              DOUBLE_803df568) * param_2 -
                              (double)(float)((double)CONCAT44(0x43300000,
                                                               state->eventCountdown ^
                                                               0x80000000) - DOUBLE_803df580));
        fVar4 = FLOAT_803df570;
        if ((-1 < (int)uVar8) &&
           (uVar8 = uVar8 ^ 0x80000000, fVar4 = FLOAT_803df574,
           (float)((double)CONCAT44(0x43300000,uVar8) - DOUBLE_803df580) <= FLOAT_803df574)) {
          local_28 = (double)CONCAT44(0x43300000,uVar8);
          fVar4 = (float)(local_28 - DOUBLE_803df580);
        }
        state->eventCountdown = (u16)(int)fVar4;
      }
      if (state->eventCountdown == 0) {
        state->prevEventState = 0;
      }
    }
    fVar4 = objAnim->moveProgress;
    objAnim->moveProgress = fVar4 + (float)(param_1 * param_2);
    fVar6 = FLOAT_803df570;
    fVar5 = FLOAT_803df560;
    if (objAnim->moveProgress < FLOAT_803df560) {
      if (objAnim->moveProgress < FLOAT_803df570) {
        if (state->frameType == '\0') {
          objAnim->moveProgress = FLOAT_803df570;
        }
        else {
          while (objAnim->moveProgress < fVar6) {
            objAnim->moveProgress = objAnim->moveProgress + fVar5;
          }
        }
        uVar7 = 1;
      }
    }
    else {
      if (state->frameType == '\0') {
        objAnim->moveProgress = FLOAT_803df560;
      }
      else {
        while (fVar5 <= objAnim->moveProgress) {
          objAnim->moveProgress = objAnim->moveProgress - fVar5;
        }
      }
      uVar7 = 1;
    }
    if ((events != (ObjAnimEventList *)0) && (events->resetFlag = 0, objAnim->eventTable != 0)) {
      events->count = 0;
      iVar11 = **(int **)objAnim->eventTable >> 1;
      if (iVar11 != 0) {
        iVar1 = (int)(FLOAT_803df578 * fVar4);
        iVar2 = (int)(FLOAT_803df578 * objAnim->moveProgress);
        bVar13 = iVar2 < iVar1;
        if ((float)(param_1 * param_2) < FLOAT_803df570) {
          bVar13 = bVar13 | 2;
        }
        iVar12 = 0;
        iVar9 = 0;
        while ((iVar12 < iVar11 && (events->count < 8))) {
          uVar14 = (uint)*(short *)(*(int *)(*(int *)objAnim->eventTable + 4) + iVar9);
          uVar8 = uVar14 & 0x1ff;
          uVar14 = uVar14 >> 9 & 0x7f;
          if (uVar14 != 0x7f) {
            uVar15 = (undefined)uVar14;
            if (((bVar13 == 0) && (iVar1 <= (int)uVar8)) && ((int)uVar8 < iVar2)) {
              cVar3 = events->count;
              events->count = cVar3 + '\x01';
              events->triggeredIds[(u8)cVar3] = uVar15;
            }
            if ((bVar13 == 1) && ((iVar1 <= (int)uVar8 || ((int)uVar8 < iVar2)))) {
              cVar3 = events->count;
              events->count = cVar3 + '\x01';
              events->triggeredIds[(u8)cVar3] = uVar15;
            }
            if (((bVar13 == 3) && (iVar2 < (int)uVar8)) && ((int)uVar8 <= iVar1)) {
              cVar3 = events->count;
              events->count = cVar3 + '\x01';
              events->triggeredIds[(u8)cVar3] = uVar15;
            }
            if ((bVar13 == 2) && ((iVar2 < (int)uVar8 || ((int)uVar8 <= iVar1)))) {
              cVar3 = events->count;
              events->count = cVar3 + '\x01';
              events->triggeredIds[(u8)cVar3] = uVar15;
            }
          }
          iVar9 = iVar9 + 2;
          iVar12 = iVar12 + 1;
        }
      }
    }
  }
  return uVar7;
}

/*
 * --INFO--
 *
 * Function: fn_8002F304
 * EN v1.0 Address: 0x8002F6C4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8002F304
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 fn_8002F304(double param_1,int param_2)
{
  ObjAnimComponent *objAnim;
  double dVar1;
  
  objAnim = (ObjAnimComponent *)param_2;
  dVar1 = (double)FLOAT_803df588;
  if ((param_1 <= dVar1) && (dVar1 = param_1, param_1 < (double)FLOAT_803df570)) {
    dVar1 = (double)FLOAT_803df570;
  }
  objAnim->moveProgress = (float)dVar1;
  return 0;
}

/*
 * --INFO--
 *
 * Function: Object_ObjAnimSetMove
 * EN v1.0 Address: 0x8002F6F8
 * EN v1.0 Size: 816b
 * EN v1.1 Address: 0x8002F334
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
Object_ObjAnimSetMove(double param_1,double param_2,double param_3,undefined8 param_4,
                      undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                      int param_9,uint param_10,undefined param_11)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
  short sVar1;
  uint uVar2;
  int iVar3;
  int iVar6;
  double dVar7;
  
  objAnim = (ObjAnimComponent *)param_9;
  dVar7 = (double)FLOAT_803df560;
  if ((param_1 <= dVar7) && (dVar7 = param_1, param_1 < (double)FLOAT_803df570)) {
    dVar7 = (double)FLOAT_803df570;
  }
  objAnim->moveProgress = (float)dVar7;
  bank = ObjAnim_GetActiveBank(objAnim);
  animDef = bank->animDef;
  if (animDef->moveCount != 0) {
    state = bank->primaryState;
    state->flags = param_11;
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
    state->lastBlendMoveIndex = -1;
    sVar1 = objAnim->activeMove;
    objAnim->activeMove = (s16)param_10;
    iVar3 = ObjAnim_ResolveMoveIndex(animDef, param_10);
    if ((animDef->flags & 0x40) == 0) {
      state->moveCacheSlot = (u16)iVar3;
      iVar6 = (int)animDef->moveData[state->moveCacheSlot];
    }
    else {
      if ((int)(param_10 - (int)sVar1 | (int)sVar1 - param_10) < 0) {
        state->blendToggle = '\x01' - state->blendToggle;
        state->moveCacheSlot = (u16)state->blendToggle;
        if (animDef->blendMoveIds[iVar3] == -1) {
          param_1 = (double)FUN_800723a0();
          iVar3 = 0;
        }
        FUN_8001786c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)animDef->blendMoveIds[iVar3],(int)(s16)iVar3,
                     (undefined4)state->moveCache[state->moveCacheSlot],(int)animDef);
      }
      iVar6 = (int)state->moveCache[state->moveCacheSlot] + 0x80;
    }
    state->frameData = (u8 *)(iVar6 + 6);
    state->frameType = *(u8 *)(iVar6 + 1) & 0xf0;
    state->segmentLength =
         (float)((double)CONCAT44(0x43300000,(uint)state->frameData[1]) -
                DOUBLE_803df568);
    if (state->frameType == '\0') {
      state->segmentLength = state->segmentLength - FLOAT_803df560;
    }
    uVar2 = (int)*(char *)(iVar6 + 1) & 0xf;
    if (uVar2 != 0) {
      state->savedStep = state->step;
      state->eventStep =
           (short)(int)(FLOAT_803df574 /
                        (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803df580));
      state->eventCountdown = 0x4000;
    }
    state->step = FLOAT_803df570;
    state->speed = (float)(dVar7 * (double)state->segmentLength);
  }
  return 0;
}
