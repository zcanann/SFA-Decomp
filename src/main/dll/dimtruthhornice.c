#include "ghidra_import.h"
#include "main/dll/dimtruthhornice.h"

extern undefined4 *gPartfxInterface;
extern undefined4 *gObjectTriggerInterface;
extern uint GameBit_Get(int eventId);
extern void objRenderFn_8003b8f4(int obj, float arg);
extern int ObjGroup_FindNearestObject(int group, int obj, float *outDist);
extern void ObjPath_GetPointWorldPosition(int obj, int param2, float *outX, float *outY, float *outZ, int param6);

extern f32 lbl_803E51F8;
extern f32 lbl_803E51FC;

typedef struct TreeBirdState {
  s16 gameBit;
  s16 triggerId;
  s16 immediateTrigger;
  u8 triggerLatched;
  u8 searchDelay;
  void *targetObj;
} TreeBirdState;

typedef struct TreeBirdSeqData {
  u8 pad0[0x81];
  u8 commands[10];
  u8 commandCount;
} TreeBirdSeqData;

typedef undefined4 (*TreeBirdTriggerImmediateFn)(int obj, int triggerId);

#define TREEBIRD_SPAWN_PARTICLE(obj,id) \
  (*(code *)(*gPartfxInterface + 8))(obj,id,0,1,-1,0)

#pragma peephole off
#pragma scheduling off

/*
 * --INFO--
 *
 * Function: TreeBird_SeqFn
 * EN v1.0 Address: 0x801CD7DC
 * EN v1.0 Size: 620b
 * EN v1.1 Address: 0x801CD80C
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int TreeBird_SeqFn(int obj, int param_2, int data)
{
  TreeBirdState *state;
  TreeBirdSeqData *seqData;
  int i;
  int j;
  u8 cmd;

  state = *(TreeBirdState **)(obj + 0xb8);
  seqData = (TreeBirdSeqData *)data;
  i = 0;
  while (i < (int)seqData->commandCount) {
    cmd = seqData->commands[i];
    switch (cmd) {
    case 1:
      j = 200;
      do {
        TREEBIRD_SPAWN_PARTICLE(obj,0xcc);
        j--;
      } while (j != 0);
      break;
    case 2:
      j = 100;
      if (*(short *)(obj + 0x46) == 0x5d) {
        do {
          TREEBIRD_SPAWN_PARTICLE(obj,0xd3);
          j--;
        } while (j != 0);
      }
      else if (state->triggerId == 0) {
        do {
          TREEBIRD_SPAWN_PARTICLE(obj,0xcd);
          j--;
        } while (j != 0);
      }
      else if (state->triggerId == 1) {
        do {
          TREEBIRD_SPAWN_PARTICLE(obj,0xcf);
          j--;
        } while (j != 0);
      }
      break;
    case 3:
      j = 5;
      if (*(short *)(obj + 0x46) == 0x5d) {
        do {
          TREEBIRD_SPAWN_PARTICLE(obj,0xd4);
          j--;
        } while (j != 0);
      }
      else if (state->triggerId == 0) {
        do {
          TREEBIRD_SPAWN_PARTICLE(obj,0xce);
          j--;
        } while (j != 0);
      }
      else if (state->triggerId == 1) {
        do {
          TREEBIRD_SPAWN_PARTICLE(obj,0xd0);
          j--;
        } while (j != 0);
      }
      break;
    }
    i++;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: treebird_getExtraSize
 * EN v1.0 Address: 0x801CDA48
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int treebird_getExtraSize(void)
{
  return 0xc;
}

/*
 * --INFO--
 *
 * Function: treebird_render
 * EN v1.0 Address: 0x801CDA50
 * EN v1.0 Size: 136b
 */
void treebird_render(int obj)
{
  TreeBirdState *state;
  float fx, fy, fz;

  state = *(TreeBirdState **)(obj + 0xb8);
  objRenderFn_8003b8f4(obj, lbl_803E51F8);
  if (state->targetObj != NULL) {
    ObjPath_GetPointWorldPosition(obj, 0, &fx, &fy, &fz, 0);
    *(float *)((u8 *)state->targetObj + 0xc) = fx;
    *(float *)((u8 *)state->targetObj + 0x10) = fy;
    *(float *)((u8 *)state->targetObj + 0x14) = fz;
  }
}

/*
 * --INFO--
 *
 * Function: treebird_update
 * EN v1.0 Address: 0x801CDAD8
 * EN v1.0 Size: 276b
 */
void treebird_update(int obj)
{
  TreeBirdState *state;
  int immediateTrigger;
  float dist;

  state = *(TreeBirdState **)(obj + 0xb8);
  dist = lbl_803E51FC;
  if (state->searchDelay != 0) {
    state->targetObj = (void *)ObjGroup_FindNearestObject(4, obj, &dist);
    if ((u32)state->targetObj != 0) {
      state->searchDelay = 0;
    }
    else {
      state->searchDelay--;
    }
  }
  else if (state->triggerLatched == 0) {
    immediateTrigger = state->immediateTrigger;
    if (immediateTrigger != 0) {
      ((TreeBirdTriggerImmediateFn)*(code *)(*gObjectTriggerInterface + 0x54))(obj, immediateTrigger);
      (*(code *)(*gObjectTriggerInterface + 0x48))((int)state->triggerId, obj, 1);
      state->triggerLatched = 1;
    }
    else if (GameBit_Get((int)state->gameBit) != 0) {
      (*(code *)(*gObjectTriggerInterface + 0x48))((int)state->triggerId, obj, -1);
      state->triggerLatched = 1;
    }
  }
}
