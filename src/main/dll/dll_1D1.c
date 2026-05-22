#include "ghidra_import.h"
#include "main/dll/dll_1D1.h"

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
  int targetObj;
} TreeBirdState;

typedef struct TreeBirdSeqData {
  u8 pad0[0x81];
  u8 commands[10];
  u8 commandCount;
} TreeBirdSeqData;

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
  int state;
  float fx, fy, fz;

  state = *(int *)(obj + 0xb8);
  objRenderFn_8003b8f4(obj, lbl_803E51F8);
  if ((u32)*(int *)(state + 8) != 0) {
    ObjPath_GetPointWorldPosition(obj, 0, &fx, &fy, &fz, 0);
    *(float *)(*(int *)(state + 8) + 0xc) = fx;
    *(float *)(*(int *)(state + 8) + 0x10) = fy;
    *(float *)(*(int *)(state + 8) + 0x14) = fz;
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
  int state;
  float dist;

  state = *(int *)(obj + 0xb8);
  dist = lbl_803E51FC;
  if (*(u8 *)(state + 7) != 0) {
    *(int *)(state + 8) = ObjGroup_FindNearestObject(4, obj, &dist);
    if (*(int *)(state + 8) != 0) {
      *(u8 *)(state + 7) = 0;
    }
    else {
      *(u8 *)(state + 7) = *(u8 *)(state + 7) - 1;
    }
  }
  else if (*(u8 *)(state + 6) == 0) {
    if (*(short *)(state + 4) != 0) {
      (*(code *)(*gObjectTriggerInterface + 0x54))();
      (*(code *)(*gObjectTriggerInterface + 0x48))((int)*(short *)(state + 2), obj, 1);
      *(u8 *)(state + 6) = 1;
    }
    else if (GameBit_Get((int)*(short *)state) != 0) {
      (*(code *)(*gObjectTriggerInterface + 0x48))((int)*(short *)(state + 2), obj, -1);
      *(u8 *)(state + 6) = 1;
    }
  }
}
