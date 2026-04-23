#include "ghidra_import.h"
#include "main/dll/dll_BC.h"

extern void* FUN_8000facc();
extern double FUN_8000fc54();
extern undefined4 FUN_800238c4();
extern undefined4 FUN_8010192c();

extern undefined4 gCamcontrolSavedActionMode;
extern undefined4 gCamcontrolSavedActionFlags;
extern undefined4 gCamcontrolSavedActionId;
extern undefined gCamcontrolQueuedActionMode;
extern undefined4 gCamcontrolQueuedActionBlendFrames;
extern undefined gCamcontrolQueuedActionPending;
extern void *gCamcontrolQueuedActionData;
extern undefined4 gCamcontrolCurrentActionMode;
extern undefined4 gCamcontrolCurrentActionFlags;
extern int gCamcontrolQueuedActionSource;
extern undefined4 gCamcontrolCurrentActionId;
extern undefined4* gCamcontrolState;
extern f64 DOUBLE_803e22d0;
extern f32 FLOAT_803e22ac;
extern f32 FLOAT_803e22b0;

/*
 * --INFO--
 *
 * Function: camcontrol_applyQueuedAction
 * EN v1.0 Address: 0x80102158
 * EN v1.0 Size: 400b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_applyQueuedAction(void)
{
  float fVar1;
  undefined2 *puVar2;
  double dVar3;
  
  if (gCamcontrolQueuedActionPending != '\0') {
    if ((int)gCamcontrolQueuedActionBlendFrames < 2) {
      *(float *)(gCamcontrolState + 0x7a) = FLOAT_803e22b0;
      *(undefined *)((int)gCamcontrolState + 0x13f) = 0;
    }
    else {
      fVar1 = FLOAT_803e22ac /
              (float)((double)CONCAT44(0x43300000,gCamcontrolQueuedActionBlendFrames ^ 0x80000000) -
                     DOUBLE_803e22d0);
      if ((fVar1 <= FLOAT_803e22b0) || (FLOAT_803e22ac < fVar1)) {
        fVar1 = FLOAT_803e22ac;
      }
      *(float *)(gCamcontrolState + 0x7a) = FLOAT_803e22ac;
      *(float *)(gCamcontrolState + 0x7c) = fVar1;
      *(undefined *)((int)gCamcontrolState + 0x13f) = gCamcontrolQueuedActionMode;
    }
    puVar2 = FUN_8000facc();
    if (FLOAT_803e22ac == *(float *)(gCamcontrolState + 0x7a)) {
      *(undefined4 *)(gCamcontrolState + 0x86) = *(undefined4 *)(puVar2 + 6);
      *(undefined4 *)(gCamcontrolState + 0x88) = *(undefined4 *)(puVar2 + 8);
      *(undefined4 *)(gCamcontrolState + 0x8a) = *(undefined4 *)(puVar2 + 10);
      gCamcontrolState[0x83] = *puVar2;
      gCamcontrolState[0x84] = puVar2[1];
      gCamcontrolState[0x85] = puVar2[2];
      dVar3 = FUN_8000fc54();
      *(float *)(gCamcontrolState + 0x8c) = (float)dVar3;
    }
    else {
      *gCamcontrolState = *puVar2;
      gCamcontrolState[1] = puVar2[1];
      gCamcontrolState[2] = puVar2[2];
      dVar3 = FUN_8000fc54();
      *(float *)(gCamcontrolState + 0x5a) = (float)dVar3;
    }
    gCamcontrolSavedActionId = gCamcontrolCurrentActionId;
    gCamcontrolSavedActionFlags = gCamcontrolCurrentActionFlags;
    gCamcontrolSavedActionMode = gCamcontrolCurrentActionMode;
    FUN_8010192c(gCamcontrolQueuedActionSource & 0xffff,(undefined4)gCamcontrolQueuedActionData);
    gCamcontrolQueuedActionPending = '\0';
    if (gCamcontrolQueuedActionData != (void *)0x0) {
      FUN_800238c4((uint)gCamcontrolQueuedActionData);
      gCamcontrolQueuedActionData = (void *)0x0;
    }
  }
  return;
}
