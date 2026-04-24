#include "ghidra_import.h"
#include "main/dll/SH/dll_1E8.h"

extern undefined4 FUN_80006824();
extern double FUN_80017708();
extern int FUN_80017730();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern int FUN_800575b4();
extern undefined4 FUN_800723a0();

extern f64 DOUBLE_803e60c0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e60b0;
extern f32 FLOAT_803e60b4;
extern f32 FLOAT_803e60b8;
extern f32 FLOAT_803e60bc;

/*
 * --INFO--
 *
 * Function: SHthorntail_updateTailSwing
 * EN v1.0 Address: 0x801D5174
 * EN v1.0 Size: 216b
 * EN v1.1 Address: 0x801D5470
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_updateTailSwing(uint objectId,SHthorntailRuntime *runtime)
{
  byte bVar1;
  
  bVar1 = runtime->tailSwingState;
  if (bVar1 == 1) {
    runtime->tailSwingTimer = runtime->tailSwingTimer - FLOAT_803dc074;
    if (runtime->tailSwingTimer <= FLOAT_803e60b0) {
      FUN_80006824(objectId,0xa8);
      runtime->tailSwingState = 2;
    }
  }
  else if (bVar1 == 0) {
    runtime->tailSwingTimer = runtime->tailSwingTimer - FLOAT_803dc074;
    if (runtime->tailSwingTimer <= FLOAT_803e60b0) {
      FUN_80006824(objectId,0xa9);
      runtime->tailSwingState = 1;
      runtime->tailSwingTimer = FLOAT_803e60b4;
    }
  }
  else if ((bVar1 < 3) && ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0)) {
    runtime->tailSwingState = 0;
    runtime->tailSwingTimer = FLOAT_803e60b8;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: SHthorntail_chooseNextState
 * EN v1.0 Address: 0x801D524C
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x801D5558
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint SHthorntail_chooseNextState(short *obj,SHthorntailRuntime *runtime,SHthorntailConfig *config)
{
  short sVar1;
  int iVar2;
  uint uVar3;
  double dVar4;
  
  if (config->leashRadiusByte == '\0') {
    uVar3 = 7;
  }
  else {
    iVar2 = FUN_80017a98();
    dVar4 = FUN_80017708((float *)(obj + 0xc),(float *)(iVar2 + 0x18));
    if ((double)FLOAT_803e60bc <= dVar4) {
      dVar4 = FUN_80017708((float *)(obj + 0xc),&config->homePosX);
      if ((double)(float)((double)CONCAT44(0x43300000,
                                           (uint)config->leashRadiusByte *
                                           (uint)config->leashRadiusByte ^ 0x80000000) -
                         DOUBLE_803e60c0) < dVar4) {
        iVar2 = FUN_80017730();
        sVar1 = (short)iVar2 - *obj;
        if (0x8000 < sVar1) {
          sVar1 = sVar1 + 1;
        }
        if (sVar1 < -0x8000) {
          sVar1 = sVar1 + -1;
        }
        iVar2 = (int)sVar1;
        if (iVar2 < 0) {
          iVar2 = -iVar2;
        }
        if (0x20 < iVar2) {
          FUN_80017730();
          FUN_800723a0();
          if (('\x01' < runtime->behaviorState) && (runtime->behaviorState < '\x06')) {
            return 6;
          }
          return 7;
        }
      }
      iVar2 = FUN_800575b4((double)(*(float *)(obj + 0x54) * *(float *)(obj + 4)),(float *)(obj + 6));
      if (iVar2 == 0) {
        uVar3 = 7;
      }
      else if ((runtime->behaviorState < '\x02') || ('\x05' < runtime->behaviorState)) {
        uVar3 = 2;
      }
      else {
        uVar3 = FUN_80017760(3,5);
        uVar3 = uVar3 & 0xff;
      }
    }
    else if ((runtime->behaviorState < '\x02') || ('\x05' < runtime->behaviorState)) {
      uVar3 = 7;
    }
    else {
      uVar3 = 6;
    }
  }
  return uVar3;
}
