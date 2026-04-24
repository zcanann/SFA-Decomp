#include "ghidra_import.h"
#include "main/dll/dll_226.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_80017698();
extern undefined4 FUN_801be520();

extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de814;
extern undefined4 DAT_803de828;
extern undefined4 DAT_803de830;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de818;
extern f32 FLOAT_803de81c;
extern f32 FLOAT_803de820;
extern f32 FLOAT_803de824;
extern f32 FLOAT_803e5928;
extern f32 FLOAT_803e5934;
extern f32 FLOAT_803e594c;
extern f32 FLOAT_803e5950;
extern f32 FLOAT_803e5954;
extern f32 FLOAT_803e5958;

/*
 * --INFO--
 *
 * Function: FUN_801be44c
 * EN v1.0 Address: 0x801BE44C
 * EN v1.0 Size: 804b
 * EN v1.1 Address: 0x801BE750
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801be44c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined4 param_10,int param_11,int param_12)
{
  double dVar1;
  double dVar2;
  
  dVar2 = (double)FLOAT_803e5928;
  *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) = *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) | 1;
  *(undefined *)(param_12 + 0x25f) = 1;
  (**(code **)(*DAT_803dd738 + 0x2c))(dVar2,param_9,param_12,1);
  (**(code **)(*DAT_803dd738 + 0x54))
            (param_9,param_12,param_11 + 0x35c,(int)*(short *)(param_11 + 0x3f4),param_11 + 0x405,0,
             0,0);
  dVar1 = (double)FLOAT_803e5928;
  if (dVar1 == (double)FLOAT_803de824) {
    dVar2 = (double)(float)(dVar2 + (double)FLOAT_803e5954);
  }
  else {
    FLOAT_803de824 = (float)((double)FLOAT_803de824 - (double)FLOAT_803dc074);
    dVar2 = (double)(FLOAT_803de824 * FLOAT_803e594c);
    if (FLOAT_803de824 <= FLOAT_803e5950) {
      FLOAT_803de824 = FLOAT_803e5928;
      *(undefined *)(param_12 + 0x349) = 0;
      *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfffe;
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      FUN_80017698(0x20e,0);
      if (DAT_803de814 < '\a') {
        FUN_80017698(0x268,1);
      }
      else {
        FUN_80017698(0x311,1);
      }
    }
  }
  if (FLOAT_803de81c <= FLOAT_803de820) {
    FUN_80006824(param_9,0x189);
    if ((double)FLOAT_803e5954 < dVar2) {
      dVar2 = (double)FLOAT_803e5954;
    }
    if (dVar2 < (double)FLOAT_803e5934) {
      dVar2 = (double)FLOAT_803e5934;
    }
    FLOAT_803de81c = (float)((double)FLOAT_803de81c + dVar2);
    FUN_80006b94((double)FLOAT_803e5958);
  }
  dVar2 = (double)FLOAT_803de820;
  FLOAT_803de820 = (float)(dVar2 + (double)FLOAT_803dc074);
  FUN_801be520(dVar2,dVar1,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_12);
  if ((FLOAT_803e5928 != FLOAT_803de818) &&
     (FLOAT_803de818 = FLOAT_803de818 - FLOAT_803dc074, FLOAT_803de818 <= FLOAT_803e5928)) {
    FLOAT_803de818 = FLOAT_803e5928;
    *(undefined *)(param_12 + 0x349) = 0;
    *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfffe;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    FUN_80017698(0x20e,0);
    if (DAT_803de814 == '\x03') {
      FUN_80017698(0x268,1);
    }
    else {
      FUN_80017698(0x311,1);
    }
  }
  *(undefined4 *)(param_11 + 0x3e0) = *(undefined4 *)(param_9 + 0xc0);
  *(undefined4 *)(param_9 + 0xc0) = 0;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)FLOAT_803dc074,(double)FLOAT_803dc074,param_9,param_12,&DAT_803de830,
             &DAT_803de828);
  *(undefined4 *)(param_9 + 0xc0) = *(undefined4 *)(param_11 + 0x3e0);
  return;
}
