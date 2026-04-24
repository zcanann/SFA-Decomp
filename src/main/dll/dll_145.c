#include "ghidra_import.h"
#include "main/dll/dll_145.h"

extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80039520();

extern undefined4 DAT_803dc070;
extern f64 DOUBLE_803e43b8;
extern f32 FLOAT_803e43b0;

/*
 * --INFO--
 *
 * Function: FUN_8017ab20
 * EN v1.0 Address: 0x8017AB20
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x8017AB28
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017ab20(int param_1)
{
  float fVar1;
  uint uVar2;
  undefined4 *puVar3;
  char *pcVar4;
  undefined *puVar5;
  
  pcVar4 = *(char **)(param_1 + 0xb8);
  if (*pcVar4 == '\0') {
    uVar2 = FUN_80017690((int)*(short *)(pcVar4 + 2));
    if (uVar2 != 0) {
      puVar5 = *(undefined **)(param_1 + 0xb8);
      puVar3 = (undefined4 *)FUN_80039520(param_1,0);
      if (puVar3 != (undefined4 *)0x0) {
        *puVar3 = 0x100;
      }
      *puVar5 = 1;
    }
  }
  else {
    uVar2 = FUN_80017690((int)*(short *)(pcVar4 + 2));
    if (uVar2 == 0) {
      puVar5 = *(undefined **)(param_1 + 0xb8);
      puVar3 = (undefined4 *)FUN_80039520(param_1,0);
      if (puVar3 != (undefined4 *)0x0) {
        *puVar3 = 0;
      }
      *puVar5 = 0;
    }
  }
  fVar1 = FLOAT_803e43b0;
  if (FLOAT_803e43b0 < *(float *)(pcVar4 + 4)) {
    *(float *)(pcVar4 + 4) =
         *(float *)(pcVar4 + 4) -
         (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e43b8);
    if (*(float *)(pcVar4 + 4) <= fVar1) {
      *(float *)(pcVar4 + 4) = fVar1;
      FUN_80017698((int)*(short *)(pcVar4 + 2),0);
    }
  }
  return;
}
