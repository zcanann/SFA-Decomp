#include "ghidra_import.h"
#include "main/dll/landedArwing.h"

extern int FUN_80017a98();
extern undefined4 ObjHits_DisableObject();
extern undefined4 FUN_801660c0();
extern undefined4 FUN_801661ec();
extern undefined4 FUN_8016693c();
extern undefined4 FUN_80166e9c();

extern undefined4 DAT_803dc070;
extern f32 FLOAT_803e3c74;
extern f32 FLOAT_803e3c8c;
extern f32 FLOAT_803e3c94;
extern f32 FLOAT_803e3c98;

/*
 * --INFO--
 *
 * Function: FUN_8016558c
 * EN v1.0 Address: 0x8016558C
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x80165884
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8016558c(short *param_1,int param_2)
{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  iVar4 = *(int *)(*(int *)(param_1 + 0x5c) + 0x40c);
  iVar2 = FUN_80017a98();
  *(undefined *)(param_2 + 0x34d) = 1;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(undefined2 *)(iVar4 + 0x8e) = 0x3c;
    *(float *)(iVar4 + 0x60) = FLOAT_803e3c94;
    ObjHits_DisableObject((int)param_1);
  }
  if ((*(char *)(iVar4 + 0x90) == '\x06') ||
     ((((iVar2 != 0 && (*(float *)(iVar4 + 0x48) <= *(float *)(iVar2 + 0x18))) &&
       ((*(float *)(iVar2 + 0x18) <= *(float *)(iVar4 + 0x4c) ||
        (*(float *)(iVar4 + 0x5c) <= *(float *)(iVar2 + 0x1c))))) &&
      (((*(float *)(iVar2 + 0x1c) <= *(float *)(iVar4 + 0x58) ||
        (*(float *)(iVar4 + 0x54) <= *(float *)(iVar2 + 0x20))) &&
       (*(float *)(iVar2 + 0x20) <= *(float *)(iVar4 + 0x50))))))) {
    dVar5 = -(double)(FLOAT_803e3c98 * (*(float *)(iVar2 + 0xc) - *(float *)(param_1 + 6)) -
                     *(float *)(param_1 + 6));
    dVar6 = -(double)(FLOAT_803e3c98 * (*(float *)(iVar2 + 0x10) - *(float *)(param_1 + 8)) -
                     *(float *)(param_1 + 8));
    dVar7 = -(double)(FLOAT_803e3c98 * (*(float *)(iVar2 + 0x14) - *(float *)(param_1 + 10)) -
                     *(float *)(param_1 + 10));
    fVar1 = FLOAT_803e3c8c;
  }
  else {
    dVar5 = (double)*(float *)(param_1 + 6);
    dVar6 = (double)*(float *)(param_1 + 8);
    dVar7 = (double)*(float *)(param_1 + 10);
    fVar1 = FLOAT_803e3c74;
  }
  FUN_80166e9c(dVar5,dVar6,dVar7,(double)fVar1,(int)param_1);
  if (*(char *)(iVar4 + 0x90) == '\x06') {
    if ((*(byte *)(iVar4 + 0x92) >> 2 & 1) == 0) {
      FUN_8016693c((int)param_1,iVar4);
    }
    else {
      FUN_801660c0((int)param_1,iVar4);
    }
  }
  else {
    FUN_801661ec(param_1,iVar4);
  }
  if ((ushort)DAT_803dc070 < *(ushort *)(iVar4 + 0x8e)) {
    *(ushort *)(iVar4 + 0x8e) = *(ushort *)(iVar4 + 0x8e) - (ushort)DAT_803dc070;
    uVar3 = 0;
  }
  else {
    uVar3 = 2;
  }
  return uVar3;
}
