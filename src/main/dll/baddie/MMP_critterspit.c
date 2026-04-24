#include "ghidra_import.h"
#include "main/dll/baddie/MMP_critterspit.h"

extern double FUN_80017708();
extern void* FUN_80037134();
extern undefined4 FUN_80139a4c();
extern int FUN_8013b368();
extern int FUN_8013dc88();
extern undefined4 FUN_80146fa0();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();

extern f32 FLOAT_803e306c;
extern f32 FLOAT_803e30a0;
extern f32 FLOAT_803e30a4;
extern f32 FLOAT_803e30a8;
extern f32 FLOAT_803e30cc;
extern f32 FLOAT_803e30d0;
extern f32 FLOAT_803e30d4;
extern f32 FLOAT_803e310c;
extern f32 FLOAT_803e3154;

/*
 * --INFO--
 *
 * Function: FUN_8013db3c
 * EN v1.0 Address: 0x8013DB3C
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x8013DC78
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013db3c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  int local_48 [12];
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar11 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar11 >> 0x20);
  iVar6 = (int)uVar11;
  iVar7 = 0;
  dVar9 = (double)FLOAT_803e30a8;
  iVar4 = FUN_8013dc88(iVar3,iVar6);
  if (iVar4 == 0) {
    *(undefined *)(iVar6 + 8) = 1;
    *(undefined *)(iVar6 + 10) = 0;
    fVar2 = FLOAT_803e306c;
    *(float *)(iVar6 + 0x71c) = FLOAT_803e306c;
    *(float *)(iVar6 + 0x720) = fVar2;
    *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xffffffef;
    *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffeffff;
    *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffdffff;
    *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffbffff;
    *(undefined *)(iVar6 + 0xd) = 0xff;
  }
  else {
    piVar5 = FUN_80037134(0x4b,local_48);
    dVar10 = (double)FLOAT_803e3154;
    for (iVar4 = 0; iVar4 < local_48[0]; iVar4 = iVar4 + 1) {
      dVar8 = FUN_80017708((float *)(*(int *)(iVar6 + 4) + 0x18),(float *)(*piVar5 + 0x18));
      if ((dVar10 < dVar8) &&
         (dVar8 = FUN_80017708((float *)(iVar3 + 0x18),(float *)(*piVar5 + 0x18)), dVar8 < dVar9)) {
        iVar7 = *piVar5;
        dVar9 = dVar8;
      }
      piVar5 = piVar5 + 1;
    }
    if (iVar7 != 0) {
      *(int *)(iVar6 + 0x24) = iVar7;
      if (*(int *)(iVar6 + 0x28) != iVar7 + 0x18) {
        *(int *)(iVar6 + 0x28) = iVar7 + 0x18;
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffffbff;
        *(undefined2 *)(iVar6 + 0xd2) = 0;
      }
      iVar4 = FUN_8013b368((double)FLOAT_803e310c,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,iVar3,iVar6,param_11,param_12,param_13,param_14,param_15,param_16
                          );
      if (iVar4 == 1) goto LAB_8013de9c;
    }
    if (FLOAT_803e306c == *(float *)(iVar6 + 0x2ac)) {
      bVar1 = false;
    }
    else if (FLOAT_803e30a0 == *(float *)(iVar6 + 0x2b0)) {
      bVar1 = true;
    }
    else if (*(float *)(iVar6 + 0x2b4) - *(float *)(iVar6 + 0x2b0) <= FLOAT_803e30a4) {
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
    if (bVar1) {
      FUN_80139a4c((double)FLOAT_803e30cc,iVar3,8,0);
      *(float *)(iVar6 + 0x79c) = FLOAT_803e30d0;
      *(float *)(iVar6 + 0x838) = FLOAT_803e306c;
      FUN_80146fa0();
    }
    else {
      FUN_80139a4c((double)FLOAT_803e30d4,iVar3,0,0);
      FUN_80146fa0();
    }
  }
LAB_8013de9c:
  FUN_8028688c();
  return;
}
