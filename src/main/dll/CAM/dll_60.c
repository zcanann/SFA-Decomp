#include "ghidra_import.h"
#include "main/dll/CAM/dll_60.h"

extern undefined4 FUN_80017814();
extern undefined4 FUN_80053ba4();

extern undefined4* DAT_803dd6d0;
extern undefined4 DAT_803de1e0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e2540;
extern f32 FLOAT_803e2544;
extern f32 FLOAT_803e2548;

/*
 * --INFO--
 *
 * Function: camdrakor_computeTargetOffset
 * EN v1.0 Address: 0x8010C0D8
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x8010C1A4
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camdrakor_computeTargetOffset
          (int param_1,float *param_2,float *param_3,float *param_4,float *param_5)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  
  iVar7 = *(int *)(param_1 + 0x11c);
  iVar6 = *(int *)(param_1 + 0xa4);
  iVar9 = *(int *)(iVar7 + 0x74);
  if (*(char *)(iVar7 + 0xe4) != *(char *)(DAT_803de1e0 + 0x14)) {
    *(char *)(DAT_803de1e0 + 0x13) = *(char *)(DAT_803de1e0 + 0x14);
    *(float *)(DAT_803de1e0 + 0x18) = FLOAT_803e2540;
  }
  fVar1 = FLOAT_803e2544;
  if (*(float *)(DAT_803de1e0 + 0x18) <= FLOAT_803e2544) {
    *param_2 = *(float *)(iVar9 + (uint)*(byte *)(iVar7 + 0xe4) * 0x18 + 0xc) -
               *(float *)(iVar6 + 0x18);
    *param_3 = *(float *)(iVar9 + (uint)*(byte *)(iVar7 + 0xe4) * 0x18 + 0x10) - *param_5;
    *param_4 = *(float *)(iVar9 + (uint)*(byte *)(iVar7 + 0xe4) * 0x18 + 0x14) -
               *(float *)(iVar6 + 0x20);
  }
  else {
    *(float *)(DAT_803de1e0 + 0x18) =
         -(FLOAT_803e2548 * FLOAT_803dc074 - *(float *)(DAT_803de1e0 + 0x18));
    if (*(float *)(DAT_803de1e0 + 0x18) < fVar1) {
      *(float *)(DAT_803de1e0 + 0x18) = fVar1;
      *(undefined *)(DAT_803de1e0 + 0x13) = *(undefined *)(iVar7 + 0xe4);
    }
    iVar8 = iVar9 + (uint)*(byte *)(DAT_803de1e0 + 0x13) * 0x18;
    iVar9 = iVar9 + (uint)*(byte *)(iVar7 + 0xe4) * 0x18;
    fVar1 = *(float *)(iVar8 + 0x10);
    fVar2 = *(float *)(iVar9 + 0x10);
    fVar3 = *(float *)(iVar8 + 0x14);
    fVar4 = *(float *)(iVar9 + 0x14);
    fVar5 = *(float *)(DAT_803de1e0 + 0x18);
    *param_2 = ((*(float *)(iVar8 + 0xc) - *(float *)(iVar9 + 0xc)) * fVar5 +
               *(float *)(iVar9 + 0xc)) - *(float *)(iVar6 + 0x18);
    *param_3 = ((fVar1 - fVar2) * fVar5 + fVar2) - *param_5;
    *param_4 = ((fVar3 - fVar4) * fVar5 + fVar4) - *(float *)(iVar6 + 0x20);
  }
  *(undefined *)(DAT_803de1e0 + 0x14) = *(undefined *)(iVar7 + 0xe4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010c234
 * EN v1.0 Address: 0x8010C234
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x8010C304
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010c234(int param_1)
{
  if (*(int *)(param_1 + 0x11c) != 0) {
    (**(code **)(*DAT_803dd6d0 + 0x48))(0);
  }
  FUN_80017814(DAT_803de1e0);
  DAT_803de1e0 = 0;
  FUN_80053ba4();
  *(byte *)(param_1 + 0x143) = *(byte *)(param_1 + 0x143) & 0x7f;
  return;
}
