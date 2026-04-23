#include "ghidra_import.h"
#include "main/dll/CAM/camclimb.h"

extern undefined4 FUN_8000e054();
extern undefined4 FUN_8000e0c0();
extern uint FUN_80021884();
extern undefined4 FUN_801038fc();
extern char camcontrol_getTargetPosition();
extern char FUN_801068f0();
extern undefined4 FUN_80107214();

extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803de1b0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e23c0;
extern f32 FLOAT_803e23d8;
extern f32 FLOAT_803e23dc;

/*
 * --INFO--
 *
 * Function: FUN_80107398
 * EN v1.0 Address: 0x80107398
 * EN v1.0 Size: 896b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80107398(ushort *param_1)
{
  char cVar2;
  uint uVar1;
  int iVar3;
  short *psVar4;
  int iVar5;
  float local_38;
  undefined local_34 [4];
  undefined auStack_30 [4];
  undefined local_2c [4];
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20 [4];
  
  if (*(char *)(DAT_803de1b0 + 0x6f) == '\0') {
    if (*DAT_803de1b0 != *(int *)(param_1 + 0x18)) {
      iVar3 = 0;
      for (iVar5 = 0; iVar5 < DAT_803de1b0[0x6c]; iVar5 = iVar5 + 1) {
        FUN_8000e0c0((double)*(float *)((int)DAT_803de1b0 + iVar3 + 0x1c),
                     (double)*(float *)((int)DAT_803de1b0 + iVar3 + 0x6c),
                     (double)*(float *)((int)DAT_803de1b0 + iVar3 + 0xbc),
                     (float *)((int)DAT_803de1b0 + iVar3 + 0x1c),
                     (float *)((int)DAT_803de1b0 + iVar3 + 0x6c),
                     (float *)((int)DAT_803de1b0 + iVar3 + 0xbc),*DAT_803de1b0);
        iVar3 = iVar3 + 4;
      }
      iVar3 = 0;
      for (iVar5 = 0; iVar5 < DAT_803de1b0[0x6c]; iVar5 = iVar5 + 1) {
        FUN_8000e054((double)*(float *)((int)DAT_803de1b0 + iVar3 + 0x1c),
                     (double)*(float *)((int)DAT_803de1b0 + iVar3 + 0x6c),
                     (double)*(float *)((int)DAT_803de1b0 + iVar3 + 0xbc),
                     (float *)((int)DAT_803de1b0 + iVar3 + 0x1c),
                     (float *)((int)DAT_803de1b0 + iVar3 + 0x6c),
                     (float *)((int)DAT_803de1b0 + iVar3 + 0xbc),*(int *)(param_1 + 0x18));
        iVar3 = iVar3 + 4;
      }
      *DAT_803de1b0 = *(int *)(param_1 + 0x18);
    }
    psVar4 = *(short **)(param_1 + 0x52);
    local_24 = *(undefined4 *)(param_1 + 8);
    cVar2 = FUN_801068f0(&local_28,&local_24,local_20,psVar4,(int)param_1);
    *(undefined4 *)(param_1 + 6) = local_28;
    *(undefined4 *)(param_1 + 10) = local_20[0];
    iVar3 = (**(code **)(*DAT_803dd6d0 + 0x18))();
    FUN_8000e0c0((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                 (double)*(float *)(param_1 + 10),(float *)(param_1 + 0xc),(float *)(param_1 + 0xe),
                 (float *)(param_1 + 0x10),*(int *)(param_1 + 0x18));
    (**(code **)(**(int **)(iVar3 + 4) + 0x1c))
              ((double)FLOAT_803e23d8,(double)FLOAT_803e23dc,param_1,psVar4);
    (**(code **)(**(int **)(iVar3 + 4) + 0x24))(param_1,1,3,DAT_803de1b0 + 5,DAT_803de1b0 + 6);
    if ((param_1[0x50] != 0) || (*(char *)(param_1 + 0xa1) != '\0')) {
      DAT_803de1b0[0x47] = (int)((float)DAT_803de1b0[0x47] + FLOAT_803dc074);
    }
    if (FLOAT_803e23c0 < (float)DAT_803de1b0[0x47]) {
      cVar2 = camcontrol_getTargetPosition((int)param_1,psVar4,(float *)(param_1 + 0xc),
                                           (short *)(param_1 + 1));
      if (cVar2 == '\x01') {
        FUN_801038fc();
      }
      *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
      *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
      cVar2 = '\x01';
    }
    (**(code **)(*DAT_803dd6d0 + 0x38))
              ((double)FLOAT_803e23c0,param_1,local_2c,auStack_30,local_34,&local_38,0);
    uVar1 = FUN_80021884();
    iVar5 = (0x8000 - (uVar1 & 0xffff)) - (uint)*param_1;
    if (0x8000 < iVar5) {
      iVar5 = iVar5 + -0xffff;
    }
    if (iVar5 < -0x8000) {
      iVar5 = iVar5 + 0xffff;
    }
    *param_1 = *param_1 + (short)iVar5;
    (**(code **)(**(int **)(iVar3 + 4) + 0x18))
              ((double)*(float *)(psVar4 + 0xe),(double)local_38,param_1);
    if (cVar2 != '\0') {
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
    }
    FUN_80107214((int)param_1,(int)psVar4);
    FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  else {
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  return;
}
