#include "ghidra_import.h"

extern undefined4 fn_8000E034();
extern undefined4 fn_8000E0A0();
extern uint fn_800217C0();
extern undefined4 fn_80103660();
extern char camcontrol_getTargetPosition();
extern char camcontrol_samplePathState();
extern undefined4 camcontrol_updatePathTargetAction();

extern undefined4 **lbl_803DCA50;
extern int *lbl_803DD538;
extern f32 lbl_803DB414;
extern f32 lbl_803E1740;
extern f32 lbl_803E1758;
extern f32 lbl_803E175C;

/*
 * --INFO--
 *
 * Function: camclimb_update
 * EN v1.0 Address: 0x801070FC
 * EN v1.0 Size: 896b
 * EN v1.1 Address: 0x80107398
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camclimb_update(short *param_1)
{
  char cVar2;
  uint uVar1;
  int iVar3;
  short *psVar4;
  int iVar5;
  float local_38;
  float local_34;
  undefined auStack_30 [4];
  float local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20 [4];

  if (*(u8 *)((int)lbl_803DD538 + 0x1bc) == 0) {
    if (*lbl_803DD538 != *(int *)(param_1 + 0x18)) {
      iVar3 = 0;
      for (iVar5 = 0; iVar5 < *(int *)((int)lbl_803DD538 + 0x1b0); iVar5 = iVar5 + 1) {
        fn_8000E0A0((double)*(float *)((int)lbl_803DD538 + iVar3 + 0x1c),
                     (double)*(float *)((int)lbl_803DD538 + iVar3 + 0x6c),
                     (double)*(float *)((int)lbl_803DD538 + iVar3 + 0xbc),
                     (int)lbl_803DD538 + iVar3 + 0x1c,
                     (int)lbl_803DD538 + iVar3 + 0x6c,
                     (int)lbl_803DD538 + iVar3 + 0xbc, *lbl_803DD538);
        iVar3 = iVar3 + 4;
      }
      iVar3 = 0;
      for (iVar5 = 0; iVar5 < *(int *)((int)lbl_803DD538 + 0x1b0); iVar5 = iVar5 + 1) {
        fn_8000E034((double)*(float *)((int)lbl_803DD538 + iVar3 + 0x1c),
                     (double)*(float *)((int)lbl_803DD538 + iVar3 + 0x6c),
                     (double)*(float *)((int)lbl_803DD538 + iVar3 + 0xbc),
                     (int)lbl_803DD538 + iVar3 + 0x1c,
                     (int)lbl_803DD538 + iVar3 + 0x6c,
                     (int)lbl_803DD538 + iVar3 + 0xbc, *(undefined4 *)(param_1 + 0x18));
        iVar3 = iVar3 + 4;
      }
      *lbl_803DD538 = *(int *)(param_1 + 0x18);
    }
    psVar4 = *(short **)(param_1 + 0x52);
    local_24 = *(undefined4 *)(param_1 + 8);
    cVar2 = camcontrol_samplePathState(&local_28, &local_24, local_20, psVar4, param_1);
    *(undefined4 *)(param_1 + 6) = local_28;
    *(undefined4 *)(param_1 + 10) = local_20[0];
    iVar3 = (**(code **)(**(int **)lbl_803DCA50 + 0x18))();
    fn_8000E0A0((double)*(float *)(param_1 + 6), (double)*(float *)(param_1 + 8),
                 (double)*(float *)(param_1 + 10), param_1 + 0xc, param_1 + 0xe,
                 param_1 + 0x10, *(undefined4 *)(param_1 + 0x18));
    (**(code **)(**(int **)(iVar3 + 4) + 0x1c))
              ((double)lbl_803E1758, (double)lbl_803E175C, param_1, psVar4);
    (**(code **)(**(int **)(iVar3 + 4) + 0x24))(param_1, 1, 3,
                                                 (int)lbl_803DD538 + 0x14,
                                                 (int)lbl_803DD538 + 0x18);
    if ((param_1[0x50] != 0) || (*(u8 *)(param_1 + 0xa1) != 0)) {
      *(float *)((int)lbl_803DD538 + 0x11c) = *(float *)((int)lbl_803DD538 + 0x11c) + lbl_803DB414;
    }
    if (lbl_803E1740 < *(float *)((int)lbl_803DD538 + 0x11c)) {
      cVar2 = camcontrol_getTargetPosition(param_1, psVar4, param_1 + 0xc, param_1 + 1);
      if (cVar2 == '\x01') {
        fn_80103660(1);
      }
      *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
      *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
      cVar2 = '\x01';
    }
    (**(code **)(**(int **)lbl_803DCA50 + 0x38))
              ((double)lbl_803E1740, param_1, &local_2c, auStack_30, &local_34, &local_38, 0);
    uVar1 = fn_800217C0((double)local_2c, (double)local_34);
    iVar5 = (0x8000 - (uVar1 & 0xffff)) - ((int)*param_1 & 0xffffU);
    if (0x8000 < iVar5) {
      iVar5 = iVar5 + -0xffff;
    }
    if (iVar5 < -0x8000) {
      iVar5 = iVar5 + 0xffff;
    }
    *param_1 = *param_1 + (short)iVar5;
    (**(code **)(**(int **)(iVar3 + 4) + 0x18))
              ((double)*(float *)(psVar4 + 0xe), (double)local_38, param_1);
    if (cVar2 != '\0') {
      (**(code **)(**(int **)lbl_803DCA50 + 0x1c))(0x42, 0, 1, 0, 0, 0, 0xff);
    }
    camcontrol_updatePathTargetAction(param_1, psVar4);
    fn_8000E034((double)*(float *)(param_1 + 0xc), (double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10), param_1 + 6, param_1 + 8,
                 param_1 + 10, *(undefined4 *)(param_1 + 0x18));
  }
  else {
    (**(code **)(**(int **)lbl_803DCA50 + 0x1c))(0x42, 0, 1, 0, 0, 0, 0xff);
  }
  return;
}
