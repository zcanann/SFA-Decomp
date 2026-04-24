// Function: FUN_8016c590
// Entry: 8016c590
// Size: 596 bytes

void FUN_8016c590(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  byte bVar1;
  int *piVar2;
  uint uVar3;
  undefined2 *puVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  undefined4 uVar8;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar9;
  int iVar10;
  int iVar11;
  undefined8 extraout_f1;
  undefined8 uVar12;
  int local_18;
  int local_14;
  
  iVar10 = *(int *)(param_9 + 0xb8);
  if ((*(int *)(param_9 + 0x4c) != 0) && (*(short *)(*(int *)(param_9 + 0x4c) + 0x18) != -1)) {
    local_14 = (**(code **)(*DAT_803dd6d4 + 0x14))((double)FLOAT_803dc074);
    uVar12 = extraout_f1;
    if ((local_14 != 0) && (*(short *)(param_9 + 0xb4) == -2)) {
      iVar9 = (int)*(char *)(iVar10 + 0x57);
      iVar11 = 0;
      piVar2 = (int *)FUN_8002e1f4(&local_14,&local_18);
      iVar7 = 0;
      for (local_14 = 0; local_14 < local_18; local_14 = local_14 + 1) {
        iVar5 = *piVar2;
        if (*(short *)(iVar5 + 0xb4) == iVar9) {
          iVar11 = iVar5;
        }
        if (((*(short *)(iVar5 + 0xb4) == -2) && (*(short *)(iVar5 + 0x44) == 0x10)) &&
           (iVar10 = *(int *)(iVar5 + 0xb8), iVar9 == *(char *)(iVar10 + 0x57))) {
          iVar7 = iVar7 + 1;
        }
        piVar2 = piVar2 + 1;
      }
      if (((iVar7 < 2) && (iVar11 != 0)) && (*(short *)(iVar11 + 0xb4) != -1)) {
        *(undefined2 *)(iVar11 + 0xb4) = 0xffff;
        uVar12 = (**(code **)(*DAT_803dd6d4 + 0x4c))(iVar9);
      }
      *(undefined2 *)(param_9 + 0xb4) = 0xffff;
      *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x8000;
      *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
    }
    if (*(short *)(param_9 + 0x46) == 0x774) {
      for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)(iVar10 + 0x8b); iVar11 = iVar11 + 1) {
        bVar1 = *(byte *)(iVar10 + iVar11 + 0x81);
        if (bVar1 == 0xb) {
          if (*(char *)(param_9 + 0xeb) != '\0') {
            FUN_8002cc9c(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         *(int *)(param_9 + 200));
            uVar12 = FUN_80037da8(param_9,*(int *)(param_9 + 200));
          }
        }
        else if (((bVar1 < 0xb) && (9 < bVar1)) && (uVar3 = FUN_8002e144(), (uVar3 & 0xff) != 0)) {
          puVar4 = FUN_8002becc(0x18,0x69);
          uVar6 = 0xffffffff;
          uVar8 = 0;
          iVar7 = FUN_8002e088(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4
                               ,4,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
          FUN_80037e24(param_9,iVar7,0);
          FUN_8003042c((double)FLOAT_803e3ec4,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,iVar7,0,0,uVar6,uVar8,in_r8,in_r9,in_r10);
          param_2 = (double)FLOAT_803dc074;
          uVar12 = FUN_8002fb40((double)FLOAT_803e3ec0,param_2);
        }
      }
    }
  }
  return;
}

