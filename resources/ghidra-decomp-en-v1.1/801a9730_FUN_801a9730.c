// Function: FUN_801a9730
// Entry: 801a9730
// Size: 380 bytes

void FUN_801a9730(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 extraout_f1;
  int local_28;
  int local_24 [6];
  
  iVar4 = *(int *)(param_9 + 0xb8);
  if ((*(int *)(param_9 + 0x4c) != 0) && (*(short *)(*(int *)(param_9 + 0x4c) + 0x18) != -1)) {
    local_24[2] = (int)DAT_803dc070;
    local_24[1] = 0x43300000;
    local_24[0] = (**(code **)(*DAT_803dd6d4 + 0x14))
                            ((double)(float)((double)CONCAT44(0x43300000,local_24[2]) -
                                            DOUBLE_803e5268));
    FUN_801a953c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar4);
    if ((local_24[0] != 0) && (*(short *)(param_9 + 0xb4) == -2)) {
      iVar5 = (int)*(char *)(iVar4 + 0x57);
      iVar4 = 0;
      piVar1 = (int *)FUN_8002e1f4(local_24,&local_28);
      iVar3 = 0;
      for (local_24[0] = 0; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
        iVar2 = *piVar1;
        if (*(short *)(iVar2 + 0xb4) == iVar5) {
          iVar4 = iVar2;
        }
        if (((*(short *)(iVar2 + 0xb4) == -2) && (*(short *)(iVar2 + 0x44) == 0x10)) &&
           (iVar5 == *(char *)(*(int *)(iVar2 + 0xb8) + 0x57))) {
          iVar3 = iVar3 + 1;
        }
        piVar1 = piVar1 + 1;
      }
      if (((iVar3 < 2) && (iVar4 != 0)) && (*(short *)(iVar4 + 0xb4) != -1)) {
        *(undefined2 *)(iVar4 + 0xb4) = 0xffff;
        (**(code **)(*DAT_803dd6d4 + 0x4c))(iVar5);
      }
      *(undefined2 *)(param_9 + 0xb4) = 0xffff;
    }
  }
  return;
}

