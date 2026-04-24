// Function: FUN_801c3cc4
// Entry: 801c3cc4
// Size: 612 bytes

void FUN_801c3cc4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  byte bVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  int local_28;
  int local_24 [5];
  
  iVar2 = *(int *)(param_9 + 0x4c);
  iVar7 = *(int *)(param_9 + 0xb8);
  if (((iVar2 != 0) && (*(short *)(iVar2 + 0x18) != -1)) && (*(int *)(iVar2 + 0x14) != 0x4ca62)) {
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(iVar7 + 0x8b); iVar2 = iVar2 + 1) {
      bVar1 = *(byte *)(iVar7 + iVar2 + 0x81);
      if (bVar1 == 2) {
        *(undefined *)(iVar7 + 0x144) = 1;
      }
      else if ((bVar1 < 2) && (bVar1 != 0)) {
        *(undefined *)(iVar7 + 0x144) = 0;
      }
    }
    local_24[2] = (int)DAT_803dc071;
    local_24[1] = 0x43300000;
    local_28 = (**(code **)(*DAT_803dd6d4 + 0x14))
                         ((double)(float)((double)CONCAT44(0x43300000,local_24[2]) - DOUBLE_803e5b38
                                         ),param_9);
    if ((local_28 != 0) && (*(short *)(param_9 + 0xb4) == -2)) {
      iVar6 = (int)*(char *)(iVar7 + 0x57);
      iVar2 = 0;
      uVar8 = extraout_f1;
      piVar3 = (int *)FUN_8002e1f4(&local_28,local_24);
      iVar5 = 0;
      for (local_28 = 0; local_28 < local_24[0]; local_28 = local_28 + 1) {
        iVar4 = *piVar3;
        if (*(short *)(iVar4 + 0xb4) == iVar6) {
          iVar2 = iVar4;
        }
        if (((*(short *)(iVar4 + 0xb4) == -2) && (*(short *)(iVar4 + 0x44) == 0x10)) &&
           (iVar6 == *(char *)(*(int *)(iVar4 + 0xb8) + 0x57))) {
          iVar5 = iVar5 + 1;
        }
        piVar3 = piVar3 + 1;
      }
      if (((iVar5 < 2) && (iVar2 != 0)) && (*(short *)(iVar2 + 0xb4) != -1)) {
        *(undefined2 *)(iVar2 + 0xb4) = 0xffff;
        uVar8 = (**(code **)(*DAT_803dd6d4 + 0x4c))(iVar6);
      }
      *(undefined2 *)(param_9 + 0xb4) = 0xffff;
      FUN_8002cc9c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
    *(float *)(iVar7 + 0x148) = *(float *)(iVar7 + 0x148) - FLOAT_803dc074;
    if (*(float *)(iVar7 + 0x148) < FLOAT_803e5b34) {
      iVar2 = FUN_8002bac4();
      local_24[2] = FUN_80022264(0xb4,0xf0);
      local_24[2] = local_24[2] ^ 0x80000000;
      local_24[1] = 0x43300000;
      *(float *)(iVar7 + 0x148) =
           (float)((double)CONCAT44(0x43300000,local_24[2]) - DOUBLE_803e5b40);
      if ((*(char *)(param_9 + 0xac) == -1) &&
         ((iVar2 == 0 || (iVar2 = FUN_8005b128(), iVar2 == 0xb)))) {
        FUN_8000bb38(param_9,0x4a0);
      }
    }
  }
  return;
}

