// Function: FUN_801c3f28
// Entry: 801c3f28
// Size: 492 bytes

void FUN_801c3f28(int param_1,int param_2)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(int *)(param_2 + 0x14) != 0x4ca62) {
    *(undefined2 *)(iVar4 + 0x6a) = *(undefined2 *)(param_2 + 0x1a);
    *(undefined2 *)(iVar4 + 0x6e) = 0xffff;
    *(float *)(iVar4 + 0x24) =
         FLOAT_803e5b30 /
         (FLOAT_803e5b30 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - DOUBLE_803e5b38));
    *(undefined4 *)(iVar4 + 0x28) = 0xffffffff;
    iVar3 = *(int *)(param_1 + 0xf4);
    if ((iVar3 == 0) && (*(short *)(param_2 + 0x18) != 1)) {
      (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar4);
      *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
    }
    else if ((iVar3 != 0) && ((int)*(short *)(param_2 + 0x18) != iVar3 + -1)) {
      (**(code **)(*DAT_803dd6d4 + 0x24))(iVar4);
      if (*(short *)(param_2 + 0x18) != -1) {
        (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar4,param_2);
      }
      *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
    }
    if (*(short *)(param_1 + 0x46) != 0x1d9) {
      *(undefined *)(iVar4 + 0x144) = 1;
    }
    if (*(int *)(iVar4 + 0x140) == 0) {
      iVar3 = param_1;
      if (*(char *)(iVar4 + 0x144) != '\0') {
        iVar3 = 0;
      }
      piVar1 = FUN_8001f58c(iVar3,'\x01');
      *(int **)(iVar4 + 0x140) = piVar1;
      if (*(int *)(iVar4 + 0x140) != 0) {
        FUN_8001dbf0(*(int *)(iVar4 + 0x140),2);
        FUN_8001dbb4(*(int *)(iVar4 + 0x140),0x96,0x32,0xff,0xff);
        FUN_8001dcfc((double)FLOAT_803e5b48,(double)FLOAT_803e5b4c,*(int *)(iVar4 + 0x140));
      }
    }
    *(undefined *)(param_1 + 0x36) = 0;
    *(undefined *)(param_1 + 0x37) = 0;
    uVar2 = FUN_80022264(0xb4,0xf0);
    *(float *)(iVar4 + 0x148) =
         (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5b40);
  }
  return;
}

