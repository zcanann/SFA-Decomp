// Function: FUN_801c3974
// Entry: 801c3974
// Size: 492 bytes

void FUN_801c3974(int param_1,int param_2)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(int *)(param_2 + 0x14) != 0x4ca62) {
    *(undefined2 *)(iVar4 + 0x6a) = *(undefined2 *)(param_2 + 0x1a);
    *(undefined2 *)(iVar4 + 0x6e) = 0xffff;
    *(float *)(iVar4 + 0x24) =
         FLOAT_803e4e98 /
         (FLOAT_803e4e98 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - DOUBLE_803e4ea0));
    *(undefined4 *)(iVar4 + 0x28) = 0xffffffff;
    iVar3 = *(int *)(param_1 + 0xf4);
    if ((iVar3 == 0) && (*(short *)(param_2 + 0x18) != 1)) {
      (**(code **)(*DAT_803dca54 + 0x1c))(iVar4);
      *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
    }
    else if ((iVar3 != 0) && ((int)*(short *)(param_2 + 0x18) != iVar3 + -1)) {
      (**(code **)(*DAT_803dca54 + 0x24))(iVar4);
      if (*(short *)(param_2 + 0x18) != -1) {
        (**(code **)(*DAT_803dca54 + 0x1c))(iVar4,param_2);
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
      uVar1 = FUN_8001f4c8(iVar3,1);
      *(undefined4 *)(iVar4 + 0x140) = uVar1;
      if (*(int *)(iVar4 + 0x140) != 0) {
        FUN_8001db2c(*(int *)(iVar4 + 0x140),2);
        FUN_8001daf0(*(undefined4 *)(iVar4 + 0x140),0x96,0x32,0xff,0xff);
        FUN_8001dc38((double)FLOAT_803e4eb0,(double)FLOAT_803e4eb4,*(undefined4 *)(iVar4 + 0x140));
      }
    }
    *(undefined *)(param_1 + 0x36) = 0;
    *(undefined *)(param_1 + 0x37) = 0;
    uVar2 = FUN_800221a0(0xb4,0xf0);
    *(float *)(iVar4 + 0x148) =
         (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e4ea8);
  }
  return;
}

