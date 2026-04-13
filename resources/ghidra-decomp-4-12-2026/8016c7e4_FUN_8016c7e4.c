// Function: FUN_8016c7e4
// Entry: 8016c7e4
// Size: 372 bytes

void FUN_8016c7e4(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  FUN_8002b9a0(param_1,'d');
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined2 *)(iVar2 + 0x6a) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar2 + 0x6e) = 0xffff;
  *(float *)(iVar2 + 0x24) =
       FLOAT_803e3ec0 /
       (FLOAT_803e3ec0 +
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - DOUBLE_803e3ed0));
  *(undefined4 *)(iVar2 + 0x28) = 0xffffffff;
  *(undefined4 *)(iVar2 + 0x98) = 0;
  *(undefined4 *)(iVar2 + 0x94) = 0;
  *(undefined2 *)(iVar2 + 0x116) = 0;
  *(undefined2 *)(iVar2 + 0x114) = 0;
  *(undefined4 *)(iVar2 + 0xe8) = 0;
  iVar1 = *(int *)(param_1 + 0xf4);
  if ((iVar1 == 0) && (*(short *)(param_2 + 0x18) != 1)) {
    (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar2,param_2);
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  else if ((iVar1 != 0) && ((int)*(short *)(param_2 + 0x18) != iVar1 + -1)) {
    (**(code **)(*DAT_803dd6d4 + 0x24))(iVar2);
    if (*(short *)(param_2 + 0x18) != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar2,param_2);
    }
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  if (*(int *)(param_1 + 100) != 0) {
    *(undefined *)(*(int *)(param_1 + 100) + 0x3a) = 100;
    *(undefined *)(*(int *)(param_1 + 100) + 0x3b) = 0x96;
  }
  FUN_8002a84c(param_1,0xff);
  return;
}

