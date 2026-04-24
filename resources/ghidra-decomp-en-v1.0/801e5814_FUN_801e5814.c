// Function: FUN_801e5814
// Entry: 801e5814
// Size: 400 bytes

void FUN_801e5814(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined2 *)(iVar2 + 0x6a) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar2 + 0x6e) = 0xffff;
  *(float *)(iVar2 + 0x24) =
       FLOAT_803e595c /
       (FLOAT_803e595c +
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - DOUBLE_803e5968));
  *(undefined4 *)(iVar2 + 0x28) = 0xffffffff;
  iVar1 = *(int *)(param_1 + 0xf4);
  if ((iVar1 == 0) && (*(short *)(param_2 + 0x18) != 1)) {
    (**(code **)(*DAT_803dca54 + 0x1c))(iVar2);
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  else if ((iVar1 != 0) && ((int)*(short *)(param_2 + 0x18) != iVar1 + -1)) {
    (**(code **)(*DAT_803dca54 + 0x24))(iVar2);
    if (*(short *)(param_2 + 0x18) != -1) {
      (**(code **)(*DAT_803dca54 + 0x1c))(iVar2,param_2);
    }
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  if (*(short *)(param_1 + 0x46) == 0x171) {
    iVar1 = FUN_8001f4c8(param_1,1);
    if (iVar1 != 0) {
      FUN_8001db2c(iVar1,2);
      FUN_8001daf0(iVar1,200,0x3c,0,0);
      FUN_8001dc38((double)FLOAT_803e5970,(double)FLOAT_803e5974,iVar1);
    }
    *(int *)(param_1 + 0xf8) = iVar1;
  }
  FLOAT_803ddc50 = FLOAT_803e5958;
  uRam803ddc54 = 0;
  return;
}

