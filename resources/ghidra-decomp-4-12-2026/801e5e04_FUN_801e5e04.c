// Function: FUN_801e5e04
// Entry: 801e5e04
// Size: 400 bytes

void FUN_801e5e04(int param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(undefined2 *)(iVar3 + 0x6a) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar3 + 0x6e) = 0xffff;
  *(float *)(iVar3 + 0x24) =
       FLOAT_803e65f4 /
       (FLOAT_803e65f4 +
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - DOUBLE_803e6600));
  *(undefined4 *)(iVar3 + 0x28) = 0xffffffff;
  iVar2 = *(int *)(param_1 + 0xf4);
  if ((iVar2 == 0) && (*(short *)(param_2 + 0x18) != 1)) {
    (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar3);
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  else if ((iVar2 != 0) && ((int)*(short *)(param_2 + 0x18) != iVar2 + -1)) {
    (**(code **)(*DAT_803dd6d4 + 0x24))(iVar3);
    if (*(short *)(param_2 + 0x18) != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar3,param_2);
    }
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  if (*(short *)(param_1 + 0x46) == 0x171) {
    piVar1 = FUN_8001f58c(param_1,'\x01');
    if (piVar1 != (int *)0x0) {
      FUN_8001dbf0((int)piVar1,2);
      FUN_8001dbb4((int)piVar1,200,0x3c,0,0);
      FUN_8001dcfc((double)FLOAT_803e6608,(double)FLOAT_803e660c,(int)piVar1);
    }
    *(int **)(param_1 + 0xf8) = piVar1;
  }
  FLOAT_803de8d0 = FLOAT_803e65f0;
  uRam803de8d4 = 0;
  return;
}

