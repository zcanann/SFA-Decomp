// Function: FUN_8015e5dc
// Entry: 8015e5dc
// Size: 444 bytes

undefined4 FUN_8015e5dc(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int local_28;
  int local_24 [5];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80035f20();
  }
  FUN_80035df4(param_1,10,1,0xffffffff);
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6c) = 10;
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6d) = 1;
  FUN_8003393c(param_1);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    iVar1 = FUN_8002e0fc(&local_28,local_24);
    for (; local_28 < local_24[0]; local_28 = local_28 + 1) {
      iVar2 = *(int *)(iVar1 + local_28 * 4);
      if ((iVar2 != param_1) && (*(short *)(iVar2 + 0x46) == 0x306)) {
        (**(code **)(**(int **)(iVar2 + 0x68) + 0x24))(iVar2,0x81,0);
      }
    }
    iVar1 = FUN_800221a0(0,1);
    if (iVar1 == 0) {
      if (*(char *)(param_2 + 0x27a) != '\0') {
        FUN_80030334((double)FLOAT_803e2dc8,param_1,7,0);
        *(undefined *)(param_2 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_2 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e2dc8,param_1,6,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    *(undefined *)(param_2 + 0x34d) = 1;
    *(float *)(param_2 + 0x2a0) =
         FLOAT_803e2ddc +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar3 + 0x406)) - DOUBLE_803e2dc0) /
         FLOAT_803e2de0;
  }
  *(float *)(param_2 + 0x280) = FLOAT_803e2dc8;
  return 0;
}

