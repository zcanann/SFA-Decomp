// Function: FUN_8015e3a0
// Entry: 8015e3a0
// Size: 384 bytes

undefined4 FUN_8015e3a0(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int local_18;
  int local_14;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80035f20();
  }
  FUN_80035df4(param_1,10,1,0xffffffff);
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6c) = 10;
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6d) = 1;
  FUN_8003393c(param_1);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    iVar1 = FUN_8002e0fc(&local_18,&local_14);
    for (; local_18 < local_14; local_18 = local_18 + 1) {
      iVar2 = *(int *)(iVar1 + local_18 * 4);
      if ((iVar2 != param_1) && (*(short *)(iVar2 + 0x46) == 0x306)) {
        (**(code **)(**(int **)(iVar2 + 0x68) + 0x24))(iVar2,0x81,0);
      }
    }
  }
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2dd8;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2dc8,param_1,10,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(undefined *)(param_2 + 0x34d) = 1;
  if ((*(uint *)(param_2 + 0x314) & 1) != 0) {
    iVar3 = *(int *)(iVar3 + 0x40c);
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffffe;
    *(byte *)(iVar3 + 8) = *(byte *)(iVar3 + 8) | 1;
    FUN_8000bb18(param_1,0x266);
  }
  return 0;
}

