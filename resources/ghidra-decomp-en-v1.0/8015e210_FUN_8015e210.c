// Function: FUN_8015e210
// Entry: 8015e210
// Size: 400 bytes

undefined4 FUN_8015e210(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int local_18;
  int local_14;
  
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2dc8,param_1,0,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  if (*(char *)(param_2 + 0x27a) != '\0') {
    iVar1 = FUN_8002e0fc(&local_18,&local_14);
    for (; local_18 < local_14; local_18 = local_18 + 1) {
      iVar2 = *(int *)(iVar1 + local_18 * 4);
      if ((iVar2 != param_1) && (*(short *)(iVar2 + 0x46) == 0x306)) {
        (**(code **)(**(int **)(iVar2 + 0x68) + 0x24))(iVar2,0x81,0);
      }
    }
    iVar1 = FUN_8002b9ec();
    iVar2 = *(int *)(iVar1 + 200);
    iVar1 = FUN_8002b9ec();
    iVar2 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x44))(iVar2);
    if (iVar2 == 0) {
      if (*(short *)(iVar1 + 0x46) == 0) {
        FUN_8000bb18(param_1,0x239);
      }
      else {
        FUN_8000bb18(param_1,0x1f2);
      }
    }
    else if (*(short *)(iVar1 + 0x46) == 0) {
      FUN_8000bb18(param_1,0x95);
    }
    else {
      FUN_8000bb18(param_1,0x1f2);
    }
    FUN_8000bb18(param_1,0x267);
  }
  *(undefined *)(param_2 + 0x34d) = 3;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2dd4;
  *(float *)(param_2 + 0x280) = FLOAT_803e2dc8;
  return 0;
}

