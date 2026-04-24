// Function: FUN_80164084
// Entry: 80164084
// Size: 252 bytes

void FUN_80164084(int param_1)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int unaff_r30;
  int local_18;
  int local_14 [2];
  
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x4ba) {
    unaff_r30 = 0x4b9;
  }
  else if (sVar1 < 0x4ba) {
    if (sVar1 == 0x3fb) {
      unaff_r30 = 0x3fd;
    }
    else if ((sVar1 < 0x3fb) && (sVar1 == 0x39d)) {
      unaff_r30 = 0x28d;
    }
  }
  else if (sVar1 == 0x4c1) {
    unaff_r30 = 0x4be;
  }
  iVar2 = FUN_8002e0fc(local_14,&local_18);
  for (; local_14[0] < local_18; local_14[0] = local_14[0] + 1) {
    iVar3 = *(int *)(iVar2 + local_14[0] * 4);
    if (unaff_r30 == *(short *)(iVar3 + 0x46)) {
      (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(iVar3,param_1);
    }
  }
  FUN_80036fa4(param_1,3);
  FUN_80036fa4(param_1,0x31);
  return;
}

