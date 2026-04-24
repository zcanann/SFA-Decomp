// Function: FUN_801895a0
// Entry: 801895a0
// Size: 112 bytes

void FUN_801895a0(int param_1,int param_2)

{
  int iVar1;
  
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  *(undefined *)(*(int *)(param_1 + 0xb8) + 0x16) = 1;
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1c));
  if (iVar1 == 0) {
    FUN_8004350c(0,0,1);
  }
  *(code **)(param_1 + 0xbc) = FUN_80188cc0;
  return;
}

