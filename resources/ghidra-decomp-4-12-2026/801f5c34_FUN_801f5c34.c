// Function: FUN_801f5c34
// Entry: 801f5c34
// Size: 136 bytes

void FUN_801f5c34(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_801f5260(param_1,iVar1);
  *(undefined *)(param_1 + 0x36) = 0;
  *(code **)(param_1 + 0xbc) = FUN_801f523c;
  FUN_80037a5c(param_1,1);
  FUN_800803f8((undefined4 *)(iVar1 + 0x74));
  if (*(short *)(param_2 + 0x1a) == 0x7f) {
    FUN_80080404((float *)(iVar1 + 0x74),0xe10);
  }
  return;
}

