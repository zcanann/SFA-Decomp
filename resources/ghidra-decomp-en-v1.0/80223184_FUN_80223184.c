// Function: FUN_80223184
// Entry: 80223184
// Size: 96 bytes

void FUN_80223184(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(short *)(param_1 + 0xa0) == 0x203) {
    uVar1 = FUN_800394a0();
    FUN_8003aae0(param_1,uVar1,*(undefined *)(iVar2 + 0x610),0,100000);
  }
  return;
}

