// Function: FUN_8022de44
// Entry: 8022de44
// Size: 72 bytes

void FUN_8022de44(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_8003709c(param_1,0x26);
  DAT_803dea08 = 0;
  uVar1 = *(uint *)(iVar2 + 0x450);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
  }
  return;
}

