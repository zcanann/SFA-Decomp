// Function: FUN_801e7fec
// Entry: 801e7fec
// Size: 160 bytes

void FUN_801e7fec(int param_1)

{
  char in_r8;
  int iVar1;
  float local_18 [4];
  
  iVar1 = *(int *)(param_1 + 0xb8);
  local_18[0] = FLOAT_803e59d8;
  if ((*(short *)(iVar1 + 0x274) != 7) && (in_r8 != '\0')) {
    FUN_8003b8f4();
    FUN_80114dec(param_1,iVar1 + 0x35c,0);
  }
  if ((*(byte *)(iVar1 + 0x9d4) & 0x20) != 0) {
    (**(code **)(*DAT_803dcab4 + 0xc))(param_1,0x7ef,local_18,0x50,0);
  }
  return;
}

