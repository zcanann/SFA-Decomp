// Function: FUN_802be0b0
// Entry: 802be0b0
// Size: 204 bytes

void FUN_802be0b0(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 == -1) {
    FUN_8003b8f4((double)FLOAT_803e8338);
    FUN_8003842c(param_1,0xb,iVar1 + 0x1438,iVar1 + 0x143c,&DAT_00001440 + iVar1,0);
    FUN_80038280(param_1,3,4,iVar1 + 0xb18);
  }
  else if (in_r8 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e8338);
    FUN_8003842c(param_1,0xb,iVar1 + 0x1438,iVar1 + 0x143c,&DAT_00001440 + iVar1,0);
    FUN_80038280(param_1,3,4,iVar1 + 0xb18);
    FUN_80114dec(param_1,iVar1 + 0x3ec,0);
  }
  return;
}

