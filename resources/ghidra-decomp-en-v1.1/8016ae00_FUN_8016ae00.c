// Function: FUN_8016ae00
// Entry: 8016ae00
// Size: 112 bytes

void FUN_8016ae00(void)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = FUN_80286840();
  uVar2 = FUN_800803dc((float *)(*(int *)(iVar1 + 0xb8) + 0x20));
  if (uVar2 == 0) {
    FUN_8003b9ec(iVar1);
  }
  FUN_8028688c();
  return;
}

