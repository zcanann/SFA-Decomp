// Function: FUN_8018c630
// Entry: 8018c630
// Size: 140 bytes

void FUN_8018c630(int param_1)

{
  uint uVar1;
  byte bVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  for (bVar2 = 0; bVar2 < 10; bVar2 = bVar2 + 1) {
    uVar1 = *(uint *)(iVar3 + (uint)bVar2 * 4 + 8);
    if (uVar1 != 0) {
      FUN_8008ff08(uVar1);
    }
  }
  if (*(char *)(iVar3 + 0x5c) < '\0') {
    FUN_8003709c(param_1,0x4f);
  }
  return;
}

