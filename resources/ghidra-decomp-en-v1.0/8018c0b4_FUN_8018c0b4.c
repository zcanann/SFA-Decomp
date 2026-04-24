// Function: FUN_8018c0b4
// Entry: 8018c0b4
// Size: 140 bytes

void FUN_8018c0b4(int param_1)

{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  for (bVar1 = 0; bVar1 < 10; bVar1 = bVar1 + 1) {
    if (*(int *)(iVar2 + (uint)bVar1 * 4 + 8) != 0) {
      FUN_8008fc7c();
    }
  }
  if (*(char *)(iVar2 + 0x5c) < '\0') {
    FUN_80036fa4(param_1,0x4f);
  }
  return;
}

