// Function: FUN_80037a04
// Entry: 80037a04
// Size: 100 bytes

bool FUN_80037a04(int param_1)

{
  int iVar1;
  
  FUN_8002b9ec();
  iVar1 = FUN_80295cd4();
  if (iVar1 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  return iVar1 == 0;
}

