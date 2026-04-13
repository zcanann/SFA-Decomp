// Function: FUN_8021deb4
// Entry: 8021deb4
// Size: 92 bytes

undefined4 FUN_8021deb4(int param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(byte *)(*(int *)(param_1 + 0xb8) + 0x9fd) = *(byte *)(*(int *)(param_1 + 0xb8) + 0x9fd) | 1;
  }
  uVar1 = FUN_80020078(0x632);
  if (uVar1 == 0) {
    uVar2 = 2;
  }
  else {
    uVar2 = 8;
  }
  return uVar2;
}

