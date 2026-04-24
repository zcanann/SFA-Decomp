// Function: FUN_8021eb34
// Entry: 8021eb34
// Size: 84 bytes

undefined4 FUN_8021eb34(int param_1)

{
  undefined4 uVar1;
  uint uVar2;
  
  if (*(char *)(*(int *)(param_1 + 0x4c) + 0x19) == '\0') {
    uVar2 = FUN_80020078(0x631);
    if (uVar2 == 0) {
      uVar1 = 5;
    }
    else {
      uVar1 = 8;
    }
  }
  else {
    uVar1 = 10;
  }
  return uVar1;
}

