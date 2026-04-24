// Function: FUN_8021e4f0
// Entry: 8021e4f0
// Size: 84 bytes

undefined4 FUN_8021e4f0(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  if (*(char *)(*(int *)(param_1 + 0x4c) + 0x19) == '\0') {
    iVar2 = FUN_8001ffb4(0x631);
    if (iVar2 == 0) {
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

