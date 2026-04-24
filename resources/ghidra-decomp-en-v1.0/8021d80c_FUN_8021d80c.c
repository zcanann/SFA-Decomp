// Function: FUN_8021d80c
// Entry: 8021d80c
// Size: 92 bytes

undefined4 FUN_8021d80c(int param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(byte *)(*(int *)(param_1 + 0xb8) + 0x9fd) = *(byte *)(*(int *)(param_1 + 0xb8) + 0x9fd) | 1;
  }
  iVar1 = FUN_8001ffb4(0x632);
  if (iVar1 == 0) {
    uVar2 = 2;
  }
  else {
    uVar2 = 8;
  }
  return uVar2;
}

