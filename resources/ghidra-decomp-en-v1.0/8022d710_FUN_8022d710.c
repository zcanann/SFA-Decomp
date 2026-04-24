// Function: FUN_8022d710
// Entry: 8022d710
// Size: 40 bytes

undefined4 FUN_8022d710(int param_1)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 0x478);
  if ((cVar1 == '\x05') || (cVar1 == '\x06')) {
    uVar2 = 1;
  }
  return uVar2;
}

