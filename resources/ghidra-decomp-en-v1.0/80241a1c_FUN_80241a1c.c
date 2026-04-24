// Function: FUN_80241a1c
// Entry: 80241a1c
// Size: 52 bytes

uint FUN_80241a1c(uint param_1,int param_2)

{
  uint uVar1;
  
  if (param_2 == 0) {
    return param_1;
  }
  if ((param_1 & 0x1f) != 0) {
    param_2 = param_2 + 0x20;
  }
  uVar1 = param_2 + 0x1fU >> 5;
  do {
    dataCacheBlockStore(param_1);
    param_1 = param_1 + 0x20;
    uVar1 = uVar1 - 1;
  } while (uVar1 != 0);
  syscall();
  return param_1;
}

