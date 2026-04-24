// Function: FUN_8008038c
// Entry: 8008038c
// Size: 80 bytes

uint FUN_8008038c(int param_1)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = (param_1 * 0x3c) / 0x3c + (param_1 * 0x3c >> 0x1f);
  uVar2 = FUN_80022264(0,iVar1 - (iVar1 >> 0x1f));
  uVar2 = countLeadingZeros(uVar2);
  return uVar2 >> 5;
}

