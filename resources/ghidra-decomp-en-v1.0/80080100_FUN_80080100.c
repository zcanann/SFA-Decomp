// Function: FUN_80080100
// Entry: 80080100
// Size: 80 bytes

uint FUN_80080100(int param_1)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  
  iVar1 = (param_1 * 0x3c) / 0x3c + (param_1 * 0x3c >> 0x1f);
  uVar3 = FUN_800221a0(0,iVar1 - (iVar1 >> 0x1f));
  uVar2 = countLeadingZeros(uVar3);
  return uVar2 >> 5;
}

