// Function: FUN_80286cd0
// Entry: 80286cd0
// Size: 160 bytes

double FUN_80286cd0(uint param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  bool bVar4;
  bool bVar5;
  
  if (param_1 != 0 || param_2 != 0) {
    uVar1 = countLeadingZeros(param_1);
    uVar3 = countLeadingZeros(param_2);
    iVar2 = uVar1 + ((int)(uVar1 << 0x1a | uVar1 >> 6) >> 0x1f & uVar3);
    uVar1 = param_1 << iVar2 | param_2 >> 0x20 - iVar2 | param_2 << iVar2 + -0x20;
    uVar3 = param_2 << iVar2;
    iVar2 = 0x43e - iVar2;
    if ((0x3ff < (uVar3 & 0x7ff)) && ((0x400 < (uVar3 & 0x7ff) || ((uVar3 & 0x800) != 0)))) {
      bVar4 = 0xfffff7ff < uVar3;
      uVar3 = uVar3 + 0x800;
      bVar5 = CARRY4(uVar1,(uint)bVar4);
      uVar1 = uVar1 + bVar4;
      iVar2 = iVar2 + (uint)bVar5;
    }
    param_2 = uVar1 << 0x15 | uVar3 >> 0xb;
    param_1 = iVar2 << 0x14 | uVar1 >> 0xb & 0xfffff;
  }
  return (double)(float)(double)CONCAT44(param_1,param_2);
}

