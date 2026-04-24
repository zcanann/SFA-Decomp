// Function: FUN_8028656c
// Entry: 8028656c
// Size: 160 bytes

double FUN_8028656c(uint param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  bool bVar4;
  bool bVar5;
  
  if ((param_1 | param_2) != 0) {
    uVar1 = countLeadingZeros(param_1);
    uVar3 = countLeadingZeros(param_2);
    iVar2 = uVar1 + ((int)(uVar1 << 0x1a | uVar1 >> 6) >> 0x1f & uVar3);
    uVar1 = param_1 << iVar2 | param_2 >> 0x20 - iVar2 | param_2 << iVar2 + -0x20;
    param_2 = param_2 << iVar2;
    iVar2 = 0x43e - iVar2;
    if ((0x3ff < (param_2 & 0x7ff)) && ((0x400 < (param_2 & 0x7ff) || ((param_2 & 0x800) != 0)))) {
      bVar4 = 0xfffff7ff < param_2;
      param_2 = param_2 + 0x800;
      bVar5 = CARRY4(uVar1,(uint)bVar4);
      uVar1 = uVar1 + bVar4;
      iVar2 = iVar2 + (uint)bVar5;
    }
    param_2 = uVar1 << 0x15 | param_2 >> 0xb;
    param_1 = iVar2 << 0x14 | uVar1 >> 0xb & 0xfffff;
  }
  return (double)(float)(double)CONCAT44(param_1,param_2);
}

