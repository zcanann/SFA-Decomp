// Function: FUN_802864b8
// Entry: 802864b8
// Size: 180 bytes

double FUN_802864b8(uint param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  bool bVar5;
  bool bVar6;
  
  uVar1 = param_1 & 0x80000000;
  if (uVar1 != 0) {
    bVar5 = param_2 != 0;
    param_2 = -param_2;
    param_1 = -(bVar5 + param_1);
  }
  if ((param_1 | param_2) != 0) {
    uVar2 = countLeadingZeros(param_1);
    uVar4 = countLeadingZeros(param_2);
    iVar3 = uVar2 + ((int)(uVar2 << 0x1a | uVar2 >> 6) >> 0x1f & uVar4);
    uVar2 = param_1 << iVar3 | param_2 >> 0x20 - iVar3 | param_2 << iVar3 + -0x20;
    param_2 = param_2 << iVar3;
    iVar3 = 0x43e - iVar3;
    if ((0x3ff < (param_2 & 0x7ff)) && ((0x400 < (param_2 & 0x7ff) || ((param_2 & 0x800) != 0)))) {
      bVar5 = 0xfffff7ff < param_2;
      param_2 = param_2 + 0x800;
      bVar6 = CARRY4(uVar2,(uint)bVar5);
      uVar2 = uVar2 + bVar5;
      iVar3 = iVar3 + (uint)bVar6;
    }
    param_2 = uVar2 << 0x15 | param_2 >> 0xb;
    param_1 = uVar1 | iVar3 << 0x14 | uVar2 >> 0xb & 0xfffff;
  }
  return (double)(float)(double)CONCAT44(param_1,param_2);
}

