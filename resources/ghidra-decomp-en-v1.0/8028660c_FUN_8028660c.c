// Function: FUN_8028660c
// Entry: 8028660c
// Size: 204 bytes

undefined8 FUN_8028660c(ulonglong param_1)

{
  bool bVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint local_8;
  uint uStack4;
  
  local_8 = (uint)(param_1 >> 0x20);
  uStack4 = (uint)param_1;
  uVar3 = local_8 >> 0x14 & 0x7ff;
  if (uVar3 < 0x3ff) {
    uVar2 = 0;
    uStack4 = 0;
  }
  else {
    uVar2 = local_8 & 0xfffff | 0x100000;
    iVar4 = uVar3 - 0x433;
    if (iVar4 < 0) {
      iVar4 = -iVar4;
      uStack4 = uStack4 >> iVar4 | uVar2 << uVar3 - 0x413 | uVar2 >> iVar4 + -0x20;
      uVar2 = uVar2 >> iVar4;
    }
    else {
      if (10 < iVar4) {
        if ((param_1 & 0x8000000000000000) == 0) {
          uVar2 = 0x7fffffff;
          uStack4 = 0xffffffff;
        }
        else {
          uVar2 = 0x80000000;
          uStack4 = 0;
        }
        goto LAB_802866d0;
      }
      uVar2 = uVar2 << iVar4 | uStack4 >> 0x20 - iVar4 | uStack4 << uVar3 - 0x453;
      uStack4 = uStack4 << iVar4;
    }
    if ((param_1 & 0x8000000000000000) != 0) {
      bVar1 = uStack4 != 0;
      uStack4 = -uStack4;
      uVar2 = -(bVar1 + uVar2);
    }
  }
LAB_802866d0:
  return CONCAT44(uVar2,uStack4);
}

