// Function: FUN_8028cfa4
// Entry: 8028cfa4
// Size: 292 bytes

int FUN_8028cfa4(uint param_1,int param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  
  uVar2 = (param_2 + param_1) - 1;
  iVar1 = 0x700;
  if (uVar2 < param_1) {
    iVar1 = 0x700;
  }
  else if ((param_1 <= DAT_802c30fc) && (DAT_802c30f8 <= uVar2)) {
    if ((((param_3 & 0xff) == 0) && (DAT_802c3100 == 0)) ||
       (((param_3 & 0xff) == 1 && (DAT_802c3104 == 0)))) {
      iVar1 = 0x700;
    }
    else {
      iVar1 = 0;
      if (param_1 < DAT_802c30f8) {
        iVar1 = FUN_8028cfa4(param_1,DAT_802c30f8 - param_1,param_3);
      }
      if ((iVar1 == 0) && (DAT_802c30fc < uVar2)) {
        iVar1 = FUN_8028cfa4(DAT_802c30fc,uVar2 - DAT_802c30fc,param_3);
      }
    }
  }
  return iVar1;
}

