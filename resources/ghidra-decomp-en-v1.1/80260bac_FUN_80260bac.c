// Function: FUN_80260bac
// Entry: 80260bac
// Size: 100 bytes

int FUN_80260bac(int param_1,undefined4 param_2,uint param_3,undefined4 param_4,undefined4 param_5)

{
  int iVar1;
  
  iVar1 = param_1 * 0x110;
  if ((&DAT_803afe40)[param_1 * 0x44] == 0) {
    iVar1 = -3;
  }
  else {
    *(undefined4 *)(&DAT_803aff14 + iVar1) = param_5;
    *(uint *)(&DAT_803afeec + iVar1) = param_3 >> 7;
    *(undefined4 *)(&DAT_803afef0 + iVar1) = param_2;
    *(undefined4 *)(&DAT_803afef4 + iVar1) = param_4;
    iVar1 = FUN_8025f25c(param_1,-0x7fd9f530);
  }
  return iVar1;
}

