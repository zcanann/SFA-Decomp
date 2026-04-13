// Function: FUN_80254238
// Entry: 80254238
// Size: 128 bytes

int FUN_80254238(int param_1)

{
  int iVar1;
  byte abStack_c [4];
  
  iVar1 = FUN_802540c4(param_1);
  if ((iVar1 != 0) && ((&DAT_803af080)[param_1 * 0x10] == 0)) {
    iVar1 = FUN_80254e44(param_1,0,abStack_c);
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else {
      iVar1 = 1;
    }
  }
  return iVar1;
}

