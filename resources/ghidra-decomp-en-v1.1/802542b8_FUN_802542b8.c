// Function: FUN_802542b8
// Entry: 802542b8
// Size: 180 bytes

undefined4 FUN_802542b8(int param_1)

{
  int iVar1;
  undefined4 uVar2;
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
  if (iVar1 == 0) {
    if ((&DAT_800030c0)[param_1] == 0) {
      uVar2 = 0xffffffff;
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}

