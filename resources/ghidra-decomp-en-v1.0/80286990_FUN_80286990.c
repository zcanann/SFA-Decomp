// Function: FUN_80286990
// Entry: 80286990
// Size: 224 bytes

undefined4 FUN_80286990(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  FUN_8028aefc(&DAT_803d68f0);
  if (DAT_803d68f4 == 2) {
    uVar2 = 0x100;
  }
  else {
    iVar1 = DAT_803d68f8 + DAT_803d68f4 >> 0x1f;
    iVar1 = (DAT_803d68f8 + DAT_803d68f4 & 1U ^ -iVar1) + iVar1;
    FUN_80003514(&DAT_803d68fc + iVar1 * 0xc,param_1,0xc);
    (&DAT_803d6900)[iVar1 * 3] = DAT_803d6914;
    DAT_803d6914 = DAT_803d6914 + 1;
    if (DAT_803d6914 < 0x100) {
      DAT_803d6914 = 0x100;
    }
    DAT_803d68f4 = DAT_803d68f4 + 1;
  }
  FUN_8028aef4(&DAT_803d68f0);
  return uVar2;
}

