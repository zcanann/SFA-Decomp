// Function: FUN_80286a70
// Entry: 80286a70
// Size: 180 bytes

undefined4 FUN_80286a70(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  FUN_8028aefc(&DAT_803d68f0);
  if (0 < DAT_803d68f4) {
    FUN_80003514(param_1,&DAT_803d68fc + DAT_803d68f8 * 0xc,0xc);
    DAT_803d68f8 = DAT_803d68f8 + 1;
    DAT_803d68f4 = DAT_803d68f4 + -1;
    if (DAT_803d68f8 == 2) {
      DAT_803d68f8 = 0;
    }
    uVar1 = 1;
  }
  FUN_8028aef4(&DAT_803d68f0);
  return uVar1;
}

