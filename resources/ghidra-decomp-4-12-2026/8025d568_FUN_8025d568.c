// Function: FUN_8025d568
// Entry: 8025d568
// Size: 212 bytes

undefined4 FUN_8025d568(undefined4 param_1,undefined4 param_2,uint param_3)

{
  uint uVar1;
  undefined4 uVar2;
  
  if (*(int *)(DAT_803dd210 + 0x4f4) != 0) {
    FUN_80258f60(DAT_803dd210,&DAT_803b0000,param_3);
  }
  uVar1 = *(uint *)(DAT_803ded28 + 0x14);
  FUN_802569ec(&DAT_803af920,DAT_803ded28,param_3);
  FUN_80256744(DAT_803ded70);
  if (*(char *)(DAT_803dd210 + 0x4f1) != '\0') {
    FUN_80243e74();
    uVar2 = *(undefined4 *)(DAT_803dd210 + 8);
    FUN_80003494(DAT_803dd210,0x803af944,0x4f8);
    *(undefined4 *)(DAT_803dd210 + 8) = uVar2;
    FUN_80243e9c();
  }
  *(undefined *)(DAT_803dd210 + 0x4f0) = 0;
  uVar2 = DAT_803af93c;
  if ((uVar1 >> 0x1a & 1) != 0) {
    uVar2 = 0;
  }
  return uVar2;
}

