// Function: FUN_8025ce04
// Entry: 8025ce04
// Size: 212 bytes

undefined4 FUN_8025ce04(void)

{
  uint uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  
  if (*(int *)(DAT_803dc5a8 + 0x4f4) != 0) {
    FUN_802587fc();
  }
  uVar1 = *(uint *)(DAT_803de0a8 + 0x14);
  FUN_80256288(&DAT_803aecc0);
  FUN_80255fe0(DAT_803de0f0);
  if (*(char *)(DAT_803dc5a8 + 0x4f1) != '\0') {
    uVar2 = FUN_8024377c();
    uVar3 = *(undefined4 *)(DAT_803dc5a8 + 8);
    FUN_80003494(DAT_803dc5a8,&DAT_803aece4,0x4f8);
    *(undefined4 *)(DAT_803dc5a8 + 8) = uVar3;
    FUN_802437a4(uVar2);
  }
  *(undefined *)(DAT_803dc5a8 + 0x4f0) = 0;
  uVar2 = DAT_803aecdc;
  if ((uVar1 >> 0x1a & 1) != 0) {
    uVar2 = 0;
  }
  return uVar2;
}

