// Function: FUN_8024e354
// Entry: 8024e354
// Size: 420 bytes

void FUN_8024e354(uint param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = param_1 * 0xc;
  uVar1 = DAT_803dd1f8 & 0x700;
  if (uVar1 == 0x400) goto LAB_8024e47c;
  if (uVar1 < 0x400) {
    if (uVar1 == 0x200) {
      (&DAT_803aee24)[iVar2] = (&DAT_803aee24)[iVar2] & 0xf0;
      (&DAT_803aee25)[iVar2] = (&DAT_803aee25)[iVar2] & 0xf0;
      (&DAT_803aee26)[iVar2] = (&DAT_803aee26)[iVar2] & 0xf0;
      (&DAT_803aee27)[iVar2] = (&DAT_803aee27)[iVar2] & 0xf0;
      goto LAB_8024e47c;
    }
    if (0x1ff < uVar1) goto LAB_8024e47c;
    if (uVar1 == 0x100) {
      (&DAT_803aee24)[iVar2] = (&DAT_803aee24)[iVar2] & 0xf0;
      (&DAT_803aee25)[iVar2] = (&DAT_803aee25)[iVar2] & 0xf0;
      (&DAT_803aee28)[iVar2] = (&DAT_803aee28)[iVar2] & 0xf0;
      (&DAT_803aee29)[iVar2] = (&DAT_803aee29)[iVar2] & 0xf0;
      goto LAB_8024e47c;
    }
    if ((0xff < uVar1) || (uVar1 != 0)) goto LAB_8024e47c;
  }
  else if (uVar1 != 0x600) {
    if (uVar1 < 0x600) {
      if (uVar1 != 0x500) goto LAB_8024e47c;
    }
    else if (uVar1 != 0x700) goto LAB_8024e47c;
  }
  (&DAT_803aee26)[iVar2] = (&DAT_803aee26)[iVar2] & 0xf0;
  (&DAT_803aee27)[iVar2] = (&DAT_803aee27)[iVar2] & 0xf0;
  (&DAT_803aee28)[iVar2] = (&DAT_803aee28)[iVar2] & 0xf0;
  (&DAT_803aee29)[iVar2] = (&DAT_803aee29)[iVar2] & 0xf0;
LAB_8024e47c:
  (&DAT_803aee22)[iVar2] = (&DAT_803aee22)[iVar2] + -0x80;
  (&DAT_803aee23)[iVar2] = (&DAT_803aee23)[iVar2] + -0x80;
  (&DAT_803aee24)[iVar2] = (&DAT_803aee24)[iVar2] + -0x80;
  (&DAT_803aee25)[iVar2] = (&DAT_803aee25)[iVar2] + -0x80;
  if ((((DAT_803dd1f4 & 0x80000000U >> param_1) != 0) && ('@' < (char)(&DAT_803aee22)[iVar2])) &&
     (uVar1 = FUN_802534e4(param_1), (uVar1 & 0xffff0000) == 0x9000000)) {
    (&DAT_803aee22)[iVar2] = 0;
  }
  return;
}

