// Function: FUN_8024dbf0
// Entry: 8024dbf0
// Size: 420 bytes

void FUN_8024dbf0(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = param_1 * 0xc;
  uVar1 = DAT_803dc590 & 0x700;
  if (uVar1 == 0x400) goto LAB_8024dd18;
  if (uVar1 < 0x400) {
    if (uVar1 == 0x200) {
      (&DAT_803ae1c4)[iVar2] = (&DAT_803ae1c4)[iVar2] & 0xf0;
      (&DAT_803ae1c5)[iVar2] = (&DAT_803ae1c5)[iVar2] & 0xf0;
      (&DAT_803ae1c6)[iVar2] = (&DAT_803ae1c6)[iVar2] & 0xf0;
      (&DAT_803ae1c7)[iVar2] = (&DAT_803ae1c7)[iVar2] & 0xf0;
      goto LAB_8024dd18;
    }
    if (0x1ff < uVar1) goto LAB_8024dd18;
    if (uVar1 == 0x100) {
      (&DAT_803ae1c4)[iVar2] = (&DAT_803ae1c4)[iVar2] & 0xf0;
      (&DAT_803ae1c5)[iVar2] = (&DAT_803ae1c5)[iVar2] & 0xf0;
      (&DAT_803ae1c8)[iVar2] = (&DAT_803ae1c8)[iVar2] & 0xf0;
      (&DAT_803ae1c9)[iVar2] = (&DAT_803ae1c9)[iVar2] & 0xf0;
      goto LAB_8024dd18;
    }
    if ((0xff < uVar1) || (uVar1 != 0)) goto LAB_8024dd18;
  }
  else if (uVar1 != 0x600) {
    if (uVar1 < 0x600) {
      if (uVar1 != 0x500) goto LAB_8024dd18;
    }
    else if (uVar1 != 0x700) goto LAB_8024dd18;
  }
  (&DAT_803ae1c6)[iVar2] = (&DAT_803ae1c6)[iVar2] & 0xf0;
  (&DAT_803ae1c7)[iVar2] = (&DAT_803ae1c7)[iVar2] & 0xf0;
  (&DAT_803ae1c8)[iVar2] = (&DAT_803ae1c8)[iVar2] & 0xf0;
  (&DAT_803ae1c9)[iVar2] = (&DAT_803ae1c9)[iVar2] & 0xf0;
LAB_8024dd18:
  (&DAT_803ae1c2)[iVar2] = (&DAT_803ae1c2)[iVar2] + -0x80;
  (&DAT_803ae1c3)[iVar2] = (&DAT_803ae1c3)[iVar2] + -0x80;
  (&DAT_803ae1c4)[iVar2] = (&DAT_803ae1c4)[iVar2] + -0x80;
  (&DAT_803ae1c5)[iVar2] = (&DAT_803ae1c5)[iVar2] + -0x80;
  if ((((DAT_803dc58c & 0x80000000U >> param_1) != 0) && ('@' < (char)(&DAT_803ae1c2)[iVar2])) &&
     (uVar1 = FUN_80252d80(), (uVar1 & 0xffff0000) == 0x9000000)) {
    (&DAT_803ae1c2)[iVar2] = 0;
  }
  return;
}

