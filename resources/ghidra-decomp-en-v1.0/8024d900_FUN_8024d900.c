// Function: FUN_8024d900
// Entry: 8024d900
// Size: 124 bytes

int FUN_8024d900(void)

{
  int unaff_r31;
  int iVar1;
  
  FUN_8024377c();
  if (DAT_803ddfa4 == 3) {
LAB_8024d94c:
    iVar1 = 0;
  }
  else {
    if (DAT_803ddfa4 < 3) {
      if (DAT_803ddfa4 != 1) {
        iVar1 = DAT_803ddfa4;
        if ((0 < DAT_803ddfa4) || (iVar1 = unaff_r31, DAT_803ddfa4 < 0)) goto LAB_8024d960;
        goto LAB_8024d94c;
      }
    }
    else {
      iVar1 = DAT_803ddfa4;
      if ((DAT_803ddfa4 == 5) || (iVar1 = unaff_r31, 4 < DAT_803ddfa4)) goto LAB_8024d960;
    }
    iVar1 = 1;
  }
LAB_8024d960:
  FUN_802437a4();
  return iVar1;
}

