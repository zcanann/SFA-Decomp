// Function: FUN_8024e064
// Entry: 8024e064
// Size: 124 bytes

int FUN_8024e064(void)

{
  int unaff_r31;
  int iVar1;
  
  FUN_80243e74();
  if (DAT_803dec24 == 3) {
LAB_8024e0b0:
    iVar1 = 0;
  }
  else {
    if (DAT_803dec24 < 3) {
      if (DAT_803dec24 != 1) {
        iVar1 = DAT_803dec24;
        if ((0 < DAT_803dec24) || (iVar1 = unaff_r31, DAT_803dec24 < 0)) goto LAB_8024e0c4;
        goto LAB_8024e0b0;
      }
    }
    else {
      iVar1 = DAT_803dec24;
      if ((DAT_803dec24 == 5) || (iVar1 = unaff_r31, 4 < DAT_803dec24)) goto LAB_8024e0c4;
    }
    iVar1 = 1;
  }
LAB_8024e0c4:
  FUN_80243e9c();
  return iVar1;
}

