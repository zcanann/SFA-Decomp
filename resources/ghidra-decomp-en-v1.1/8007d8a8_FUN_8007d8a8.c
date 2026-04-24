// Function: FUN_8007d8a8
// Entry: 8007d8a8
// Size: 564 bytes

undefined4 FUN_8007d8a8(void)

{
  bool bVar1;
  int iVar2;
  undefined8 in_f1;
  double in_f2;
  undefined8 in_f3;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  uint local_18;
  int local_14;
  
  iVar2 = FUN_8007df88(in_f1,in_f2,in_f3,in_f4,in_f5,in_f6,in_f7,in_f8,'\0');
  if (iVar2 == 0) {
    bVar1 = false;
  }
  else {
    DAT_803ddcc0 = FUN_80023d8c(0xa000,-1);
    if (DAT_803ddcc0 == 0) {
      DAT_803dc360 = 8;
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
  }
  if (bVar1) {
    DAT_803dc360 = 0;
    iVar2 = FUN_80262b10(0,DAT_803ddcc0,&LAB_80080084);
    bVar1 = iVar2 != -0xd;
    if (iVar2 == -6) {
      iVar2 = FUN_8026218c(0);
      if (iVar2 == -6) {
        iVar2 = FUN_8026343c(0);
      }
    }
    else if (((iVar2 == -0xd) || (iVar2 == 0)) && (iVar2 = FUN_80264b4c(0,&local_18), iVar2 == 0)) {
      if ((DAT_803ddccc == 0 && DAT_803ddcc8 == 0) ||
         (DAT_803ddccc != local_14 || DAT_803ddcc8 != local_18)) {
        iVar2 = -0x55;
        DAT_803dc360 = 0xb;
      }
      else {
        if (bVar1) {
          FUN_80262bf4(0);
          FUN_800238c4(DAT_803ddcc0);
          DAT_803dc360 = 0xd;
          DAT_803ddcc0 = 0;
          return 1;
        }
        iVar2 = FUN_8026343c(0);
      }
    }
    FUN_80262bf4(0);
    FUN_800238c4(DAT_803ddcc0);
    DAT_803ddcc0 = 0;
    if (iVar2 == -2) {
      DAT_803dc360 = 1;
    }
    else if (iVar2 < -2) {
      if (iVar2 != -4) {
        if (iVar2 < -4) {
          if (-6 < iVar2) {
            DAT_803dc360 = 4;
          }
        }
        else if (DAT_803dc360 != 3) {
          DAT_803dc360 = 2;
        }
      }
    }
    else if (iVar2 == 0) {
      DAT_803dc360 = 0xd;
      DAT_803ddcc0 = 0;
      DAT_803ddcc8 = 0;
      DAT_803ddccc = 0;
      DAT_803ddcd0 = 0;
      DAT_803ddcd4 = 0;
      return 1;
    }
  }
  return 0;
}

