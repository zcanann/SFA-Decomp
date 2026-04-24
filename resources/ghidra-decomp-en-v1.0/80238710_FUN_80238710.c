// Function: FUN_80238710
// Entry: 80238710
// Size: 780 bytes

void FUN_80238710(void)

{
  byte bVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  float fVar5;
  int *piVar6;
  float fVar7;
  int iVar8;
  uint uVar9;
  float *pfVar10;
  int unaff_r31;
  
  iVar3 = FUN_802860dc();
  pfVar10 = *(float **)(iVar3 + 0xb8);
  iVar8 = *(int *)(iVar3 + 0x4c);
  iVar4 = FUN_80080150(pfVar10);
  if (iVar4 == 0) {
    iVar4 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x20));
    if ((iVar4 != 0) || ((*(byte *)((int)pfVar10 + 0xd) >> 6 & 1) != 0)) {
      FUN_8008016c(pfVar10);
      if (*(short *)(iVar8 + 0x1a) != 0) {
        FUN_80080178(pfVar10,(int)(short)(*(short *)(iVar8 + 0x1a) * 0x3c));
      }
      bVar1 = *(byte *)(pfVar10 + 3);
      if (bVar1 == 2) {
        fVar5 = (float)FUN_8001cc9c(iVar3,0xff,0,0,0);
        pfVar10[1] = fVar5;
        if (pfVar10[1] != 0.0) {
          FUN_8001d730((double)FLOAT_803dc418,pfVar10[1],0,0xff,0,0,100);
          FUN_8001dd88((double)FLOAT_803e741c,(double)FLOAT_803e7420,(double)FLOAT_803e741c,
                       pfVar10[1]);
        }
      }
      else if ((bVar1 < 2) && (bVar1 != 0)) {
        FUN_800146bc(0x1d,(int)*(short *)(iVar8 + 0x1a));
        FUN_8001469c();
      }
    }
  }
  else {
    bVar2 = false;
    if (((*(byte *)((int)pfVar10 + 0xd) >> 6 & 1) == 0) &&
       (iVar4 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x20)), iVar4 == 0)) {
      FUN_8008016c(pfVar10);
      if ((*(char *)(pfVar10 + 3) == '\x01') && (*(int *)(*(int *)(iVar3 + 0x4c) + 0x14) != 0x466ed)
         ) {
        FUN_8000bb18(iVar3,0x7e);
      }
      bVar2 = true;
    }
    iVar4 = FUN_800801a8(pfVar10);
    if (iVar4 != 0) {
      FUN_800200e8((int)*(short *)(iVar8 + 0x1e),1);
      FUN_800200e8((int)*(short *)(iVar8 + 0x20),0);
      bVar2 = true;
    }
    if (bVar2) {
      *(byte *)((int)pfVar10 + 0xd) = *(byte *)((int)pfVar10 + 0xd) & 0x7f | 0x80;
      bVar1 = *(byte *)(pfVar10 + 3);
      if (bVar1 == 2) {
        FUN_8001cb3c(pfVar10 + 1);
      }
      else if (((bVar1 < 2) && (bVar1 != 0)) && (bVar1 != 0)) {
        FUN_8001467c();
      }
      *(byte *)((int)pfVar10 + 0xd) = *(byte *)((int)pfVar10 + 0xd) & 0xbf;
      goto LAB_80238a04;
    }
  }
  if ((*(char *)(pfVar10 + 3) == '\x02') && (iVar4 = FUN_80080150(pfVar10), iVar4 != 0)) {
    fVar7 = pfVar10[1];
    fVar5 = ((float)((double)CONCAT44(0x43300000,*(short *)(iVar8 + 0x1a) * 0x3c ^ 0x80000000) -
                    DOUBLE_803e7410) / *pfVar10) * FLOAT_803dc41c;
    piVar6 = (int *)FUN_800394ac(iVar3,0,0);
    if (piVar6 != (int *)0x0) {
      unaff_r31 = *piVar6 + (int)fVar5 * (uint)DAT_803db410;
      if (0x200 < unaff_r31) {
        unaff_r31 = unaff_r31 + -0x200;
      }
      *piVar6 = unaff_r31;
    }
    if (fVar7 == 0.0) {
      uVar9 = 0;
    }
    else {
      uVar9 = unaff_r31 >> 8;
    }
    if (pfVar10[1] != 0.0) {
      if ((uVar9 == 1) && ((*(byte *)((int)pfVar10 + 0xd) >> 5 & 1) != 1)) {
        FUN_8000bb18(iVar3,0x3da);
      }
      FUN_8001db6c((double)FLOAT_803e741c,pfVar10[1],uVar9 & 0xff);
    }
    *(byte *)((int)pfVar10 + 0xd) =
         (byte)((uVar9 & 0xff) << 5) & 0x20 | *(byte *)((int)pfVar10 + 0xd) & 0xdf;
  }
  if (pfVar10[1] != 0.0) {
    FUN_8001d6b0();
  }
LAB_80238a04:
  FUN_80286128();
  return;
}

