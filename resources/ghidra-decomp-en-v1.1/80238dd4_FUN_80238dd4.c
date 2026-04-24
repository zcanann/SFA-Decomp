// Function: FUN_80238dd4
// Entry: 80238dd4
// Size: 832 bytes

void FUN_80238dd4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  byte bVar7;
  float fVar5;
  int *piVar6;
  undefined4 in_r9;
  undefined4 in_r10;
  float fVar8;
  int iVar9;
  float *pfVar10;
  int unaff_r31;
  
  uVar2 = FUN_80286840();
  pfVar10 = *(float **)(uVar2 + 0xb8);
  iVar9 = *(int *)(uVar2 + 0x4c);
  uVar3 = FUN_800803dc(pfVar10);
  if (uVar3 == 0) {
    uVar3 = FUN_80020078((int)*(short *)(iVar9 + 0x20));
    if ((uVar3 != 0) || ((*(byte *)((int)pfVar10 + 0xd) >> 6 & 1) != 0)) {
      FUN_800803f8(pfVar10);
      if (*(short *)(iVar9 + 0x1a) != 0) {
        FUN_80080404(pfVar10,*(short *)(iVar9 + 0x1a) * 0x3c);
      }
      bVar7 = *(byte *)(pfVar10 + 3);
      if (bVar7 == 2) {
        fVar5 = (float)FUN_8001cd60(uVar2,0xff,0,0,0);
        pfVar10[1] = fVar5;
        if (pfVar10[1] != 0.0) {
          FUN_8001d7f4((double)FLOAT_803dd080,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,pfVar10[1],0,0xff,0,0,100,in_r9,in_r10);
          FUN_8001de4c((double)FLOAT_803e80b4,(double)FLOAT_803e80b8,(double)FLOAT_803e80b4,
                       (int *)pfVar10[1]);
        }
      }
      else if ((bVar7 < 2) && (bVar7 != 0)) {
        FUN_800146e8(0x1d,(int)*(short *)(iVar9 + 0x1a));
        FUN_800146c8();
      }
    }
  }
  else {
    bVar1 = false;
    if (((*(byte *)((int)pfVar10 + 0xd) >> 6 & 1) == 0) &&
       (uVar3 = FUN_80020078((int)*(short *)(iVar9 + 0x20)), uVar3 == 0)) {
      FUN_800803f8(pfVar10);
      if ((*(char *)(pfVar10 + 3) == '\x01') && (*(int *)(*(int *)(uVar2 + 0x4c) + 0x14) != 0x466ed)
         ) {
        FUN_8000bb38(uVar2,0x7e);
      }
      bVar1 = true;
    }
    iVar4 = FUN_80080434(pfVar10);
    if (iVar4 != 0) {
      FUN_800201ac((int)*(short *)(iVar9 + 0x1e),1);
      FUN_800201ac((int)*(short *)(iVar9 + 0x20),0);
      bVar1 = true;
    }
    if ((*(char *)(pfVar10 + 3) == '\x01') && (bVar7 = FUN_8001469c(), bVar7 == 1)) {
      FUN_800201ac((int)*(short *)(iVar9 + 0x1e),1);
      FUN_800201ac((int)*(short *)(iVar9 + 0x20),0);
      bVar1 = true;
    }
    if (bVar1) {
      *(byte *)((int)pfVar10 + 0xd) = *(byte *)((int)pfVar10 + 0xd) & 0x7f | 0x80;
      bVar7 = *(byte *)(pfVar10 + 3);
      if (bVar7 == 2) {
        FUN_8001cc00((uint *)(pfVar10 + 1));
      }
      else if (((bVar7 < 2) && (bVar7 != 0)) && (bVar7 != 0)) {
        FUN_800146a8();
      }
      *(byte *)((int)pfVar10 + 0xd) = *(byte *)((int)pfVar10 + 0xd) & 0xbf;
      goto LAB_802390fc;
    }
  }
  if ((*(char *)(pfVar10 + 3) == '\x02') && (uVar3 = FUN_800803dc(pfVar10), uVar3 != 0)) {
    fVar8 = pfVar10[1];
    fVar5 = ((float)((double)CONCAT44(0x43300000,*(short *)(iVar9 + 0x1a) * 0x3c ^ 0x80000000) -
                    DOUBLE_803e80a8) / *pfVar10) * FLOAT_803dd084;
    piVar6 = (int *)FUN_800395a4(uVar2,0);
    if (piVar6 != (int *)0x0) {
      unaff_r31 = *piVar6 + (int)fVar5 * (uint)DAT_803dc070;
      if (0x200 < unaff_r31) {
        unaff_r31 = unaff_r31 + -0x200;
      }
      *piVar6 = unaff_r31;
    }
    if (fVar8 == 0.0) {
      uVar3 = 0;
    }
    else {
      uVar3 = unaff_r31 >> 8;
    }
    if (pfVar10[1] != 0.0) {
      if ((uVar3 == 1) && ((*(byte *)((int)pfVar10 + 0xd) >> 5 & 1) != 1)) {
        FUN_8000bb38(uVar2,0x3da);
      }
      FUN_8001dc30((double)FLOAT_803e80b4,(int)pfVar10[1],(char)uVar3);
    }
    *(byte *)((int)pfVar10 + 0xd) =
         (byte)((uVar3 & 0xff) << 5) & 0x20 | *(byte *)((int)pfVar10 + 0xd) & 0xdf;
  }
  if (pfVar10[1] != 0.0) {
    FUN_8001d774((int)pfVar10[1]);
  }
LAB_802390fc:
  FUN_8028688c();
  return;
}

