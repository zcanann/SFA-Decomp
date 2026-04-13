// Function: FUN_800072c4
// Entry: 800072c4
// Size: 552 bytes

/* WARNING: Removing unreachable block (ram,0x80007428) */
/* WARNING: Removing unreachable block (ram,0x800073a8) */
/* WARNING: Removing unreachable block (ram,0x80007328) */

double FUN_800072c4(void)

{
  float fVar1;
  int iVar2;
  byte bVar3;
  byte bVar4;
  longlong lVar5;
  short sVar6;
  uint uVar7;
  short *unaff_r25;
  uint unaff_GQR5;
  double dVar8;
  double dVar9;
  double dVar10;
  float local_28;
  
  iVar2 = ((int)*unaff_r25 >> 1) << 2;
  sVar6 = (short)iVar2;
  local_28 = (float)CONCAT22(sVar6,local_28._2_2_);
  bVar3 = (byte)(unaff_GQR5 >> 0x10) & 7;
  bVar4 = (byte)(unaff_GQR5 >> 0x18);
  if ((unaff_GQR5 & 0x3f000000) == 0) {
    lVar5 = 0x3ff0000000000000;
  }
  else {
    lVar5 = ldexpf(-(bVar4 & 0x3f));
  }
  if (bVar3 == 4 || bVar3 == 6) {
    local_28._0_1_ = (char)((uint)iVar2 >> 8);
    dVar10 = (double)(lVar5 * (longlong)(double)local_28._0_1_);
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    dVar10 = (double)(lVar5 * (longlong)(double)sVar6);
  }
  else {
    dVar10 = (double)local_28;
  }
  fVar1 = (float)(dVar10 * dVar10);
  dVar9 = (double)(float)(dVar10 * (double)(fVar1 * (fVar1 * (fVar1 * FLOAT_803df1b4 +
                                                             FLOAT_803df1b8) + FLOAT_803df1bc) +
                                           FLOAT_803df1c0));
  dVar8 = (double)(fVar1 * (fVar1 * (fVar1 * (fVar1 * FLOAT_803df1a0 + FLOAT_803df1a4) +
                                    FLOAT_803df1a8) + FLOAT_803df1ac) + FLOAT_803df1b0);
  uVar7 = ((int)*unaff_r25 >> 1) + 0x2000U & 0xc000;
  dVar10 = dVar9;
  if ((uVar7 != 0) && (dVar10 = dVar8, uVar7 != 0x4000)) {
    if (uVar7 == 0x8000) {
      dVar10 = -dVar9;
    }
    else {
      dVar10 = -dVar8;
    }
  }
  if ((unaff_GQR5 & 0x3f000000) != 0) {
    ldexpf(-(bVar4 & 0x3f));
  }
  if ((unaff_GQR5 & 0x3f000000) != 0) {
    ldexpf(-(bVar4 & 0x3f));
  }
  return dVar10;
}

