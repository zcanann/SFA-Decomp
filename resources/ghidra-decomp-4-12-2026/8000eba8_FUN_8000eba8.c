// Function: FUN_8000eba8
// Entry: 8000eba8
// Size: 548 bytes

/* WARNING: Removing unreachable block (ram,0x8000edac) */
/* WARNING: Removing unreachable block (ram,0x8000eda4) */

void FUN_8000eba8(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,float *param_7,float *param_8,float *param_9,float *param_10)

{
  byte bVar1;
  byte bVar2;
  float fVar3;
  float *pfVar4;
  float *pfVar5;
  uint unaff_GQR0;
  double extraout_f1;
  double dVar6;
  double in_f30;
  double dVar7;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar8;
  float local_58;
  float local_54;
  float local_50;
  undefined4 local_18;
  float fStack_14;
  undefined4 local_8;
  float fStack_4;
  
  bVar1 = (byte)unaff_GQR0 & 7;
  bVar2 = (byte)(unaff_GQR0 >> 8);
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar6 = 1.0;
  }
  else {
    dVar6 = (double)ldexpf(bVar2 & 0x3f);
  }
  if (bVar1 == 4 || bVar1 == 6) {
    local_8 = (float)CONCAT13((char)(dVar6 * in_f31),
                              CONCAT12((char)(dVar6 * in_ps31_1),local_8._2_2_));
  }
  else if (bVar1 == 5 || bVar1 == 7) {
    local_8 = (float)CONCAT22((short)(dVar6 * in_f31),(short)(dVar6 * in_ps31_1));
  }
  else {
    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
  }
  bVar1 = (byte)unaff_GQR0 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar6 = 1.0;
  }
  else {
    dVar6 = (double)ldexpf(bVar2 & 0x3f);
  }
  if (bVar1 == 4 || bVar1 == 6) {
    local_18 = (float)CONCAT13((char)(dVar6 * in_f30),
                               CONCAT12((char)(dVar6 * in_ps30_1),local_18._2_2_));
  }
  else if (bVar1 == 5 || bVar1 == 7) {
    local_18 = (float)CONCAT22((short)(dVar6 * in_f30),(short)(dVar6 * in_ps30_1));
  }
  else {
    local_18 = (float)in_f30;
    fStack_14 = (float)in_ps30_1;
  }
  uVar8 = FUN_80286838();
  pfVar4 = (float *)((ulonglong)uVar8 >> 0x20);
  pfVar5 = (float *)uVar8;
  local_58 = (float)extraout_f1;
  local_54 = (float)param_2;
  local_50 = (float)param_3;
  FUN_80247bf8((float *)&DAT_80339330,&local_58,&local_58);
  *pfVar4 = DAT_803393bc +
            DAT_803393b8 * local_50 + DAT_803393b0 * local_58 + DAT_803393b4 * local_54;
  *pfVar5 = DAT_803393cc +
            DAT_803393c8 * local_50 + DAT_803393c0 * local_58 + DAT_803393c4 * local_54;
  *param_7 = DAT_803393dc +
             DAT_803393d8 * local_50 + DAT_803393d0 * local_58 + DAT_803393d4 * local_54;
  fVar3 = DAT_803393ec + DAT_803393e8 * local_50 + DAT_803393e0 * local_58 + DAT_803393e4 * local_54
  ;
  if (FLOAT_803df28c != fVar3) {
    fVar3 = FLOAT_803df270 / fVar3;
    *pfVar4 = *pfVar4 * fVar3;
    *pfVar5 = *pfVar5 * fVar3;
    *param_7 = *param_7 * fVar3;
    local_50 = (float)((double)local_50 + param_4);
    if (FLOAT_803df2a4 < local_50) {
      local_50 = FLOAT_803df2a4;
    }
    fVar3 = DAT_803393ec +
            DAT_803393e8 * local_50 + DAT_803393e0 * local_58 + DAT_803393e4 * local_54;
    if (FLOAT_803df28c != fVar3) {
      dVar7 = (double)(FLOAT_803df270 / fVar3);
      dVar6 = FUN_8029241c((double)(float)(dVar7 * (double)(float)(param_4 * (double)DAT_803393b0)))
      ;
      *param_8 = (float)dVar6;
      dVar6 = FUN_8029241c((double)(float)(dVar7 * (double)(float)(param_4 * (double)DAT_803393c4)))
      ;
      *param_9 = (float)dVar6;
      dVar6 = FUN_8029241c((double)(float)(dVar7 * (double)(float)(param_4 * (double)DAT_803393d8)))
      ;
      *param_10 = (float)dVar6;
    }
  }
  bVar1 = (byte)(unaff_GQR0 >> 0x18);
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  FUN_80286884();
  return;
}

