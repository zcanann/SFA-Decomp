// Function: FUN_8000edcc
// Entry: 8000edcc
// Size: 412 bytes

/* WARNING: Removing unreachable block (ram,0x8000ef44) */

void FUN_8000edcc(double param_1,double param_2,double param_3,double param_4,float *param_5,
                 float *param_6,float *param_7)

{
  float fVar1;
  uint unaff_GQR0;
  float afStack_38 [3];
  float local_2c;
  float local_28;
  float local_24;
  
  if ((unaff_GQR0 & 0x3f00) != 0) {
    ldexpf((byte)(unaff_GQR0 >> 8) & 0x3f);
  }
  local_2c = (float)param_1;
  local_28 = (float)param_2;
  local_24 = (float)param_3;
  FUN_80247bf8((float *)&DAT_80339330,&local_2c,&local_2c);
  FUN_80247ef8(&local_2c,afStack_38);
  FUN_80247edc(param_4,afStack_38,afStack_38);
  FUN_80247eb8(&local_2c,afStack_38,&local_2c);
  *param_5 = DAT_803393bc +
             DAT_803393b8 * local_24 + DAT_803393b0 * local_2c + DAT_803393b4 * local_28;
  *param_6 = DAT_803393cc +
             DAT_803393c8 * local_24 + DAT_803393c0 * local_2c + DAT_803393c4 * local_28;
  *param_7 = DAT_803393dc +
             DAT_803393d8 * local_24 + DAT_803393d0 * local_2c + DAT_803393d4 * local_28;
  fVar1 = DAT_803393ec + DAT_803393e8 * local_24 + DAT_803393e0 * local_2c + DAT_803393e4 * local_28
  ;
  if (FLOAT_803df28c != fVar1) {
    fVar1 = FLOAT_803df270 / fVar1;
    *param_5 = *param_5 * fVar1;
    *param_6 = *param_6 * fVar1;
    *param_7 = *param_7 * fVar1;
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-((byte)(unaff_GQR0 >> 0x18) & 0x3f));
  }
  return;
}

