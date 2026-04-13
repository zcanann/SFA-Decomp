// Function: FUN_80070088
// Entry: 80070088
// Size: 664 bytes

/* WARNING: Removing unreachable block (ram,0x80070300) */
/* WARNING: Removing unreachable block (ram,0x800702f8) */
/* WARNING: Removing unreachable block (ram,0x800702f0) */
/* WARNING: Removing unreachable block (ram,0x800702e8) */
/* WARNING: Removing unreachable block (ram,0x800702e0) */
/* WARNING: Removing unreachable block (ram,0x800702d8) */
/* WARNING: Removing unreachable block (ram,0x800702d0) */
/* WARNING: Removing unreachable block (ram,0x800700c8) */
/* WARNING: Removing unreachable block (ram,0x800700c0) */
/* WARNING: Removing unreachable block (ram,0x800700b8) */
/* WARNING: Removing unreachable block (ram,0x800700b0) */
/* WARNING: Removing unreachable block (ram,0x800700a8) */
/* WARNING: Removing unreachable block (ram,0x800700a0) */
/* WARNING: Removing unreachable block (ram,0x80070098) */

void FUN_80070088(double param_1,double param_2,double param_3,double param_4,double param_5,
                 float *param_6,short *param_7)

{
  double dVar1;
  double dVar2;
  
  FUN_800703b0(param_6);
  dVar1 = (double)FUN_802945e0();
  dVar2 = (double)FUN_80294964();
  *param_6 = (float)((double)(float)(dVar2 / dVar1) / param_2);
  param_6[5] = (float)(dVar2 / dVar1);
  param_6[10] = (float)(-param_3 / (double)(float)(param_4 - param_3));
  param_6[0xb] = FLOAT_803dfaf4;
  param_6[0xe] = (float)((double)(float)(-param_3 * param_4) / (double)(float)(param_4 - param_3));
  param_6[0xf] = FLOAT_803dfaf8;
  *param_6 = (float)((double)*param_6 * param_5);
  param_6[1] = (float)((double)param_6[1] * param_5);
  param_6[2] = (float)((double)param_6[2] * param_5);
  param_6[3] = (float)((double)param_6[3] * param_5);
  param_6[4] = (float)((double)param_6[4] * param_5);
  param_6[5] = (float)((double)param_6[5] * param_5);
  param_6[6] = (float)((double)param_6[6] * param_5);
  param_6[7] = (float)((double)param_6[7] * param_5);
  param_6[8] = (float)((double)param_6[8] * param_5);
  param_6[9] = (float)((double)param_6[9] * param_5);
  param_6[10] = (float)((double)param_6[10] * param_5);
  param_6[0xb] = (float)((double)param_6[0xb] * param_5);
  param_6[0xc] = (float)((double)param_6[0xc] * param_5);
  param_6[0xd] = (float)((double)param_6[0xd] * param_5);
  param_6[0xe] = (float)((double)param_6[0xe] * param_5);
  param_6[0xf] = (float)((double)param_6[0xf] * param_5);
  if (param_7 != (short *)0x0) {
    if (FLOAT_803dfafc < (float)(param_3 + param_4)) {
      *param_7 = (short)(int)(FLOAT_803dfb00 / (float)(param_3 + param_4));
      if (*param_7 == 0) {
        *param_7 = 1;
      }
    }
    else {
      *param_7 = -1;
    }
  }
  FLOAT_803ddcb8 = (float)ABS(param_3);
  FLOAT_803ddcb4 = (float)ABS(param_4);
  FUN_80247d2c(param_1,param_2,(double)FLOAT_803ddcb8,(double)FLOAT_803ddcb4,(float *)&DAT_80397520)
  ;
  DAT_803ddcbc = 0;
  return;
}

