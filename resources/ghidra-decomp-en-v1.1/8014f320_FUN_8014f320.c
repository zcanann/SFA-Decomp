// Function: FUN_8014f320
// Entry: 8014f320
// Size: 856 bytes

void FUN_8014f320(short *param_1,undefined4 *param_2)

{
  float fVar1;
  int iVar2;
  char cVar3;
  float *pfVar4;
  double dVar5;
  
  pfVar4 = (float *)*param_2;
  iVar2 = FUN_80010340((double)(float)param_2[2],pfVar4);
  if ((((iVar2 != 0) || (pfVar4[4] != DAT_803de6e0)) &&
      (cVar3 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar4), cVar3 != '\0')) &&
     (cVar3 = (**(code **)(*DAT_803dd71c + 0x8c))
                        ((double)FLOAT_803e3310,*param_2,param_1,&DAT_803dc8e0,0xffffffff),
     cVar3 != '\0')) {
    *(byte *)(param_2 + 7) = *(byte *)(param_2 + 7) & 0xfe;
  }
  fVar1 = FLOAT_803e3314;
  DAT_803de6e0 = pfVar4[4];
  if ((*(byte *)(param_2 + 7) & 2) == 0) {
    *(float *)(param_1 + 0x12) =
         FLOAT_803e3314 * (pfVar4[0x1a] - *(float *)(param_1 + 6)) + *(float *)(param_1 + 0x12);
    *(float *)(param_1 + 0x14) =
         fVar1 * (pfVar4[0x1b] - *(float *)(param_1 + 8)) + *(float *)(param_1 + 0x14);
    *(float *)(param_1 + 0x16) =
         fVar1 * (pfVar4[0x1c] - *(float *)(param_1 + 10)) + *(float *)(param_1 + 0x16);
  }
  else {
    *(float *)(param_1 + 0x12) =
         FLOAT_803e3314 * (*(float *)(param_2[1] + 0xc) - *(float *)(param_1 + 6)) +
         *(float *)(param_1 + 0x12);
    *(float *)(param_1 + 0x14) =
         fVar1 * ((FLOAT_803e3318 + *(float *)(param_2[1] + 0x10)) - *(float *)(param_1 + 8)) +
         *(float *)(param_1 + 0x14);
    *(float *)(param_1 + 0x16) =
         fVar1 * (*(float *)(param_2[1] + 0x14) - *(float *)(param_1 + 10)) +
         *(float *)(param_1 + 0x16);
  }
  fVar1 = FLOAT_803e331c;
  *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e331c;
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) * fVar1;
  *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar1;
  if (FLOAT_803e3320 < *(float *)(param_1 + 0x12)) {
    *(float *)(param_1 + 0x12) = FLOAT_803e3320;
  }
  if (FLOAT_803e3320 < *(float *)(param_1 + 0x14)) {
    *(float *)(param_1 + 0x14) = FLOAT_803e3320;
  }
  if (FLOAT_803e3320 < *(float *)(param_1 + 0x16)) {
    *(float *)(param_1 + 0x16) = FLOAT_803e3320;
  }
  if (*(float *)(param_1 + 0x12) < FLOAT_803e3324) {
    *(float *)(param_1 + 0x12) = FLOAT_803e3324;
  }
  if (*(float *)(param_1 + 0x14) < FLOAT_803e3324) {
    *(float *)(param_1 + 0x14) = FLOAT_803e3324;
  }
  if (*(float *)(param_1 + 0x16) < FLOAT_803e3324) {
    *(float *)(param_1 + 0x16) = FLOAT_803e3324;
  }
  FUN_8002ba34((double)(*(float *)(param_1 + 0x12) * FLOAT_803dc074),
               (double)(*(float *)(param_1 + 0x14) * FLOAT_803dc074),
               (double)(*(float *)(param_1 + 0x16) * FLOAT_803dc074),(int)param_1);
  *(short *)((int)param_2 + 0x1e) =
       *(short *)((int)param_2 + 0x1e) + (short)(int)(FLOAT_803e3328 * FLOAT_803dc074);
  *(short *)(param_2 + 8) = *(short *)(param_2 + 8) + (short)(int)(FLOAT_803e332c * FLOAT_803dc074);
  dVar5 = (double)FUN_802945e0();
  *param_1 = *param_1 + (short)(int)(FLOAT_803e3330 * (float)((double)FLOAT_803e3334 * dVar5));
  dVar5 = (double)FUN_802945e0();
  param_1[2] = param_1[2] + (short)(int)(FLOAT_803e3330 * (float)((double)FLOAT_803e3334 * dVar5));
  return;
}

