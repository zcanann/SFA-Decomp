// Function: FUN_8014fab4
// Entry: 8014fab4
// Size: 864 bytes

void FUN_8014fab4(int param_1,undefined4 *param_2)

{
  float fVar1;
  int iVar2;
  char cVar3;
  float *pfVar4;
  double dVar5;
  
  pfVar4 = (float *)*param_2;
  *(short *)((int)param_2 + 0x26) =
       *(short *)((int)param_2 + 0x26) + (short)(int)(FLOAT_803e3368 * FLOAT_803dc074);
  *(short *)(param_2 + 10) =
       *(short *)(param_2 + 10) + (short)(int)(FLOAT_803e336c * FLOAT_803dc074);
  dVar5 = (double)FUN_802945e0();
  iVar2 = FUN_80010340((double)((float)param_2[2] * (float)((double)FLOAT_803e3370 + dVar5)),pfVar4)
  ;
  if ((((iVar2 != 0) || (pfVar4[4] != DAT_803de6e8)) &&
      (cVar3 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar4), cVar3 != '\0')) &&
     (cVar3 = (**(code **)(*DAT_803dd71c + 0x8c))
                        ((double)FLOAT_803e337c,*param_2,param_1,&DAT_803dc8e8,0xffffffff),
     cVar3 != '\0')) {
    *(byte *)(param_2 + 9) = *(byte *)(param_2 + 9) & 0xfe;
  }
  DAT_803de6e8 = pfVar4[4];
  if ((*(byte *)(param_2 + 9) & 2) == 0) {
    *(float *)(param_1 + 0x24) =
         FLOAT_803e3380 * (pfVar4[0x1a] - *(float *)(param_1 + 0xc)) + *(float *)(param_1 + 0x24);
    dVar5 = (double)FUN_802945e0();
    fVar1 = FLOAT_803e3380;
    *(float *)(param_1 + 0x28) =
         FLOAT_803e3380 *
         ((float)((double)FLOAT_803e3388 * dVar5 + (double)pfVar4[0x1b]) -
         *(float *)(param_1 + 0x10)) + *(float *)(param_1 + 0x28);
    *(float *)(param_1 + 0x2c) =
         fVar1 * (pfVar4[0x1c] - *(float *)(param_1 + 0x14)) + *(float *)(param_1 + 0x2c);
  }
  else {
    *(float *)(param_1 + 0x24) =
         FLOAT_803e3380 * (*(float *)(param_2[1] + 0xc) - *(float *)(param_1 + 0xc)) +
         *(float *)(param_1 + 0x24);
    dVar5 = (double)FUN_802945e0();
    fVar1 = FLOAT_803e3380;
    *(float *)(param_1 + 0x28) =
         FLOAT_803e3380 *
         ((float)((double)FLOAT_803e3388 * dVar5 +
                 (double)(FLOAT_803e3384 + *(float *)(param_2[1] + 0x10))) -
         *(float *)(param_1 + 0x10)) + *(float *)(param_1 + 0x28);
    *(float *)(param_1 + 0x2c) =
         fVar1 * (*(float *)(param_2[1] + 0x14) - *(float *)(param_1 + 0x14)) +
         *(float *)(param_1 + 0x2c);
  }
  fVar1 = FLOAT_803e338c;
  *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * FLOAT_803e338c;
  *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * fVar1;
  *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * fVar1;
  if (FLOAT_803e3390 < *(float *)(param_1 + 0x24)) {
    *(float *)(param_1 + 0x24) = FLOAT_803e3390;
  }
  if (FLOAT_803e3390 < *(float *)(param_1 + 0x28)) {
    *(float *)(param_1 + 0x28) = FLOAT_803e3390;
  }
  if (FLOAT_803e3390 < *(float *)(param_1 + 0x2c)) {
    *(float *)(param_1 + 0x2c) = FLOAT_803e3390;
  }
  if (*(float *)(param_1 + 0x24) < FLOAT_803e3394) {
    *(float *)(param_1 + 0x24) = FLOAT_803e3394;
  }
  if (*(float *)(param_1 + 0x28) < FLOAT_803e3394) {
    *(float *)(param_1 + 0x28) = FLOAT_803e3394;
  }
  if (*(float *)(param_1 + 0x2c) < FLOAT_803e3394) {
    *(float *)(param_1 + 0x2c) = FLOAT_803e3394;
  }
  FUN_8002ba34((double)(*(float *)(param_1 + 0x24) * FLOAT_803dc074),
               (double)(*(float *)(param_1 + 0x28) * FLOAT_803dc074),
               (double)(*(float *)(param_1 + 0x2c) * FLOAT_803dc074),param_1);
  return;
}

