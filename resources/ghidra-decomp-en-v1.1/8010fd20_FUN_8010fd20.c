// Function: FUN_8010fd20
// Entry: 8010fd20
// Size: 360 bytes

void FUN_8010fd20(short *param_1)

{
  int iVar1;
  double dVar2;
  
  iVar1 = FUN_800396d0(*DAT_803de218,0);
  if ((short *)*DAT_803de218 != (short *)0x0) {
    *param_1 = (short)(int)((float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                   DOUBLE_803e2778) +
                           (float)((double)CONCAT44(0x43300000,
                                                    (int)(short)(((-0x8000 - *(short *)*DAT_803de218
                                                                  ) - *(short *)(iVar1 + 2)) -
                                                                *param_1) ^ 0x80000000) -
                                  DOUBLE_803e2778) / FLOAT_803e2760);
    dVar2 = (double)FUN_802945e0();
    *(float *)(param_1 + 6) =
         -(float)((double)FLOAT_803e2764 * dVar2 - (double)*(float *)(*DAT_803de218 + 0xc));
    *(float *)(param_1 + 8) = FLOAT_803e2770 + *(float *)(*DAT_803de218 + 0x10);
    dVar2 = (double)FUN_80294964();
    *(float *)(param_1 + 10) =
         -(float)((double)FLOAT_803e2764 * dVar2 - (double)*(float *)(*DAT_803de218 + 0x14));
  }
  return;
}

