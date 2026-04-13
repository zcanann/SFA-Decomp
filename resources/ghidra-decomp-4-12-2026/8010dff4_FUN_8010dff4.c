// Function: FUN_8010dff4
// Entry: 8010dff4
// Size: 664 bytes

/* WARNING: Removing unreachable block (ram,0x8010e268) */
/* WARNING: Removing unreachable block (ram,0x8010e260) */
/* WARNING: Removing unreachable block (ram,0x8010e258) */
/* WARNING: Removing unreachable block (ram,0x8010e250) */
/* WARNING: Removing unreachable block (ram,0x8010e01c) */
/* WARNING: Removing unreachable block (ram,0x8010e014) */
/* WARNING: Removing unreachable block (ram,0x8010e00c) */
/* WARNING: Removing unreachable block (ram,0x8010e004) */

void FUN_8010dff4(short *param_1)

{
  float *pfVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  
  pfVar1 = DAT_803de1fc;
  iVar2 = *(int *)(param_1 + 0x52);
  if (iVar2 != 0) {
    if (DAT_803de1fc[7] == 8.40779e-45) {
      DAT_803de1fc[6] =
           (float)(int)((float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)((int)DAT_803de1fc + 0x22) ^
                                                 0x80000000) - DOUBLE_803e2660) * FLOAT_803dc074 +
                       (float)((double)CONCAT44(0x43300000,-DAT_803de1fc[6]) - DOUBLE_803e2660));
      if ((*(short *)((int)DAT_803de1fc + 0x22) < 1) || ((int)DAT_803de1fc[6] < 0xd6d9)) {
        if ((*(short *)((int)DAT_803de1fc + 0x22) < 0) && ((int)DAT_803de1fc[6] < -55000)) {
          DAT_803de1fc[6] = -NAN;
        }
      }
      else {
        DAT_803de1fc[6] = 7.70714e-41;
      }
      FUN_8010de18(iVar2,DAT_803de1fc + 9,DAT_803de1fc + 10,DAT_803de1fc + 0xb);
    }
    *(float *)(param_1 + 0xc) = DAT_803de1fc[9];
    *(float *)(param_1 + 0xe) = DAT_803de1fc[10];
    *(float *)(param_1 + 0x10) = DAT_803de1fc[0xb];
    dVar4 = (double)((*(float *)(iVar2 + 0x18) - *pfVar1) * DAT_803de1fc[0x12]);
    dVar3 = (double)((*(float *)(iVar2 + 0x20) - pfVar1[2]) * DAT_803de1fc[0x12]);
    if (DAT_803de1fc[7] == 4.2039e-45) {
      FUN_80293900((double)(float)(dVar4 * dVar4 + (double)(float)(dVar3 * dVar3)));
      iVar2 = FUN_80021884();
      param_1[1] = (short)iVar2;
    }
    dVar4 = (double)(*(float *)(param_1 + 0xc) - (float)(dVar4 + (double)*pfVar1));
    dVar3 = (double)(*(float *)(param_1 + 0x10) - (float)(dVar3 + (double)pfVar1[2]));
    iVar2 = FUN_80021884();
    *param_1 = -0x8000 - (short)iVar2;
    if (DAT_803de1fc[7] != 4.2039e-45) {
      FUN_80293900((double)(float)(dVar4 * dVar4 + (double)(float)(dVar3 * dVar3)));
      iVar2 = FUN_80021884();
      param_1[1] = (short)iVar2;
    }
    FUN_800551f8((double)*pfVar1,(double)pfVar1[1],(double)pfVar1[2],1,0);
    FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  return;
}

