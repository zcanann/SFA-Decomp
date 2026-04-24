// Function: FUN_8014e670
// Entry: 8014e670
// Size: 1368 bytes

/* WARNING: Removing unreachable block (ram,0x8014eba4) */
/* WARNING: Removing unreachable block (ram,0x8014e680) */

void FUN_8014e670(ushort *param_1,undefined4 *param_2)

{
  float fVar1;
  int iVar2;
  char cVar4;
  uint uVar3;
  float *pfVar5;
  double dVar6;
  double dVar7;
  undefined8 local_28;
  
  pfVar5 = (float *)*param_2;
  iVar2 = FUN_80010340((double)(float)param_2[2],pfVar5);
  if ((((iVar2 != 0) || (pfVar5[4] != DAT_803de6d8)) &&
      (cVar4 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar5), cVar4 != '\0')) &&
     (cVar4 = (**(code **)(*DAT_803dd71c + 0x8c))
                        ((double)FLOAT_803e32a0,*param_2,param_1,&DAT_803dc8d8,0xffffffff),
     cVar4 != '\0')) {
    *(byte *)((int)param_2 + 0x26) = *(byte *)((int)param_2 + 0x26) & 0xfe;
  }
  DAT_803de6d8 = pfVar5[4];
  *(short *)(param_2 + 8) = *(short *)(param_2 + 8) + (short)(int)(FLOAT_803e32a4 * FLOAT_803dc074);
  *(short *)((int)param_2 + 0x22) =
       *(short *)((int)param_2 + 0x22) + (short)(int)(FLOAT_803e32a8 * FLOAT_803dc074);
  *(short *)(param_2 + 9) = *(short *)(param_2 + 9) + (short)(int)(FLOAT_803e32ac * FLOAT_803dc074);
  dVar6 = (double)FUN_802945e0();
  dVar7 = (double)FUN_802945e0();
  param_1[2] = (ushort)(int)(FLOAT_803e32b0 * (float)(dVar7 + dVar6));
  dVar6 = (double)FUN_802945e0();
  dVar7 = (double)FUN_802945e0();
  param_1[1] = (ushort)(int)(FLOAT_803e32b0 * (float)(dVar7 + dVar6));
  fVar1 = FLOAT_803e32bc;
  if ((*(byte *)((int)param_2 + 0x26) & 2) == 0) {
    if ((*(byte *)((int)param_2 + 0x26) & 4) == 0) {
      *(float *)(param_1 + 0x12) =
           FLOAT_803e32bc * (pfVar5[0x1a] - *(float *)(param_1 + 6)) + *(float *)(param_1 + 0x12);
      dVar6 = (double)FUN_802945e0();
      dVar7 = (double)FUN_802945e0();
      fVar1 = FLOAT_803e32bc;
      *(float *)(param_1 + 0x14) =
           FLOAT_803e32bc *
           ((FLOAT_803e32c4 * (float)(dVar7 + dVar6) + pfVar5[0x1b]) - *(float *)(param_1 + 8)) +
           *(float *)(param_1 + 0x14);
      *(float *)(param_1 + 0x16) =
           fVar1 * (pfVar5[0x1c] - *(float *)(param_1 + 10)) + *(float *)(param_1 + 0x16);
    }
    else {
      *(float *)(param_1 + 0x12) =
           FLOAT_803e32bc * (pfVar5[0x1a] - *(float *)(param_1 + 6)) + *(float *)(param_1 + 0x12);
      *(float *)(param_1 + 0x14) =
           fVar1 * (pfVar5[0x1b] - *(float *)(param_1 + 8)) + *(float *)(param_1 + 0x14);
      *(float *)(param_1 + 0x16) =
           fVar1 * (pfVar5[0x1c] - *(float *)(param_1 + 10)) + *(float *)(param_1 + 0x16);
    }
  }
  else {
    *(float *)(param_1 + 0x12) =
         FLOAT_803e32bc * (*(float *)(param_2[1] + 0xc) - *(float *)(param_1 + 6)) +
         *(float *)(param_1 + 0x12);
    *(float *)(param_1 + 0x14) =
         fVar1 * ((FLOAT_803e32c0 + *(float *)(param_2[1] + 0x10)) - *(float *)(param_1 + 8)) +
         *(float *)(param_1 + 0x14);
    *(float *)(param_1 + 0x16) =
         fVar1 * (*(float *)(param_2[1] + 0x14) - *(float *)(param_1 + 10)) +
         *(float *)(param_1 + 0x16);
  }
  fVar1 = FLOAT_803e32c8;
  *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e32c8;
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) * fVar1;
  *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar1;
  if (FLOAT_803e32cc < *(float *)(param_1 + 0x12)) {
    *(float *)(param_1 + 0x12) = FLOAT_803e32cc;
  }
  if (FLOAT_803e32cc < *(float *)(param_1 + 0x14)) {
    *(float *)(param_1 + 0x14) = FLOAT_803e32cc;
  }
  if (FLOAT_803e32cc < *(float *)(param_1 + 0x16)) {
    *(float *)(param_1 + 0x16) = FLOAT_803e32cc;
  }
  if (*(float *)(param_1 + 0x12) < FLOAT_803e32d0) {
    *(float *)(param_1 + 0x12) = FLOAT_803e32d0;
  }
  if (*(float *)(param_1 + 0x14) < FLOAT_803e32d0) {
    *(float *)(param_1 + 0x14) = FLOAT_803e32d0;
  }
  if (*(float *)(param_1 + 0x16) < FLOAT_803e32d0) {
    *(float *)(param_1 + 0x16) = FLOAT_803e32d0;
  }
  FUN_8002ba34((double)(*(float *)(param_1 + 0x12) * FLOAT_803dc074),
               (double)(*(float *)(param_1 + 0x14) * FLOAT_803dc074),
               (double)(*(float *)(param_1 + 0x16) * FLOAT_803dc074),(int)param_1);
  FUN_8002fb40((double)(float)param_2[3],(double)FLOAT_803dc074);
  uVar3 = FUN_80021884();
  uVar3 = (uVar3 & 0xffff) - (uint)*param_1;
  if (0x8000 < (int)uVar3) {
    uVar3 = uVar3 - 0xffff;
  }
  if ((int)uVar3 < -0x8000) {
    uVar3 = uVar3 + 0xffff;
  }
  local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
  *param_1 = *param_1 +
             (short)(int)(((float)(local_28 - DOUBLE_803e32e0) * FLOAT_803dc074) / FLOAT_803e32d4);
  return;
}

