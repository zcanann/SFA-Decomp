// Function: FUN_8010b144
// Entry: 8010b144
// Size: 912 bytes

/* WARNING: Removing unreachable block (ram,0x8010b4b4) */
/* WARNING: Removing unreachable block (ram,0x8010b154) */

uint FUN_8010b144(short *param_1,uint param_2)

{
  float fVar1;
  double dVar2;
  double dVar3;
  undefined8 local_28;
  
  *(undefined4 *)(DAT_803de1d8 + 0x14) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(DAT_803de1d8 + 0x1c) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(DAT_803de1d8 + 0x24) = *(undefined4 *)(param_1 + 10);
  dVar2 = DOUBLE_803e2520;
  *(float *)(DAT_803de1d8 + 0x2c) =
       (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) - DOUBLE_803e2520);
  *(float *)(DAT_803de1d8 + 0x34) =
       (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) - dVar2);
  local_28 = (double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000);
  *(float *)(DAT_803de1d8 + 0x3c) = (float)(local_28 - dVar2);
  *(undefined4 *)(DAT_803de1d8 + 0x44) = *(undefined4 *)(param_1 + 0x5a);
  dVar2 = (double)FLOAT_803e2508;
  if (dVar2 != (double)*(float *)(DAT_803de1d8 + 0x60)) {
    dVar2 = (double)(float)((double)*(float *)(DAT_803de1d8 + 0x5c) /
                           (double)*(float *)(DAT_803de1d8 + 0x60));
  }
  if ((double)FLOAT_803e250c < dVar2) {
    dVar2 = (double)FLOAT_803e250c;
  }
  dVar2 = FUN_80010de0(dVar2,(float *)(DAT_803de1d8 + 0x48),(float *)0x0);
  if (dVar2 < (double)FLOAT_803e252c) {
    dVar2 = (double)FLOAT_803e252c;
  }
  *(float *)(DAT_803de1d8 + 0x5c) =
       (float)(dVar2 * (double)FLOAT_803dc074 + (double)*(float *)(DAT_803de1d8 + 0x5c));
  dVar2 = (double)FLOAT_803e2508;
  if (dVar2 != (double)*(float *)(DAT_803de1d8 + 0x60)) {
    dVar2 = (double)(float)((double)*(float *)(DAT_803de1d8 + 0x5c) /
                           (double)*(float *)(DAT_803de1d8 + 0x60));
  }
  if ((double)FLOAT_803e250c < dVar2) {
    dVar2 = (double)FLOAT_803e250c;
  }
  dVar3 = FUN_80010c70(dVar2,(float *)(DAT_803de1d8 + 0x10));
  *(float *)(param_1 + 6) = (float)dVar3;
  dVar3 = FUN_80010c70(dVar2,(float *)(DAT_803de1d8 + 0x18));
  *(float *)(param_1 + 8) = (float)dVar3;
  dVar3 = FUN_80010c70(dVar2,(float *)(DAT_803de1d8 + 0x20));
  *(float *)(param_1 + 10) = (float)dVar3;
  dVar3 = FUN_80010c70(dVar2,(float *)(DAT_803de1d8 + 0x40));
  *(float *)(param_1 + 0x5a) = (float)dVar3;
  fVar1 = *(float *)(DAT_803de1d8 + 0x28) - *(float *)(DAT_803de1d8 + 0x2c);
  if ((FLOAT_803e2510 < fVar1) || (fVar1 < FLOAT_803e2514)) {
    if (FLOAT_803e2508 <= *(float *)(DAT_803de1d8 + 0x28)) {
      if (*(float *)(DAT_803de1d8 + 0x2c) < FLOAT_803e2508) {
        *(float *)(DAT_803de1d8 + 0x2c) = *(float *)(DAT_803de1d8 + 0x2c) + FLOAT_803e2518;
      }
    }
    else {
      *(float *)(DAT_803de1d8 + 0x28) = *(float *)(DAT_803de1d8 + 0x28) + FLOAT_803e2518;
    }
  }
  fVar1 = *(float *)(DAT_803de1d8 + 0x30) - *(float *)(DAT_803de1d8 + 0x34);
  if ((FLOAT_803e2510 < fVar1) || (fVar1 < FLOAT_803e2514)) {
    if (FLOAT_803e2508 <= *(float *)(DAT_803de1d8 + 0x30)) {
      if (*(float *)(DAT_803de1d8 + 0x34) < FLOAT_803e2508) {
        *(float *)(DAT_803de1d8 + 0x34) = *(float *)(DAT_803de1d8 + 0x34) + FLOAT_803e2518;
      }
    }
    else {
      *(float *)(DAT_803de1d8 + 0x30) = *(float *)(DAT_803de1d8 + 0x30) + FLOAT_803e2518;
    }
  }
  fVar1 = *(float *)(DAT_803de1d8 + 0x38) - *(float *)(DAT_803de1d8 + 0x3c);
  if ((FLOAT_803e2510 < fVar1) || (fVar1 < FLOAT_803e2514)) {
    if (FLOAT_803e2508 <= *(float *)(DAT_803de1d8 + 0x38)) {
      if (*(float *)(DAT_803de1d8 + 0x3c) < FLOAT_803e2508) {
        *(float *)(DAT_803de1d8 + 0x3c) = *(float *)(DAT_803de1d8 + 0x3c) + FLOAT_803e2518;
      }
    }
    else {
      *(float *)(DAT_803de1d8 + 0x38) = *(float *)(DAT_803de1d8 + 0x38) + FLOAT_803e2518;
    }
  }
  if ((param_2 & 1) == 0) {
    dVar3 = FUN_80010c70(dVar2,(float *)(DAT_803de1d8 + 0x28));
    *param_1 = (short)(int)dVar3;
  }
  if ((param_2 & 2) == 0) {
    dVar3 = FUN_80010c70(dVar2,(float *)(DAT_803de1d8 + 0x30));
    param_1[1] = (short)(int)dVar3;
  }
  if ((param_2 & 4) == 0) {
    dVar3 = FUN_80010c70(dVar2,(float *)(DAT_803de1d8 + 0x38));
    param_1[2] = (short)(int)dVar3;
  }
  return ((uint)(byte)(((double)FLOAT_803e250c <= dVar2) << 1) << 0x1c) >> 0x1d;
}

