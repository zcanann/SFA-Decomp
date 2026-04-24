// Function: FUN_8010aea8
// Entry: 8010aea8
// Size: 912 bytes

/* WARNING: Removing unreachable block (ram,0x8010b218) */

uint FUN_8010aea8(short *param_1,uint param_2)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  double dVar4;
  undefined8 in_f31;
  double local_28;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  *(undefined4 *)(DAT_803dd560 + 0x14) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(DAT_803dd560 + 0x1c) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(DAT_803dd560 + 0x24) = *(undefined4 *)(param_1 + 10);
  dVar3 = DOUBLE_803e18a0;
  *(float *)(DAT_803dd560 + 0x2c) =
       (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) - DOUBLE_803e18a0);
  *(float *)(DAT_803dd560 + 0x34) =
       (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) - dVar3);
  local_28 = (double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000);
  *(float *)(DAT_803dd560 + 0x3c) = (float)(local_28 - dVar3);
  *(undefined4 *)(DAT_803dd560 + 0x44) = *(undefined4 *)(param_1 + 0x5a);
  dVar3 = (double)FLOAT_803e1888;
  if (dVar3 != (double)*(float *)(DAT_803dd560 + 0x60)) {
    dVar3 = (double)(float)((double)*(float *)(DAT_803dd560 + 0x5c) /
                           (double)*(float *)(DAT_803dd560 + 0x60));
  }
  if ((double)FLOAT_803e188c < dVar3) {
    dVar3 = (double)FLOAT_803e188c;
  }
  dVar3 = (double)FUN_80010dc0(dVar3,DAT_803dd560 + 0x48,0);
  if (dVar3 < (double)FLOAT_803e18ac) {
    dVar3 = (double)FLOAT_803e18ac;
  }
  *(float *)(DAT_803dd560 + 0x5c) =
       (float)(dVar3 * (double)FLOAT_803db414 + (double)*(float *)(DAT_803dd560 + 0x5c));
  dVar3 = (double)FLOAT_803e1888;
  if (dVar3 != (double)*(float *)(DAT_803dd560 + 0x60)) {
    dVar3 = (double)(float)((double)*(float *)(DAT_803dd560 + 0x5c) /
                           (double)*(float *)(DAT_803dd560 + 0x60));
  }
  if ((double)FLOAT_803e188c < dVar3) {
    dVar3 = (double)FLOAT_803e188c;
  }
  dVar4 = (double)FUN_80010c50(dVar3,DAT_803dd560 + 0x10,0);
  *(float *)(param_1 + 6) = (float)dVar4;
  dVar4 = (double)FUN_80010c50(dVar3,DAT_803dd560 + 0x18,0);
  *(float *)(param_1 + 8) = (float)dVar4;
  dVar4 = (double)FUN_80010c50(dVar3,DAT_803dd560 + 0x20,0);
  *(float *)(param_1 + 10) = (float)dVar4;
  dVar4 = (double)FUN_80010c50(dVar3,DAT_803dd560 + 0x40,0);
  *(float *)(param_1 + 0x5a) = (float)dVar4;
  fVar1 = *(float *)(DAT_803dd560 + 0x28) - *(float *)(DAT_803dd560 + 0x2c);
  if ((FLOAT_803e1890 < fVar1) || (fVar1 < FLOAT_803e1894)) {
    if (FLOAT_803e1888 <= *(float *)(DAT_803dd560 + 0x28)) {
      if (*(float *)(DAT_803dd560 + 0x2c) < FLOAT_803e1888) {
        *(float *)(DAT_803dd560 + 0x2c) = *(float *)(DAT_803dd560 + 0x2c) + FLOAT_803e1898;
      }
    }
    else {
      *(float *)(DAT_803dd560 + 0x28) = *(float *)(DAT_803dd560 + 0x28) + FLOAT_803e1898;
    }
  }
  fVar1 = *(float *)(DAT_803dd560 + 0x30) - *(float *)(DAT_803dd560 + 0x34);
  if ((FLOAT_803e1890 < fVar1) || (fVar1 < FLOAT_803e1894)) {
    if (FLOAT_803e1888 <= *(float *)(DAT_803dd560 + 0x30)) {
      if (*(float *)(DAT_803dd560 + 0x34) < FLOAT_803e1888) {
        *(float *)(DAT_803dd560 + 0x34) = *(float *)(DAT_803dd560 + 0x34) + FLOAT_803e1898;
      }
    }
    else {
      *(float *)(DAT_803dd560 + 0x30) = *(float *)(DAT_803dd560 + 0x30) + FLOAT_803e1898;
    }
  }
  fVar1 = *(float *)(DAT_803dd560 + 0x38) - *(float *)(DAT_803dd560 + 0x3c);
  if ((FLOAT_803e1890 < fVar1) || (fVar1 < FLOAT_803e1894)) {
    if (FLOAT_803e1888 <= *(float *)(DAT_803dd560 + 0x38)) {
      if (*(float *)(DAT_803dd560 + 0x3c) < FLOAT_803e1888) {
        *(float *)(DAT_803dd560 + 0x3c) = *(float *)(DAT_803dd560 + 0x3c) + FLOAT_803e1898;
      }
    }
    else {
      *(float *)(DAT_803dd560 + 0x38) = *(float *)(DAT_803dd560 + 0x38) + FLOAT_803e1898;
    }
  }
  if ((param_2 & 1) == 0) {
    dVar4 = (double)FUN_80010c50(dVar3,DAT_803dd560 + 0x28,0);
    *param_1 = (short)(int)dVar4;
  }
  if ((param_2 & 2) == 0) {
    dVar4 = (double)FUN_80010c50(dVar3,DAT_803dd560 + 0x30,0);
    param_1[1] = (short)(int)dVar4;
  }
  if ((param_2 & 4) == 0) {
    dVar4 = (double)FUN_80010c50(dVar3,DAT_803dd560 + 0x38,0);
    param_1[2] = (short)(int)dVar4;
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return ((uint)(byte)(((double)FLOAT_803e188c <= dVar3) << 1) << 0x1c) >> 0x1d;
}

