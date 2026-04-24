// Function: FUN_801beea0
// Entry: 801beea0
// Size: 424 bytes

/* WARNING: Removing unreachable block (ram,0x801bf028) */

void FUN_801beea0(int param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  float *pfVar3;
  undefined4 uVar4;
  undefined8 in_f31;
  double dVar5;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  pfVar3 = *(float **)(param_2 + 0x40c);
  dVar5 = (double)(pfVar3[3] - *(float *)(param_1 + 0x10));
  *(short *)(pfVar3 + 5) = *(short *)(pfVar3 + 5) + 0x400;
  uVar2 = FUN_80021754((int)*(short *)(pfVar3 + 5));
  *pfVar3 = FLOAT_803db414 *
            ((float)(dVar5 + (double)((float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                             DOUBLE_803e4cf8) / FLOAT_803e4d00)) / FLOAT_803e4d04 -
            pfVar3[2]) + *pfVar3;
  *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + *pfVar3;
  *(short *)(param_1 + 2) = (short)(int)(FLOAT_803e4d08 * *pfVar3);
  dVar5 = DOUBLE_803e4cf8;
  sVar1 = -*(short *)(param_1 + 4);
  if (0x8000 < sVar1) {
    sVar1 = sVar1 + 1;
  }
  if (sVar1 < -0x8000) {
    sVar1 = sVar1 + -1;
  }
  uVar2 = (uint)sVar1;
  pfVar3[1] = pfVar3[1] +
              (float)((double)CONCAT44(0x43300000,
                                       (((int)uVar2 >> 4) +
                                       (uint)((int)uVar2 < 0 && (uVar2 & 0xf) != 0)) *
                                       (uint)DAT_803db410 ^ 0x80000000) - DOUBLE_803e4cf8);
  *(short *)(param_1 + 4) =
       (short)(int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 4) ^ 0x80000000) -
                           dVar5) + pfVar3[1]);
  *pfVar3 = *pfVar3 / FLOAT_803e4d0c;
  pfVar3[1] = pfVar3[1] / FLOAT_803e4d10;
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return;
}

