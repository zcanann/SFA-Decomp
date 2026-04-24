// Function: FUN_801bf454
// Entry: 801bf454
// Size: 424 bytes

/* WARNING: Removing unreachable block (ram,0x801bf5dc) */
/* WARNING: Removing unreachable block (ram,0x801bf464) */

void FUN_801bf454(int param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  float *pfVar3;
  double dVar4;
  
  pfVar3 = *(float **)(param_2 + 0x40c);
  dVar4 = (double)(pfVar3[3] - *(float *)(param_1 + 0x10));
  *(short *)(pfVar3 + 5) = *(short *)(pfVar3 + 5) + 0x400;
  uVar2 = FUN_80021818();
  *pfVar3 = FLOAT_803dc074 *
            ((float)(dVar4 + (double)((float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                             DOUBLE_803e5990) / FLOAT_803e5998)) / FLOAT_803e599c -
            pfVar3[2]) + *pfVar3;
  *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + *pfVar3;
  *(short *)(param_1 + 2) = (short)(int)(FLOAT_803e59a0 * *pfVar3);
  dVar4 = DOUBLE_803e5990;
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
                                       (uint)DAT_803dc070 ^ 0x80000000) - DOUBLE_803e5990);
  *(short *)(param_1 + 4) =
       (short)(int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 4) ^ 0x80000000) -
                           dVar4) + pfVar3[1]);
  *pfVar3 = *pfVar3 / FLOAT_803e59a4;
  pfVar3[1] = pfVar3[1] / FLOAT_803e59a8;
  return;
}

