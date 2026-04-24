// Function: FUN_801e823c
// Entry: 801e823c
// Size: 380 bytes

/* WARNING: Removing unreachable block (ram,0x801e8398) */
/* WARNING: Removing unreachable block (ram,0x801e8390) */
/* WARNING: Removing unreachable block (ram,0x801e8388) */
/* WARNING: Removing unreachable block (ram,0x801e825c) */
/* WARNING: Removing unreachable block (ram,0x801e8254) */
/* WARNING: Removing unreachable block (ram,0x801e824c) */

double FUN_801e823c(ushort *param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  
  fVar1 = *(float *)(param_2 + 0xc) - *(float *)(param_1 + 6);
  fVar2 = *(float *)(param_2 + 0x14) - *(float *)(param_1 + 10);
  dVar5 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
  if ((double)FLOAT_803e66bc < dVar5) {
    uVar3 = FUN_80021884();
    if (param_3 == 0) {
      iVar4 = (uVar3 & 0xffff) - (uint)*param_1;
      if (0x8000 < iVar4) {
        iVar4 = iVar4 + -0xffff;
      }
      if (iVar4 < -0x8000) {
        iVar4 = iVar4 + 0xffff;
      }
      if (iVar4 < 0x2001) {
        if (iVar4 < -0x2000) {
          iVar4 = iVar4 + 0x2000;
        }
        else {
          iVar4 = 0;
        }
      }
      else {
        iVar4 = iVar4 + -0x2000;
      }
      *param_1 = (ushort)(int)((float)((double)CONCAT44(0x43300000,iVar4 >> 3 ^ 0x80000000) -
                                      DOUBLE_803e6698) * FLOAT_803dc074 +
                              (float)((double)CONCAT44(0x43300000,(int)(short)*param_1 ^ 0x80000000)
                                     - DOUBLE_803e6698));
    }
    else {
      *param_1 = (ushort)uVar3;
    }
  }
  return dVar5;
}

