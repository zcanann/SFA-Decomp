// Function: FUN_801901cc
// Entry: 801901cc
// Size: 392 bytes

/* WARNING: Removing unreachable block (ram,0x80190330) */
/* WARNING: Removing unreachable block (ram,0x801901dc) */

void FUN_801901cc(int param_1)

{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  uint uVar6;
  float *pfVar7;
  double dVar8;
  double dVar9;
  
  pfVar7 = *(float **)(param_1 + 0xb8);
  iVar5 = FUN_8002bac4();
  if ((iVar5 != 0) &&
     ((((int)*(short *)((int)pfVar7 + 0xe) == 0xffffffff ||
       (uVar6 = FUN_80020078((int)*(short *)((int)pfVar7 + 0xe)), uVar6 != 0)) &&
      (*(short *)((int)pfVar7 + 0x12) == 0)))) {
    uVar6 = FUN_80020078((int)*(short *)(pfVar7 + 4));
    if (uVar6 != 0) {
      *(undefined2 *)((int)pfVar7 + 0x12) = 1;
    }
    sVar1 = *(short *)(pfVar7 + 3);
    if ((-1 < sVar1) || ((-1 >= sVar1 && (*(int *)(param_1 + 0xf4) < 1)))) {
      fVar2 = *(float *)(param_1 + 0x18) - *(float *)(iVar5 + 0x18);
      fVar3 = *(float *)(param_1 + 0x1c) - *(float *)(iVar5 + 0x1c);
      fVar4 = *(float *)(param_1 + 0x20) - *(float *)(iVar5 + 0x20);
      if (sVar1 == 0) {
        *(undefined2 *)((int)pfVar7 + 0x12) = 1;
      }
      dVar8 = FUN_80293900((double)(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3));
      dVar9 = (double)*pfVar7;
      if ((dVar8 <= dVar9) || ((double)FLOAT_803e4b04 == dVar9)) {
        if ((3 < *(byte *)(pfVar7 + 2)) &&
           ((dVar9 < (double)pfVar7[1] && ((double)FLOAT_803e4b04 != dVar9)))) {
          FUN_8018f6c4();
        }
        FUN_8018f854();
      }
      *(int *)(param_1 + 0xf4) = -(int)*(short *)(pfVar7 + 3);
      pfVar7[1] = (float)dVar8;
    }
    else if ((sVar1 < 0) && (0 < *(int *)(param_1 + 0xf4))) {
      *(uint *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) - (uint)DAT_803dc070;
    }
  }
  return;
}

