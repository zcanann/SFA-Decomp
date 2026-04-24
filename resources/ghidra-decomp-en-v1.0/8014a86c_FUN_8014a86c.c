// Function: FUN_8014a86c
// Entry: 8014a86c
// Size: 388 bytes

void FUN_8014a86c(int param_1,int param_2,float *param_3,float *param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  ushort uVar7;
  ushort uVar8;
  float *pfVar9;
  int local_18 [2];
  
  fVar2 = FLOAT_803e25c4;
  *param_3 = FLOAT_803e25c4;
  *param_4 = fVar2;
  uVar7 = FUN_80065e50((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                       (double)*(float *)(param_1 + 0x14),param_1,local_18,0,0);
  *param_3 = *(float *)(param_1 + 0x10);
  *param_4 = *(float *)(param_1 + 0x10);
  fVar2 = FLOAT_803e25c8;
  *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xefffffff;
  fVar6 = FLOAT_803e2574;
  *(float *)(param_2 + 0x1b8) = FLOAT_803e2574;
  *(byte *)(param_2 + 0x264) = *(byte *)(param_2 + 0x264) & 0xef;
  fVar4 = fVar2;
  for (uVar8 = 0; uVar8 < uVar7; uVar8 = uVar8 + 1) {
    pfVar9 = *(float **)(local_18[0] + (uint)uVar8 * 4);
    fVar1 = *pfVar9;
    fVar5 = fVar1 - *(float *)(param_1 + 0x10);
    fVar3 = fVar5;
    if (fVar5 < fVar6) {
      fVar3 = -fVar5;
    }
    if (*(char *)(pfVar9 + 5) == '\x0e') {
      if (fVar3 < fVar4) {
        *(float *)(param_2 + 0x1b8) = fVar5;
        *(byte *)(param_2 + 0x264) = *(byte *)(param_2 + 0x264) | 0x10;
        *param_4 = **(float **)(local_18[0] + (uint)uVar8 * 4);
        fVar4 = fVar3;
        if (FLOAT_803e25a0 < *(float *)(param_2 + 0x1b8)) {
          *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x10100000;
        }
      }
    }
    else if (fVar3 < fVar2) {
      *param_3 = fVar1;
      *(byte *)(param_2 + 0x264) = *(byte *)(param_2 + 0x264) | 0x10;
      fVar2 = fVar3;
    }
  }
  return;
}

