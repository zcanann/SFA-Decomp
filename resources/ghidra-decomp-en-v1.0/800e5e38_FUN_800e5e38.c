// Function: FUN_800e5e38
// Entry: 800e5e38
// Size: 228 bytes

void FUN_800e5e38(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  float *pfVar6;
  int local_18 [4];
  
  iVar5 = FUN_800e6b38((double)*(float *)(param_2 + 8),(double)*(float *)(param_2 + 0x10),param_1,
                       local_18,0);
  fVar1 = *(float *)(param_1 + 0x1c);
  pfVar6 = (float *)(iVar5 + (local_18[0] + -1) * 0x18);
  fVar3 = FLOAT_803e06a0;
  if (-1 < local_18[0] + -1) {
    do {
      fVar4 = fVar3;
      if (((*(char *)(pfVar6 + 5) != '\x0e') &&
          (fVar2 = *pfVar6, fVar4 = FLOAT_803e0688, fVar1 <= fVar2)) && (fVar2 - fVar3 <= fVar1)) {
        *(float *)(param_1 + 0x1c) = fVar2;
        *(float *)(param_2 + 0x1a0) = pfVar6[1];
        *(float *)(param_2 + 0x1a4) = pfVar6[2];
        *(float *)(param_2 + 0x1a8) = pfVar6[3];
        *(byte *)(param_2 + 0x260) = *(byte *)(param_2 + 0x260) | 0x11;
        *(char *)(param_2 + 0x261) = *(char *)(param_2 + 0x261) + '\x01';
        fVar4 = FLOAT_803e0688;
      }
      fVar3 = fVar4;
      pfVar6 = pfVar6 + -6;
      local_18[0] = local_18[0] + -1;
    } while (local_18[0] != 0);
  }
  return;
}

