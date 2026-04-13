// Function: FUN_800e5928
// Entry: 800e5928
// Size: 600 bytes

void FUN_800e5928(int param_1,uint *param_2)

{
  uint uVar1;
  float *pfVar2;
  float *pfVar3;
  int iVar4;
  double dVar5;
  int local_88;
  float afStack_84 [19];
  float local_38;
  undefined local_24;
  
  uVar1 = param_2[7];
  if ((*param_2 & 0x100000) == 0) {
    *(uint *)(param_1 + 0x18) = param_2[5];
    *(uint *)(param_1 + 0x20) = uVar1;
    *(uint *)(param_1 + 0x1c) = param_2[3];
  }
  pfVar2 = (float *)FUN_800e6dbc((double)(float)param_2[5],(double)(float)param_2[7],param_1,
                                 &local_88,0);
  iVar4 = 0;
  pfVar3 = pfVar2;
  if (0 < local_88) {
    do {
      if ((*(char *)(pfVar3 + 5) != '\x0e') && (FLOAT_803e12f8 < pfVar3[2])) {
        if ((*pfVar3 <= (float)param_2[6]) && ((float)param_2[3] < *pfVar3)) {
          param_2[0xe] = param_2[5];
          param_2[0xf] = param_2[6];
          param_2[0x10] = param_2[7];
          param_2[2] = param_2[5];
          param_2[3] = (uint)pfVar2[iVar4 * 6];
          param_2[4] = param_2[7];
          FUN_80067ad4();
          break;
        }
      }
      pfVar3 = pfVar3 + 6;
      iVar4 = iVar4 + 1;
      local_88 = local_88 + -1;
    } while (local_88 != 0);
  }
  if (*(short *)(param_1 + 0x44) == 1) {
    param_2[0x14] = param_2[5];
    param_2[0x15] = param_2[6];
    param_2[0x16] = param_2[7];
    param_2[8] = param_2[5];
    param_2[9] = (uint)(FLOAT_803e12fc + (float)param_2[6]);
    param_2[10] = param_2[7];
    local_38 = FLOAT_803e1300;
    local_24 = 3;
    FUN_80067ad4();
  }
  FUN_80247eb8((float *)(param_2 + 2),(float *)(param_2 + 5),afStack_84);
  if (((*param_2 & 0x8000000) != 0) ||
     (dVar5 = FUN_80247f54(afStack_84), (double)FLOAT_803e1304 < dVar5)) {
    param_2[0xe] = param_2[5];
    param_2[0xf] = param_2[6];
    param_2[0x10] = param_2[7];
    param_2[2] = param_2[5];
    param_2[3] = (uint)((float)param_2[6] - FLOAT_803e1308);
    param_2[4] = param_2[7];
    FUN_80067ad4();
  }
  param_2[0x68] = param_2[0x1a];
  param_2[0x69] = param_2[0x1b];
  param_2[0x6a] = param_2[0x1c];
  param_2[0x36] = param_2[0x31];
  if (param_2[0x36] != 0) {
    FUN_80036800(param_2[0x36],param_1);
  }
  return;
}

