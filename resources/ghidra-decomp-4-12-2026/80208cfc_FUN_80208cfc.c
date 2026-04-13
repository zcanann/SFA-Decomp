// Function: FUN_80208cfc
// Entry: 80208cfc
// Size: 1196 bytes

/* WARNING: Removing unreachable block (ram,0x80209180) */
/* WARNING: Removing unreachable block (ram,0x80209178) */
/* WARNING: Removing unreachable block (ram,0x80208d14) */
/* WARNING: Removing unreachable block (ram,0x80208d0c) */

void FUN_80208cfc(int *param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  int local_58;
  int local_54;
  undefined2 local_50;
  undefined2 local_4e;
  undefined2 local_4c;
  float local_48;
  int local_44;
  int local_40;
  int local_3c;
  
  local_58 = -1;
  iVar6 = param_1[0x2e];
  iVar5 = param_1[0x13];
  if (*(short *)((int)param_1 + 0x46) == 0x4e0) {
    FLOAT_803de978 = (float)param_1[3];
    FLOAT_803de97c = (float)param_1[5];
  }
  else if ((((*(char *)(iVar6 + 0x6b) == '\0') && (*(char *)(iVar6 + 0x6a) != '\0')) &&
           (*(char *)(iVar6 + 0x69) != '\x04')) && (*(char *)(iVar6 + 0x69) != '\x03')) {
    param_1[0x20] = param_1[3];
    param_1[0x21] = param_1[4];
    param_1[0x22] = param_1[5];
    local_54 = 0;
    iVar3 = FUN_80036974((int)param_1,&local_54,&local_58,(uint *)0x0);
    if (((iVar3 != 0) && (local_54 != 0)) && ((iVar3 == 0xe && (iVar3 == 0xe)))) {
      FUN_8000bb38((uint)param_1,0x44d);
      fVar1 = *(float *)(local_54 + 0x24);
      fVar2 = *(float *)(local_54 + 0x2c);
      if (fVar1 < FLOAT_803e7124) {
        fVar1 = fVar1 * FLOAT_803e712c;
      }
      if (fVar2 < FLOAT_803e7124) {
        fVar2 = fVar2 * FLOAT_803e712c;
      }
      if (fVar1 <= fVar2) {
        *(float *)(local_54 + 0x24) = FLOAT_803e7124;
      }
      else {
        *(float *)(local_54 + 0x2c) = FLOAT_803e7124;
      }
      fVar1 = FLOAT_803e7130;
      param_1[9] = (int)(*(float *)(local_54 + 0x24) * FLOAT_803e7130);
      param_1[0xb] = (int)(*(float *)(local_54 + 0x2c) * fVar1);
    }
    param_1[3] = (int)((float)param_1[9] * FLOAT_803dc074 + (float)param_1[3]);
    param_1[5] = (int)((float)param_1[0xb] * FLOAT_803dc074 + (float)param_1[5]);
    if (FLOAT_803e7124 != (float)param_1[9]) {
      FUN_8000da78((uint)param_1,0x3bd);
      fVar1 = (float)param_1[9];
      if (FLOAT_803e7124 <= fVar1) {
        if ((FLOAT_803e7124 < fVar1) && (fVar1 <= FLOAT_803e7124)) {
          param_1[9] = (int)FLOAT_803e7124;
        }
      }
      else if (FLOAT_803e7124 <= fVar1) {
        param_1[9] = (int)FLOAT_803e7124;
      }
    }
    if (FLOAT_803e7124 != (float)param_1[0xb]) {
      FUN_8000da78((uint)param_1,0x3bd);
      fVar1 = (float)param_1[0xb];
      if (FLOAT_803e7124 <= fVar1) {
        if ((FLOAT_803e7124 < fVar1) && (fVar1 <= FLOAT_803e7124)) {
          param_1[0xb] = (int)FLOAT_803e7124;
        }
      }
      else if (FLOAT_803e7124 <= fVar1) {
        param_1[0xb] = (int)FLOAT_803e7124;
      }
    }
    FUN_80208b40(param_1,iVar6);
    dVar8 = (double)(*(float *)(iVar5 + 8) - (float)param_1[3]);
    dVar7 = (double)(*(float *)(iVar5 + 0x10) - (float)param_1[5]);
    cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0x2b));
    if (cVar4 == '\x01') {
      if ((((double)FLOAT_803e7134 < dVar8) || (dVar8 < (double)FLOAT_803e7138)) ||
         ((dVar7 < (double)FLOAT_803e713c || ((double)FLOAT_803e7140 < dVar7)))) {
        param_1[3] = *(int *)(iVar5 + 8);
        param_1[5] = *(int *)(iVar5 + 0x10);
        fVar1 = FLOAT_803e7124;
        param_1[9] = (int)FLOAT_803e7124;
        param_1[0xb] = (int)fVar1;
        *(undefined *)(iVar6 + 0x69) = 2;
        param_1[4] = (int)(*(float *)(iVar5 + 0xc) - FLOAT_803e7144);
        FUN_8000bb38((uint)param_1,0x1d3);
      }
      fVar1 = (float)param_1[3] - FLOAT_803de978;
      fVar2 = (float)param_1[5] - FLOAT_803de97c;
      if ((FLOAT_803e7124 == fVar1) && (FLOAT_803e7124 == fVar2)) {
        *(undefined *)(iVar6 + 0x69) = 3;
      }
      else {
        dVar7 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
        if (dVar7 < (double)FLOAT_803e7148) {
          *(undefined *)(iVar6 + 0x69) = 3;
        }
      }
    }
    else if (cVar4 == '\x02') {
      if (((((double)FLOAT_803e714c < dVar8) || (dVar8 < (double)FLOAT_803e7150)) ||
          (dVar7 < (double)FLOAT_803e713c)) || ((double)FLOAT_803e7154 < dVar7)) {
        param_1[3] = *(int *)(iVar5 + 8);
        param_1[5] = *(int *)(iVar5 + 0x10);
        fVar1 = FLOAT_803e7124;
        param_1[9] = (int)FLOAT_803e7124;
        param_1[0xb] = (int)fVar1;
        *(undefined *)(iVar6 + 0x69) = 2;
        param_1[4] = (int)(*(float *)(iVar5 + 0xc) - FLOAT_803e7144);
        FUN_8000bb38((uint)param_1,0x1d3);
        local_44 = param_1[3];
        local_40 = param_1[4];
        local_3c = param_1[5];
        local_48 = FLOAT_803e7128;
        local_4c = 0;
        local_4e = 0;
        local_50 = 0;
        iVar5 = 0x14;
        do {
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x5f5,&local_50,0x200001,0xffffffff,0);
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
      fVar1 = (float)param_1[3] - FLOAT_803de978;
      fVar2 = (float)param_1[5] - FLOAT_803de97c;
      if ((FLOAT_803e7124 == fVar1) && (FLOAT_803e7124 == fVar2)) {
        *(undefined *)(iVar6 + 0x69) = 3;
      }
      else {
        dVar7 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
        if (dVar7 < (double)FLOAT_803e7158) {
          *(undefined *)(iVar6 + 0x69) = 3;
        }
      }
    }
  }
  return;
}

