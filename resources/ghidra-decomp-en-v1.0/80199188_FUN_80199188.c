// Function: FUN_80199188
// Entry: 80199188
// Size: 356 bytes

void FUN_80199188(int param_1,undefined4 param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  bool bVar7;
  char cVar8;
  int iVar9;
  double local_8;
  
  iVar9 = *(int *)(param_1 + 0xb8);
  local_8 = (double)CONCAT44(0x43300000,
                             (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x3b) << 1 ^ 0x80000000);
  fVar1 = (float)(local_8 - DOUBLE_803e40d0);
  fVar2 = *(float *)(iVar9 + 0x1c) - *(float *)(param_1 + 0x18);
  fVar4 = *(float *)(iVar9 + 0x20) - *(float *)(param_1 + 0x1c);
  fVar3 = *(float *)(iVar9 + 0x24) - *(float *)(param_1 + 0x20);
  fVar3 = fVar2 * fVar2 + fVar3 * fVar3;
  fVar2 = *(float *)(iVar9 + 0x28) - *(float *)(param_1 + 0x18);
  fVar5 = *(float *)(iVar9 + 0x2c) - *(float *)(param_1 + 0x1c);
  fVar6 = *(float *)(iVar9 + 0x30) - *(float *)(param_1 + 0x20);
  fVar6 = fVar2 * fVar2 + fVar6 * fVar6;
  fVar2 = *(float *)(iVar9 + 4);
  if (fVar6 < fVar2) {
    if (fVar5 < FLOAT_803e40d8) {
      fVar5 = -fVar5;
    }
    if (fVar5 < fVar1) {
      bVar7 = false;
      if (fVar3 < fVar2) {
        if (fVar4 < FLOAT_803e40d8) {
          fVar4 = -fVar4;
        }
        if (fVar4 < fVar1) {
          bVar7 = true;
        }
      }
      if (bVar7) {
        cVar8 = '\x02';
      }
      else {
        cVar8 = '\x01';
      }
      goto LAB_801992cc;
    }
  }
  bVar7 = false;
  if (fVar3 < fVar2) {
    if (fVar4 < FLOAT_803e40d8) {
      fVar4 = -fVar4;
    }
    if (fVar4 < fVar1) {
      bVar7 = true;
    }
  }
  if (bVar7) {
    cVar8 = -1;
  }
  else {
    cVar8 = -2;
  }
LAB_801992cc:
  FUN_801993b0(param_1,param_2,(int)cVar8,(int)fVar6);
  return;
}

