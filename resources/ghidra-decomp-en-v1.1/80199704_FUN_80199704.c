// Function: FUN_80199704
// Entry: 80199704
// Size: 356 bytes

void FUN_80199704(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5,
                 undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  char cVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f8;
  undefined8 local_8;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  local_8 = (double)CONCAT44(0x43300000,
                             (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x3b) << 1 ^ 0x80000000);
  dVar13 = (double)(float)(local_8 - DOUBLE_803e4d68);
  fVar2 = *(float *)(iVar5 + 0x1c) - *(float *)(param_1 + 0x18);
  dVar12 = (double)(*(float *)(iVar5 + 0x20) - *(float *)(param_1 + 0x1c));
  dVar9 = (double)*(float *)(param_1 + 0x20);
  fVar1 = (float)((double)*(float *)(iVar5 + 0x24) - dVar9);
  dVar10 = (double)(fVar2 * fVar2 + fVar1 * fVar1);
  fVar2 = *(float *)(iVar5 + 0x28) - *(float *)(param_1 + 0x18);
  dVar11 = (double)(*(float *)(iVar5 + 0x2c) - *(float *)(param_1 + 0x1c));
  fVar1 = (float)((double)*(float *)(iVar5 + 0x30) - dVar9);
  fVar1 = fVar2 * fVar2 + fVar1 * fVar1;
  dVar8 = (double)fVar1;
  dVar7 = (double)*(float *)(iVar5 + 4);
  if (dVar8 < dVar7) {
    dVar6 = dVar11;
    if (dVar11 < (double)FLOAT_803e4d70) {
      dVar6 = -dVar11;
    }
    if (dVar6 < dVar13) {
      bVar3 = false;
      if (dVar10 < dVar7) {
        dVar6 = dVar12;
        if (dVar12 < (double)FLOAT_803e4d70) {
          dVar6 = -dVar12;
        }
        if (dVar6 < dVar13) {
          bVar3 = true;
        }
      }
      if (bVar3) {
        cVar4 = '\x02';
      }
      else {
        cVar4 = '\x01';
      }
      goto LAB_80199848;
    }
  }
  bVar3 = false;
  if (dVar10 < dVar7) {
    dVar6 = dVar12;
    if (dVar12 < (double)FLOAT_803e4d70) {
      dVar6 = -dVar12;
    }
    if (dVar6 < dVar13) {
      bVar3 = true;
    }
  }
  if (bVar3) {
    cVar4 = -1;
  }
  else {
    cVar4 = -2;
  }
LAB_80199848:
  FUN_8019992c(dVar7,dVar8,dVar9,dVar10,dVar11,dVar12,dVar13,in_f8,param_1,param_2,(int)cVar4,
               (int)fVar1,param_5,param_6,param_7,param_8);
  return;
}

