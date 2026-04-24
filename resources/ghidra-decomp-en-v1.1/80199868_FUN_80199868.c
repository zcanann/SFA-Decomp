// Function: FUN_80199868
// Entry: 80199868
// Size: 196 bytes

void FUN_80199868(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5,
                 undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  double dVar1;
  float fVar2;
  char cVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f7;
  undefined8 in_f8;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  fVar2 = *(float *)(iVar4 + 0x1c) - *(float *)(param_1 + 0x18);
  dVar10 = (double)(*(float *)(iVar4 + 0x20) - *(float *)(param_1 + 0x1c));
  dVar11 = (double)(*(float *)(iVar4 + 0x24) - *(float *)(param_1 + 0x20));
  dVar9 = (double)(float)(dVar11 * dVar11 + (double)(fVar2 * fVar2 + (float)(dVar10 * dVar10)));
  fVar2 = *(float *)(iVar4 + 0x28) - *(float *)(param_1 + 0x18);
  dVar7 = (double)(*(float *)(iVar4 + 0x2c) - *(float *)(param_1 + 0x1c));
  dVar8 = (double)(*(float *)(iVar4 + 0x30) - *(float *)(param_1 + 0x20));
  dVar1 = dVar8 * dVar8 + (double)(fVar2 * fVar2 + (float)(dVar7 * dVar7));
  dVar6 = (double)(float)dVar1;
  dVar5 = (double)*(float *)(iVar4 + 4);
  if (dVar5 <= dVar6) {
    if (dVar5 <= dVar9) {
      cVar3 = -2;
    }
    else {
      cVar3 = -1;
    }
  }
  else if (dVar5 <= dVar9) {
    cVar3 = '\x01';
  }
  else {
    cVar3 = '\x02';
  }
  FUN_8019992c(dVar6,dVar7,dVar8,dVar9,dVar10,dVar11,in_f7,in_f8,param_1,param_2,(int)cVar3,
               (int)dVar1,param_5,param_6,param_7,param_8);
  return;
}

