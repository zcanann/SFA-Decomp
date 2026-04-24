// Function: FUN_8016ba98
// Entry: 8016ba98
// Size: 284 bytes

void FUN_8016ba98(undefined2 *param_1)

{
  float fVar1;
  uint uVar2;
  undefined2 *puVar3;
  int iVar4;
  int *piVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float local_18 [4];
  
  piVar5 = *(int **)(param_1 + 0x5c);
  FUN_80035ff8((int)param_1);
  *(undefined *)(param_1 + 0x1b) = 0xff;
  fVar1 = FLOAT_803e3e60;
  *(float *)(param_1 + 0x12) = FLOAT_803e3e60;
  *(float *)(param_1 + 0x14) = FLOAT_803e3e6c;
  *(float *)(param_1 + 0x16) = fVar1;
  param_1[1] = 0xc000;
  *param_1 = 0;
  param_1[2] = 0;
  dVar7 = (double)*(float *)(param_1 + 8);
  dVar8 = (double)*(float *)(param_1 + 10);
  FUN_80065800((double)*(float *)(param_1 + 6),dVar7,dVar8,param_1,local_18,0);
  dVar6 = (double)*(float *)(param_1 + 8);
  piVar5[1] = (int)(float)(dVar6 - (double)local_18[0]);
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) == 0) {
    *piVar5 = 0;
  }
  else {
    puVar3 = FUN_8002becc(0x20,0xc);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_1 + 10);
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined *)(puVar3 + 3) = 0xff;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    iVar4 = FUN_8002b678(dVar6,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8,(int)param_1,puVar3);
    *piVar5 = iVar4;
    *(undefined2 **)(*piVar5 + 0xc4) = param_1;
  }
  iVar4 = FUN_80013ee8(0x5b);
  piVar5[2] = iVar4;
  *(undefined *)(piVar5 + 3) = 0;
  return;
}

