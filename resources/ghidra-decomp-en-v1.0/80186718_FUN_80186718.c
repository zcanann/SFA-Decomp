// Function: FUN_80186718
// Entry: 80186718
// Size: 352 bytes

void FUN_80186718(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar7 = *(int *)(param_1 + 0xb8);
  iVar6 = *(int *)(param_1 + 0x4c);
  *(short *)(iVar7 + 0x68) = (short)*(char *)(iVar6 + 0x18);
  *(undefined *)(iVar7 + 0x6a) = *(undefined *)(iVar6 + 0x19);
  *(float *)(iVar7 + 0x4c) = FLOAT_803e3aa0;
  *(float *)(iVar7 + 0x50) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
              DOUBLE_803e3ab0);
  *(undefined *)(iVar7 + 0x6f) = 0;
  FUN_80062e84(param_1,0,1);
  iVar5 = FUN_8002b9ec();
  fVar1 = *(float *)(iVar5 + 0x18);
  fVar2 = *(float *)(iVar5 + 0x20);
  fVar3 = *(float *)(iVar5 + 0x1c) + FLOAT_803e3aa4;
  fVar4 = FLOAT_803e3aa8 + *(float *)(iVar5 + 0x1c);
  iVar5 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar5 + 0x54) = fVar1;
  *(float *)(iVar5 + 0x58) = fVar4;
  *(float *)(iVar5 + 0x5c) = fVar2;
  iVar5 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar5 + 0x34) = fVar1 - *(float *)(iVar5 + 0x54);
  *(float *)(iVar5 + 0x38) = fVar3 - *(float *)(iVar5 + 0x58);
  *(float *)(iVar5 + 0x3c) = fVar2 - *(float *)(iVar5 + 0x5c);
  *(undefined *)(iVar5 + 0x6c) = 4;
  FUN_801869dc(param_1);
  FUN_801869dc(param_1);
  FUN_801869dc(param_1);
  FUN_801869dc(param_1);
  FUN_801869dc(param_1);
  FUN_801869dc(param_1);
  *(byte *)(iVar7 + 0x70) = *(byte *)(iVar7 + 0x70) & 0x3f | 0x40;
  *(int *)(iVar7 + 0x60) = (int)*(short *)(iVar6 + 0x1a);
  FUN_8001ff3c(0x698);
  return;
}

