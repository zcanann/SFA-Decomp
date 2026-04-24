// Function: FUN_80186c70
// Entry: 80186c70
// Size: 352 bytes

void FUN_80186c70(short *param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar7 = *(int *)(param_1 + 0x5c);
  iVar6 = *(int *)(param_1 + 0x26);
  *(short *)(iVar7 + 0x68) = (short)*(char *)(iVar6 + 0x18);
  *(undefined *)(iVar7 + 0x6a) = *(undefined *)(iVar6 + 0x19);
  *(float *)(iVar7 + 0x4c) = FLOAT_803e4738;
  *(float *)(iVar7 + 0x50) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
              DOUBLE_803e4748);
  *(undefined *)(iVar7 + 0x6f) = 0;
  FUN_80063000(param_1,(short *)0x0,1);
  iVar5 = FUN_8002bac4();
  fVar1 = *(float *)(iVar5 + 0x18);
  fVar2 = *(float *)(iVar5 + 0x20);
  fVar3 = *(float *)(iVar5 + 0x1c) + FLOAT_803e473c;
  fVar4 = FLOAT_803e4740 + *(float *)(iVar5 + 0x1c);
  iVar5 = *(int *)(param_1 + 0x5c);
  *(float *)(iVar5 + 0x54) = fVar1;
  *(float *)(iVar5 + 0x58) = fVar4;
  *(float *)(iVar5 + 0x5c) = fVar2;
  iVar5 = *(int *)(param_1 + 0x5c);
  *(float *)(iVar5 + 0x34) = fVar1 - *(float *)(iVar5 + 0x54);
  *(float *)(iVar5 + 0x38) = fVar3 - *(float *)(iVar5 + 0x58);
  *(float *)(iVar5 + 0x3c) = fVar2 - *(float *)(iVar5 + 0x5c);
  *(undefined *)(iVar5 + 0x6c) = 4;
  FUN_80186f34((int)param_1);
  FUN_80186f34((int)param_1);
  FUN_80186f34((int)param_1);
  FUN_80186f34((int)param_1);
  FUN_80186f34((int)param_1);
  FUN_80186f34((int)param_1);
  *(byte *)(iVar7 + 0x70) = *(byte *)(iVar7 + 0x70) & 0x3f | 0x40;
  *(int *)(iVar7 + 0x60) = (int)*(short *)(iVar6 + 0x1a);
  FUN_80020000(0x698);
  return;
}

