// Function: FUN_80154870
// Entry: 80154870
// Size: 948 bytes

void FUN_80154870(int param_1,int *param_2)

{
  float fVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  double dVar5;
  float local_38;
  float local_34;
  float local_30;
  double local_28;
  undefined4 local_20;
  uint uStack28;
  double local_18;
  
  iVar4 = *param_2;
  if ((param_2[0xb7] & 0x80000000U) != 0) {
    FUN_8000bb18(param_1,0x4c0);
  }
  if ((((param_2[0xb7] & 0x2000U) != 0) &&
      (((iVar2 = FUN_80010320((double)FLOAT_803e2990,iVar4), iVar2 != 0 ||
        (*(int *)(iVar4 + 0x10) != 0)) &&
       (cVar3 = (**(code **)(*DAT_803dca9c + 0x90))(iVar4), cVar3 != '\0')))) &&
     (cVar3 = (**(code **)(*DAT_803dca9c + 0x8c))
                        ((double)FLOAT_803e29b0,*param_2,param_1,&DAT_803dbcd0,0xffffffff),
     cVar3 != '\0')) {
    param_2[0xb7] = param_2[0xb7] & 0xffffdfff;
  }
  FUN_80035df4(param_1,0xe,1,0);
  FUN_8002b9ec();
  cVar3 = FUN_80296448();
  local_38 = *(float *)(param_2[0xa7] + 0xc) - *(float *)(param_1 + 0xc);
  local_34 = FLOAT_803e2990;
  local_30 = *(float *)(param_2[0xa7] + 0x14) - *(float *)(param_1 + 0x14);
  if ((param_2[0xd0] != 0) && (iVar4 = FUN_8002b9ec(), param_2[0xd0] == iVar4)) {
    param_2[0xb9] = param_2[0xb9] | 0x10000;
    param_2[0xc9] = (int)FLOAT_803e2990;
  }
  local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)param_2 + 0x33a));
  dVar5 = (double)FUN_80293da4((double)(FLOAT_803e29c0 * (float)(local_28 - DOUBLE_803e29d8)));
  uStack28 = (int)*(short *)(param_1 + 2) ^ 0x80000000;
  local_20 = 0x43300000;
  iVar4 = (int)-(float)((double)FLOAT_803e29bc * dVar5 -
                       (double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e29a8));
  local_18 = (double)(longlong)iVar4;
  *(short *)(param_1 + 2) = (short)iVar4;
  fVar1 = FLOAT_803e2990;
  if (cVar3 == '\0') {
    *(float *)(param_1 + 0x24) = FLOAT_803e2990;
    *(float *)(param_1 + 0x2c) = fVar1;
    FUN_8014cf7c((double)*(float *)(param_2[0xa7] + 0xc),(double)*(float *)(param_2[0xa7] + 0x14),
                 param_1,param_2,10,0);
  }
  else {
    FUN_8014c678((double)FLOAT_803e29a0,(double)FLOAT_803e29b4,(double)FLOAT_803e29b4,param_1,
                 param_2,&local_38,1);
    FUN_8014cd1c((double)FLOAT_803e29c4,(double)FLOAT_803e2994,param_1,param_2,0xf,0);
  }
  fVar1 = FLOAT_803e2990;
  if ((param_2[0xb7] & 0x40000000U) != 0) {
    if (FLOAT_803e2990 == (float)param_2[0xca]) {
      if (cVar3 == '\0') {
        if (*(float *)(param_1 + 0x98) <= FLOAT_803e29a4) {
          param_2[0xca] = (int)FLOAT_803e29e4;
        }
        else {
          param_2[0xca] = (int)FLOAT_803e29e0;
          *(char *)((int)param_2 + 0x33b) = *(char *)((int)param_2 + 0x33b) + '\x01';
        }
      }
      else if ((double)*(float *)(param_1 + 0x98) <= DOUBLE_803e29c8) {
        FUN_8000bb18(param_1,0x24c);
        param_2[0xc2] = (int)FLOAT_803e29d4;
      }
      else {
        FUN_8000bb18(param_1,0x24b);
        param_2[0xc2] = (int)FLOAT_803e29d0;
      }
    }
    else {
      param_2[0xca] = (int)((float)param_2[0xca] - FLOAT_803db414);
      if ((float)param_2[0xca] <= fVar1) {
        param_2[0xca] = (int)fVar1;
        if ((double)*(float *)(param_1 + 0x98) <= DOUBLE_803e29c8) {
          FUN_8000bb18(param_1,0x24c);
          param_2[0xc2] = (int)FLOAT_803e29b4;
        }
        else {
          FUN_8000bb18(param_1,0x24b);
          param_2[0xc2] = (int)FLOAT_803e29d0;
        }
      }
    }
  }
  *(char *)((int)param_2 + 0x33a) = *(char *)((int)param_2 + 0x33a) + '\x01';
  local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)param_2 + 0x33a));
  dVar5 = (double)FUN_80293da4((double)(FLOAT_803e29c0 * (float)(local_18 - DOUBLE_803e29d8)));
  uStack28 = (int)*(short *)(param_1 + 2) ^ 0x80000000;
  local_20 = 0x43300000;
  iVar4 = (int)((double)FLOAT_803e29bc * dVar5 +
               (double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e29a8));
  local_28 = (double)(longlong)iVar4;
  *(short *)(param_1 + 2) = (short)iVar4;
  FUN_80154328(param_1,param_2);
  return;
}

