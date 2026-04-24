// Function: FUN_80154584
// Entry: 80154584
// Size: 748 bytes

void FUN_80154584(int param_1,int *param_2)

{
  int iVar1;
  char cVar2;
  int iVar3;
  double dVar4;
  float local_38;
  float local_34;
  float local_30;
  double local_28;
  undefined4 local_20;
  uint uStack28;
  double local_18;
  
  iVar3 = *param_2;
  *(undefined *)((int)param_2 + 0x33b) = 0;
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 0;
  if ((param_2[0xb7] & 0x2000U) != 0) {
    iVar1 = FUN_80010320((double)(float)param_2[0xbf],iVar3);
    if ((((iVar1 != 0) || (*(int *)(iVar3 + 0x10) != 0)) &&
        (cVar2 = (**(code **)(*DAT_803dca9c + 0x90))(iVar3), cVar2 != '\0')) &&
       (cVar2 = (**(code **)(*DAT_803dca9c + 0x8c))
                          ((double)FLOAT_803e29b0,*param_2,param_1,&DAT_803dbcd0,0xffffffff),
       cVar2 != '\0')) {
      param_2[0xb7] = param_2[0xb7] & 0xffffdfff;
    }
    local_38 = *(float *)(iVar3 + 0x68) - *(float *)(param_1 + 0xc);
    local_34 = FLOAT_803e2990;
    local_30 = *(float *)(iVar3 + 0x70) - *(float *)(param_1 + 0x14);
    FUN_8014c678((double)FLOAT_803e29a0,(double)FLOAT_803e29b4,(double)FLOAT_803e29b4,param_1,
                 param_2,&local_38,1);
    param_2[0xc9] = (int)((float)param_2[0xc9] + FLOAT_803db414);
    if (FLOAT_803e29b8 < (float)param_2[0xc9]) {
      param_2[0xb9] = param_2[0xb9] & 0xfffeffff;
      param_2[0xc9] = (int)FLOAT_803e2990;
    }
  }
  local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)param_2 + 0x33a));
  dVar4 = (double)FUN_80293da4((double)(FLOAT_803e29c0 * (float)(local_28 - DOUBLE_803e29d8)));
  uStack28 = (int)*(short *)(param_1 + 2) ^ 0x80000000;
  local_20 = 0x43300000;
  iVar3 = (int)-(float)((double)FLOAT_803e29bc * dVar4 -
                       (double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e29a8));
  local_18 = (double)(longlong)iVar3;
  *(short *)(param_1 + 2) = (short)iVar3;
  FUN_8014cd1c((double)FLOAT_803e29c4,(double)FLOAT_803e2994,param_1,param_2,0xf,0);
  if ((param_2[0xb7] & 0x40000000U) != 0) {
    if (DOUBLE_803e29c8 <= (double)*(float *)(param_1 + 0x98)) {
      cVar2 = FUN_800221a0(0,0x3c);
    }
    else {
      cVar2 = FUN_800221a0(0,200);
    }
    if (cVar2 == '\0') {
      if ((double)*(float *)(param_1 + 0x98) <= DOUBLE_803e29c8) {
        FUN_8000bb18(param_1,0x24c);
        param_2[0xc2] = (int)FLOAT_803e29d4;
      }
      else {
        FUN_8000bb18(param_1,0x24b);
        param_2[0xc2] = (int)FLOAT_803e29d0;
      }
    }
  }
  *(char *)((int)param_2 + 0x33a) = *(char *)((int)param_2 + 0x33a) + '\x01';
  local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)param_2 + 0x33a));
  dVar4 = (double)FUN_80293da4((double)(FLOAT_803e29c0 * (float)(local_18 - DOUBLE_803e29d8)));
  uStack28 = (int)*(short *)(param_1 + 2) ^ 0x80000000;
  local_20 = 0x43300000;
  iVar3 = (int)((double)FLOAT_803e29bc * dVar4 +
               (double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e29a8));
  local_28 = (double)(longlong)iVar3;
  *(short *)(param_1 + 2) = (short)iVar3;
  FUN_80154328(param_1,param_2);
  return;
}

