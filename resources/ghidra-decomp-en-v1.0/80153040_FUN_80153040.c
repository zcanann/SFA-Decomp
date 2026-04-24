// Function: FUN_80153040
// Entry: 80153040
// Size: 520 bytes

void FUN_80153040(int param_1,int *param_2)

{
  int iVar1;
  char cVar2;
  int iVar3;
  float local_28;
  float local_24;
  float local_20;
  
  iVar3 = *param_2;
  if (*(int *)(param_1 + 0x54) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 0;
  }
  if (*(char *)((int)param_2 + 0x33b) != '\0') {
    param_2[0xba] = param_2[0xba] | 0x80;
  }
  if ((param_2[0xb7] & 0x2000U) != 0) {
    iVar1 = FUN_80010320((double)(float)param_2[0xbf],iVar3);
    if ((((iVar1 != 0) || (*(int *)(iVar3 + 0x10) != 0)) &&
        (cVar2 = (**(code **)(*DAT_803dca9c + 0x90))(iVar3), cVar2 != '\0')) &&
       (cVar2 = (**(code **)(*DAT_803dca9c + 0x8c))
                          ((double)FLOAT_803e28b8,*param_2,param_1,&DAT_803dbcb8,0xffffffff),
       cVar2 != '\0')) {
      param_2[0xb7] = param_2[0xb7] & 0xffffdfff;
    }
    FUN_8014cf7c((double)*(float *)(iVar3 + 0x68),(double)*(float *)(iVar3 + 0x70),param_1,param_2,
                 0xf,0);
    local_28 = *(float *)(iVar3 + 0x68) - *(float *)(param_1 + 0xc);
    local_24 = *(float *)(iVar3 + 0x6c) - *(float *)(param_1 + 0x10);
    local_20 = *(float *)(iVar3 + 0x70) - *(float *)(param_1 + 0x14);
    FUN_8014c678((double)FLOAT_803e28bc,(double)FLOAT_803e28c0,(double)FLOAT_803e28c4,param_1,
                 param_2,&local_28,1);
    param_2[0xc9] = (int)((float)param_2[0xc9] + FLOAT_803db414);
    if (FLOAT_803e28c8 < (float)param_2[0xc9]) {
      param_2[0xb9] = param_2[0xb9] & 0xfffeffff;
      param_2[0xc9] = (int)FLOAT_803e28b0;
    }
  }
  FUN_8014cd1c((double)FLOAT_803e28cc,(double)FLOAT_803e28d0,param_1,param_2,0xf,0);
  param_2[0xca] = (int)((float)param_2[0xca] - FLOAT_803db414);
  if ((float)param_2[0xca] <= FLOAT_803e28b0) {
    param_2[0xca] = (int)FLOAT_803e28b4;
    FUN_8000bb18(param_1,0x25c);
  }
  param_2[0xcb] = (int)FLOAT_803e28b0;
  return;
}

