// Function: FUN_80153e0c
// Entry: 80153e0c
// Size: 660 bytes

void FUN_80153e0c(int param_1,int *param_2)

{
  float fVar1;
  int iVar2;
  char cVar4;
  uint uVar3;
  int iVar5;
  
  iVar5 = *param_2;
  *(undefined *)((int)param_2 + 0x33a) = 0;
  param_2[0xca] = (int)FLOAT_803e294c;
  if ((param_2[0xb7] & 0x2000U) != 0) {
    iVar2 = FUN_80010320((double)(float)param_2[0xbf],iVar5);
    if ((((iVar2 != 0) || (*(int *)(iVar5 + 0x10) != 0)) &&
        (cVar4 = (**(code **)(*DAT_803dca9c + 0x90))(iVar5), cVar4 != '\0')) &&
       (cVar4 = (**(code **)(*DAT_803dca9c + 0x8c))
                          ((double)FLOAT_803e2950,*param_2,param_1,&DAT_803dbcc8,0xffffffff),
       cVar4 != '\0')) {
      param_2[0xb7] = param_2[0xb7] & 0xffffdfff;
    }
    if (FLOAT_803e294c == (float)param_2[0xcb]) {
      if (*(short *)(param_1 + 0xa0) == 0) {
        FUN_8014cf7c((double)*(float *)(iVar5 + 0x68),(double)*(float *)(iVar5 + 0x70),param_1,
                     param_2,0x3c,0);
      }
      fVar1 = FLOAT_803e294c;
      if ((FLOAT_803e294c < (float)param_2[0xc9]) &&
         (param_2[0xc9] = (int)((float)param_2[0xc9] - FLOAT_803db414),
         (float)param_2[0xc9] <= fVar1)) {
        param_2[0xb9] = param_2[0xb9] & 0xfffeffff;
        param_2[0xc9] = (int)fVar1;
      }
    }
  }
  fVar1 = FLOAT_803e294c;
  if ((float)param_2[0xcb] <= FLOAT_803e294c) {
    if ((param_2[0xb7] & 0x40000000U) != 0) {
      FUN_8014d08c((double)FLOAT_803e2958,param_1,param_2,0,0,3);
    }
  }
  else {
    param_2[0xcb] = (int)((float)param_2[0xcb] - FLOAT_803db414);
    if (fVar1 < (float)param_2[0xcb]) {
      if ((param_2[0xb7] & 0x40000000U) != 0) {
        FUN_8014d08c((double)FLOAT_803e2954,param_1,param_2,5,0,3);
      }
    }
    else {
      FUN_8014d08c((double)FLOAT_803e2948,param_1,param_2,6,0,3);
      param_2[0xcb] = (int)FLOAT_803e294c;
    }
  }
  *(undefined2 *)(param_1 + 2) = *(undefined2 *)(param_2 + 0x67);
  *(undefined2 *)(param_1 + 4) = *(undefined2 *)((int)param_2 + 0x19e);
  param_2[0xcc] = (int)((float)param_2[0xcc] - FLOAT_803db414);
  if ((float)param_2[0xcc] <= FLOAT_803e294c) {
    uVar3 = FUN_800221a0(0x3c,0x78);
    param_2[0xcc] = (int)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e2960);
    FUN_8000bb18(param_1,0x25e);
  }
  if (*(char *)((int)param_2 + 0x33b) != '\0') {
    *(char *)((int)param_2 + 0x33b) = *(char *)((int)param_2 + 0x33b) + -1;
  }
  return;
}

