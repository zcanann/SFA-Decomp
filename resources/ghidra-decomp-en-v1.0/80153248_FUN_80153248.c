// Function: FUN_80153248
// Entry: 80153248
// Size: 656 bytes

void FUN_80153248(int param_1,int *param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  undefined auStack72 [4];
  undefined auStack68 [8];
  undefined auStack60 [8];
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  iVar5 = *param_2;
  if (*(char *)((int)param_2 + 0x33b) != '\0') {
    param_2[0xba] = param_2[0xba] | 0x80;
  }
  if ((param_2[0xb7] & 0x80000000U) != 0) {
    FUN_8000bb18(param_1,0x25a);
  }
  if ((((param_2[0xb7] & 0x2000U) != 0) &&
      (((iVar3 = FUN_80010320((double)(FLOAT_803e28d4 * (float)param_2[0xbf]),iVar5), iVar3 != 0 ||
        (*(int *)(iVar5 + 0x10) != 0)) &&
       (cVar4 = (**(code **)(*DAT_803dca9c + 0x90))(iVar5), cVar4 != '\0')))) &&
     (cVar4 = (**(code **)(*DAT_803dca9c + 0x8c))
                        ((double)FLOAT_803e28b8,*param_2,param_1,&DAT_803dbcb8,0xffffffff),
     cVar4 != '\0')) {
    param_2[0xb7] = param_2[0xb7] & 0xffffdfff;
  }
  FUN_80035df4(param_1,0xe,1,0);
  iVar3 = param_2[0xa7];
  local_28 = *(float *)(iVar3 + 0xc) - *(float *)(param_1 + 0xc);
  local_24 = (FLOAT_803e28d8 + *(float *)(iVar3 + 0x10)) - *(float *)(param_1 + 0x10);
  local_20 = *(float *)(iVar3 + 0x14) - *(float *)(param_1 + 0x14);
  FUN_802477f0(&local_28);
  param_2[0xcb] = (int)((float)param_2[0xcb] + FLOAT_803db414);
  if ((param_2[0xd0] != 0) || (FLOAT_803e28c8 < (float)param_2[0xcb])) {
    param_2[0xb9] = param_2[0xb9] | 0x10000;
    fVar1 = FLOAT_803e28b0;
    param_2[0xc9] = (int)FLOAT_803e28b0;
    param_2[0xcb] = (int)fVar1;
  }
  else {
    local_34 = *(undefined4 *)(param_1 + 0xc);
    local_30 = *(undefined4 *)(param_1 + 0x10);
    local_2c = *(undefined4 *)(param_1 + 0x14);
    FUN_80012d00(&local_34,auStack68);
    local_34 = *(undefined4 *)(iVar5 + 0x68);
    local_30 = *(undefined4 *)(iVar5 + 0x6c);
    local_2c = *(undefined4 *)(iVar5 + 0x70);
    FUN_80012d00(&local_34,auStack60);
    uVar2 = countLeadingZeros(param_2[0xb7]);
    if (((uVar2 >> 5 & 0x1000000) != 0) &&
       (iVar5 = FUN_800128dc(auStack60,auStack68,0,auStack72,0), iVar5 == 0)) {
      param_2[0xb9] = param_2[0xb9] | 0x10000;
      fVar1 = FLOAT_803e28b0;
      param_2[0xc9] = (int)FLOAT_803e28b0;
      param_2[0xcb] = (int)fVar1;
    }
  }
  FUN_8014c678((double)FLOAT_803e28bc,(double)FLOAT_803e28c0,(double)FLOAT_803e28c4,param_1,param_2,
               &local_28,1);
  FUN_8014cd1c((double)FLOAT_803e28cc,(double)FLOAT_803e28d0,param_1,param_2,0xf,0);
  return;
}

