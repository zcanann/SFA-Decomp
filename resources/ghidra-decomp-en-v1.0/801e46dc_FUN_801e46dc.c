// Function: FUN_801e46dc
// Entry: 801e46dc
// Size: 812 bytes

void FUN_801e46dc(undefined2 *param_1)

{
  float fVar1;
  int iVar2;
  undefined2 uVar3;
  float *pfVar4;
  float local_28;
  float local_24;
  float local_20;
  undefined4 local_18;
  uint uStack20;
  
  pfVar4 = *(float **)(param_1 + 0x5c);
  iVar2 = FUN_8002b9ec();
  fVar1 = FLOAT_803e58ec;
  if (pfVar4[8] == FLOAT_803e58ec) {
    *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 10);
    uStack20 = FUN_800221a0(0xffffff9c,100);
    uStack20 = uStack20 ^ 0x80000000;
    local_18 = 0x43300000;
    *(float *)(param_1 + 4) =
         FLOAT_803e58f8 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e5908) +
         FLOAT_803e58f4;
    if (*(char *)(pfVar4 + 7) == '\0') {
      *pfVar4 = *(float *)(param_1 + 0x12);
      pfVar4[1] = *(float *)(param_1 + 0x14);
      pfVar4[2] = *(float *)(param_1 + 0x16);
      *(undefined *)(pfVar4 + 7) = 1;
      pfVar4[3] = *(float *)(param_1 + 6);
      pfVar4[4] = *(float *)(param_1 + 8);
      pfVar4[5] = *(float *)(param_1 + 10);
    }
    fVar1 = FLOAT_803e58fc;
    pfVar4[3] = FLOAT_803e58fc * *pfVar4 * FLOAT_803db414 + pfVar4[3];
    pfVar4[4] = fVar1 * pfVar4[1] * FLOAT_803db414 + pfVar4[4];
    pfVar4[5] = fVar1 * pfVar4[2] * FLOAT_803db414 + pfVar4[5];
    *(float *)(param_1 + 6) = pfVar4[3];
    *(float *)(param_1 + 8) = pfVar4[4];
    *(float *)(param_1 + 10) = pfVar4[5];
    *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) - (uint)DAT_803db410;
    if (((*(int *)(param_1 + 0x7a) < 0) ||
        ((iVar2 != 0 && ((*(ushort *)(iVar2 + 0xb0) & 0x1000) != 0)))) &&
       (pfVar4[8] == FLOAT_803e58ec)) {
      *(undefined *)(param_1 + 0x1b) = 0;
      pfVar4[8] = FLOAT_803e58f0;
    }
    uVar3 = FUN_800217c0((double)(*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40)),
                         (double)(*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44)));
    *param_1 = uVar3;
    *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6e) = 5;
    *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6f) = 1;
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x48) = 0x10;
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x4c) = 0x10;
    *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) = *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) | 1;
    if ((*(char *)(*(int *)(param_1 + 0x2a) + 0xad) != '\0') && (pfVar4[8] == FLOAT_803e58ec)) {
      FUN_80099660((double)FLOAT_803e58e8,param_1,2);
      pfVar4[8] = FLOAT_803e58f0;
      *(undefined *)(param_1 + 0x1b) = 0;
    }
    local_28 = FLOAT_803e5900 * -*pfVar4;
    local_24 = FLOAT_803e5900 * -pfVar4[1];
    local_20 = FLOAT_803e5900 * -pfVar4[2];
    FUN_80098928((double)FLOAT_803e5904,param_1,2,0x156,0xf,&local_28);
    FUN_80098928((double)FLOAT_803e5904,param_1,2,0x156,0xf,&local_28);
    FUN_80098928((double)FLOAT_803e5904,param_1,2,0x156,0xf,&local_28);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0xa8,0,2,0xffffffff,0);
  }
  else {
    pfVar4[8] = pfVar4[8] - FLOAT_803db414;
    if (pfVar4[8] <= fVar1) {
      pfVar4[8] = fVar1;
      FUN_8002cbc4(param_1);
    }
  }
  return;
}

