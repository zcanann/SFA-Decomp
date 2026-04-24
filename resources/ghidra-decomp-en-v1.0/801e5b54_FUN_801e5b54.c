// Function: FUN_801e5b54
// Entry: 801e5b54
// Size: 528 bytes

/* WARNING: Removing unreachable block (ram,0x801e5d44) */

void FUN_801e5b54(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f31;
  undefined auStack56 [6];
  undefined2 local_32;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack28;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = FUN_8002b9ec();
  dVar6 = (double)FUN_80021704(iVar4 + 0x18,param_1 + 0x18);
  iVar4 = FUN_8000b578(param_1,0x40);
  if (iVar4 == 0) {
    if (dVar6 < (double)FLOAT_803e5980) {
      FUN_8000bb18(param_1,0x72);
    }
  }
  else if ((double)FLOAT_803e5980 <= dVar6) {
    FUN_8000b7bc(param_1,0x40);
  }
  if (*(short *)(param_1 + 0x46) != 0x3e4) {
    if (*(int *)(param_1 + 0xf8) == 0) {
      *(undefined4 *)(param_1 + 0xf8) = 1;
      uStack28 = FUN_800221a0(0,0x5a);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      FUN_80030304((double)((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5990) /
                           FLOAT_803e5980),param_1);
    }
    FUN_8002fa48((double)FLOAT_803e5984,(double)FLOAT_803db414,param_1,0);
  }
  if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
    local_30 = FLOAT_803e597c;
    local_32 = 0xc0d;
    local_2c = FLOAT_803e5988;
    local_28 = FLOAT_803e598c;
    local_24 = FLOAT_803e5988;
    FUN_8003842c(param_1,0,&local_2c,&local_28,&local_24,1);
    if (*(int *)(param_1 + 0x30) == 0) {
      fVar1 = *(float *)(param_1 + 0xc);
      fVar2 = *(float *)(param_1 + 0x10);
      fVar3 = *(float *)(param_1 + 0x14);
    }
    else {
      fVar1 = *(float *)(param_1 + 0x18);
      fVar2 = *(float *)(param_1 + 0x1c);
      fVar3 = *(float *)(param_1 + 0x20);
    }
    local_24 = local_24 - fVar3;
    local_28 = local_28 - fVar2;
    local_2c = local_2c - fVar1;
    for (iVar4 = 0; iVar4 < (int)(uint)DAT_803db410; iVar4 = iVar4 + 1) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7c7,auStack56,2,0xffffffff,0);
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

