// Function: FUN_8016c4ac
// Entry: 8016c4ac
// Size: 676 bytes

/* WARNING: Removing unreachable block (ram,0x8016c72c) */

void FUN_8016c4ac(int param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  byte bVar5;
  undefined4 uVar4;
  undefined4 uVar6;
  undefined8 in_f31;
  double dVar7;
  undefined auStack56 [8];
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if ((*(uint *)(param_1 + 0xf8) & 4) != 0) {
    dVar7 = (double)FLOAT_803e3240;
    for (bVar5 = 0; bVar5 < 10; bVar5 = bVar5 + 1) {
      fVar1 = *(float *)(param_1 + 8);
      uVar2 = (uint)bVar5;
      local_2c = (float)(dVar7 * (double)(fVar1 * (float)(&DAT_80320768)[uVar2 * 5]));
      local_28 = (float)(dVar7 * (double)(fVar1 * (float)(&DAT_8032076c)[uVar2 * 5]));
      local_24 = (float)(dVar7 * (double)(fVar1 * (float)(&DAT_80320770)[uVar2 * 5]));
      FUN_800971a0((double)(fVar1 * (float)(&DAT_80320774)[uVar2 * 5]),param_1,3,
                   (&DAT_80320778)[uVar2 * 0x14],(&DAT_80320779)[uVar2 * 0x14],auStack56);
    }
  }
  local_30 = FLOAT_803e3244;
  if ((*(uint *)(param_1 + 0xf8) & 1) != 0) {
    if ((*(uint *)(param_1 + 0xf8) & 2) == 0) {
      uVar4 = 3;
    }
    else {
      uVar4 = 6;
    }
    fVar1 = *(float *)(param_1 + 8);
    local_2c = FLOAT_803e3240 * FLOAT_803e3248 * fVar1;
    local_28 = FLOAT_803e3240 * FLOAT_803e324c * fVar1;
    local_24 = FLOAT_803e3240 * FLOAT_803e3250 * fVar1;
    FUN_8009837c((double)(FLOAT_803e3254 * fVar1),(double)FLOAT_803e3258,param_1,1,0,uVar4,auStack56
                );
    local_2c = FLOAT_803e325c;
    fVar1 = *(float *)(param_1 + 8);
    local_28 = FLOAT_803e3240 * FLOAT_803e3260 * fVar1;
    local_24 = FLOAT_803e3240 * FLOAT_803e3264 * fVar1;
    FUN_8009837c((double)(FLOAT_803e3254 * fVar1),(double)FLOAT_803e3268,param_1,1,0,uVar4,auStack56
                );
    fVar1 = *(float *)(param_1 + 8);
    local_2c = FLOAT_803e3240 * FLOAT_803e326c * fVar1;
    local_28 = FLOAT_803e3240 * FLOAT_803e324c * fVar1;
    local_24 = FLOAT_803e3240 * FLOAT_803e3250 * fVar1;
    FUN_8009837c((double)(FLOAT_803e3254 * fVar1),(double)FLOAT_803e3258,param_1,1,0,uVar4,auStack56
                );
  }
  if (*(short *)(param_1 + 0x46) == 0xa8) {
    FUN_800972dc((double)FLOAT_803e3270,(double)FLOAT_803e3274,param_1,7,5,1,10,0,0x20000000);
  }
  else if (*(short *)(param_1 + 0x46) == 0x451) {
    iVar3 = FUN_8002b588(param_1);
    *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = 2;
    if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
      FUN_800972dc((double)FLOAT_803e3270,(double)FLOAT_803e3278,param_1,5,2,1,0x14,0,0);
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return;
}

