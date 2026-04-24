// Function: FUN_8022e6b0
// Entry: 8022e6b0
// Size: 668 bytes

/* WARNING: Removing unreachable block (ram,0x8022e928) */

void FUN_8022e6b0(int param_1)

{
  int iVar1;
  int iVar2;
  short sVar3;
  undefined *puVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  undefined auStack88 [4];
  undefined auStack84 [4];
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  undefined4 local_28;
  uint uStack36;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  puVar4 = *(undefined **)(param_1 + 0xb8);
  iVar1 = FUN_8022d768();
  if ((*(short *)(param_1 + 0x46) == 0x80d) &&
     (iVar2 = FUN_8003687c(param_1,auStack84,0,auStack88), iVar2 != 0)) {
    FUN_8009ab70((double)FLOAT_803e7014,param_1,1,0,0,1,0,0,3);
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    FUN_80035f00(param_1);
    *(float *)(puVar4 + 0x10) = FLOAT_803e7028;
  }
  if ((*(int *)(*(int *)(param_1 + 0x54) + 0x50) != 0) && (puVar4[1] == '\0')) {
    if (*(short *)(param_1 + 0x46) != 0x6ae) {
      FUN_8000b4d0(param_1,0x2b3,4);
    }
    if (*(short *)(param_1 + 0x46) == 0x7e4) {
      sVar3 = FUN_800217c0((double)(*(float *)(param_1 + 0xc) - *(float *)(iVar1 + 0xc)),
                           (double)(*(float *)(param_1 + 0x10) - *(float *)(iVar1 + 0x10)));
      uStack36 = (int)-sVar3 ^ 0x80000000;
      local_28 = 0x43300000;
      dVar7 = (double)((FLOAT_803e7030 *
                       (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e7020)) /
                      FLOAT_803e7034);
      dVar6 = (double)FUN_80293e80(dVar7);
      local_44 = (float)((double)FLOAT_803e702c * dVar6);
      dVar6 = (double)FUN_80294204(dVar7);
      local_4c = (float)((double)FLOAT_803e7038 * dVar6);
      local_3c = FLOAT_803e7008;
      local_50 = local_44;
      local_48 = FLOAT_803e7008;
      local_40 = local_4c;
      FUN_8022d4ac(iVar1,&local_50);
      FUN_80014aa0((double)FLOAT_803e703c);
    }
    if ((*(int *)(*(int *)(param_1 + 0x54) + 0x50) == iVar1) &&
       (iVar2 = FUN_8022d738(iVar1), iVar2 != 0)) {
      FUN_80247794(param_1 + 0x24,param_1 + 0x24);
      local_38 = *(float *)(param_1 + 0xc) - *(float *)(iVar1 + 0xc);
      local_34 = *(float *)(param_1 + 0x10) - *(float *)(iVar1 + 0x10);
      local_30 = *(float *)(param_1 + 0x14) - *(float *)(iVar1 + 0x14);
      FUN_80247794(&local_38,&local_38);
      FUN_80247888(param_1 + 0x24,&local_38,param_1 + 0x24);
      *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * *(float *)(puVar4 + 8);
      *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * *(float *)(puVar4 + 8);
      *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * *(float *)(puVar4 + 8);
      puVar4[1] = 1;
    }
    *(float *)(puVar4 + 0x10) = FLOAT_803e7028;
    *(undefined *)(param_1 + 0x36) = 0;
    FUN_80099660((double)FLOAT_803e701c,param_1,*puVar4);
    if (*(int *)(puVar4 + 0x14) != 0) {
      FUN_8001f384();
      *(undefined4 *)(puVar4 + 0x14) = 0;
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

