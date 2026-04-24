// Function: FUN_80239eac
// Entry: 80239eac
// Size: 288 bytes

/* WARNING: Removing unreachable block (ram,0x80239f9c) */
/* WARNING: Removing unreachable block (ram,0x80239fa4) */

void FUN_80239eac(undefined4 param_1,int param_2)

{
  undefined4 *puVar1;
  undefined2 uVar2;
  short sVar3;
  int iVar4;
  undefined2 *puVar5;
  undefined4 uVar6;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  int local_48 [2];
  undefined4 local_40;
  uint uStack60;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  puVar1 = (undefined4 *)FUN_80036f50(2,local_48);
  for (iVar4 = 0; iVar4 < local_48[0]; iVar4 = iVar4 + 1) {
    puVar5 = (undefined2 *)*puVar1;
    if ((**(short **)(puVar5 + 0x26) == 0x80d) || (**(short **)(puVar5 + 0x26) == 0x859)) {
      dVar8 = (double)(*(float *)(param_2 + 0xc4) - *(float *)(puVar5 + 8));
      dVar7 = (double)(*(float *)(param_2 + 200) - *(float *)(puVar5 + 10));
      uVar2 = FUN_800217c0((double)(*(float *)(param_2 + 0xc0) - *(float *)(puVar5 + 6)),dVar7);
      *puVar5 = uVar2;
      sVar3 = FUN_800217c0(dVar8,dVar7);
      puVar5[1] = -sVar3;
      uStack60 = DAT_803dc4e8 ^ 0x80000000;
      local_40 = 0x43300000;
      FUN_8022e54c((double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e7498),puVar5);
    }
    puVar1 = puVar1 + 1;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return;
}

