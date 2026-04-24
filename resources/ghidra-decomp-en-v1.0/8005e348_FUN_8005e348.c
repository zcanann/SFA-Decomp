// Function: FUN_8005e348
// Entry: 8005e348
// Size: 532 bytes

/* WARNING: Removing unreachable block (ram,0x8005e538) */
/* WARNING: Removing unreachable block (ram,0x8005e528) */
/* WARNING: Removing unreachable block (ram,0x8005e530) */
/* WARNING: Removing unreachable block (ram,0x8005e540) */

void FUN_8005e348(undefined4 param_1,undefined4 param_2,int *param_3,undefined4 param_4)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  undefined4 uVar7;
  undefined8 in_f28;
  double dVar8;
  undefined8 in_f29;
  double dVar9;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  undefined8 uVar12;
  int local_b8;
  undefined auStack180 [4];
  float local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  float local_a0;
  undefined4 local_9c;
  undefined auStack152 [48];
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar12 = FUN_802860d8();
  uVar5 = param_3[4];
  uVar3 = *(undefined *)(*param_3 + ((int)uVar5 >> 3));
  iVar4 = *param_3 + ((int)uVar5 >> 3);
  uVar1 = *(undefined *)(iVar4 + 1);
  uVar2 = *(undefined *)(iVar4 + 2);
  param_3[4] = uVar5 + 8;
  puVar6 = (undefined4 *)
           (*(int *)((int)((ulonglong)uVar12 >> 0x20) + 0x68) +
           ((uint3)(CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar5 & 7)) & 0xff) * 0x1c);
  uVar5 = *(uint *)((int)uVar12 + 0x3c);
  if ((uVar5 & 0x4000) == 0) {
    if ((uVar5 & 0x8000) == 0) {
      if ((uVar5 & 0x10000) == 0) goto LAB_8005e528;
      iVar4 = 0x10;
    }
    else {
      iVar4 = 8;
    }
  }
  else {
    iVar4 = 4;
  }
  dVar8 = (double)FLOAT_803dec2c;
  dVar10 = (double)FLOAT_803dec24;
  dVar11 = (double)FLOAT_803debfc;
  dVar9 = DOUBLE_803debc0;
  for (uVar5 = 0; (int)uVar5 < iVar4; uVar5 = uVar5 + 1) {
    uStack100 = uVar5 + 1 ^ 0x80000000;
    local_68 = 0x43300000;
    FUN_802472e4((double)FLOAT_803debcc,
                 (double)(float)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack100) -
                                                        dVar9)),(double)FLOAT_803debcc,auStack152);
    FUN_80246eb4(param_4,auStack152,auStack152);
    FUN_8025d0a8(auStack152,0);
    local_b0 = DAT_802c1e40;
    local_ac = DAT_802c1e44;
    local_a8 = DAT_802c1e48;
    local_a4 = DAT_802c1e4c;
    local_a0 = (float)DAT_802c1e50;
    local_9c = DAT_802c1e54;
    FUN_8006c4e0(&local_b8,auStack180);
    FUN_8004c2e4(*(undefined4 *)(local_b8 + (uVar5 & 0xff) * 4),1);
    uStack92 = (uVar5 & 0xff) + 1 ^ 0x80000000;
    local_60 = 0x43300000;
    local_b0 = (float)((double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack92) - dVar9
                                                      ) * dVar10) * dVar11);
    local_a0 = local_b0;
    FUN_8025b284(1,&local_b0,DAT_803db644);
    FUN_8025ced8(*puVar6,*(undefined2 *)(puVar6 + 1));
  }
LAB_8005e528:
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  __psq_l0(auStack56,uVar7);
  __psq_l1(auStack56,uVar7);
  FUN_80286124();
  return;
}

