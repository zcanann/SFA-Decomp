// Function: FUN_8013b1e0
// Entry: 8013b1e0
// Size: 392 bytes

/* WARNING: Removing unreachable block (ram,0x8013b340) */
/* WARNING: Removing unreachable block (ram,0x8013b348) */

void FUN_8013b1e0(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  undefined8 uVar9;
  int local_58;
  int local_54;
  int local_50 [2];
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar9 = FUN_802860d8();
  uVar1 = (undefined4)((ulonglong)uVar9 >> 0x20);
  piVar2 = (int *)FUN_80036f50(0x40,local_50);
  dVar7 = (double)FLOAT_803e2484;
  dVar8 = DOUBLE_803e2400;
  for (iVar5 = 0; iVar5 < local_50[0]; iVar5 = iVar5 + 1) {
    iVar3 = *(int *)(*piVar2 + 0x4c);
    uStack68 = (uint)*(ushort *)(iVar3 + 0x18);
    local_48 = 0x43300000;
    uStack60 = (uint)*(ushort *)(iVar3 + 0x1a);
    local_40 = 0x43300000;
    FUN_8013afe0((double)(float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uStack68) -
                                                        dVar8)),
                 (double)(float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uStack60) -
                                                        dVar8)),uVar1,(int)uVar9,param_3,
                 *piVar2 + 0x18);
    piVar2 = piVar2 + 1;
  }
  iVar5 = FUN_8002e0fc(&local_54,&local_58);
  piVar2 = (int *)(iVar5 + local_54 * 4);
  for (; local_54 < local_58; local_54 = local_54 + 1) {
    iVar5 = *piVar2;
    uVar4 = (uint)*(ushort *)(*(int *)(iVar5 + 0x50) + 0x84);
    if (((uVar4 != 0) && (*(int *)(iVar5 + 0x54) != 0)) &&
       ((*(ushort *)(*(int *)(iVar5 + 0x54) + 0x60) & 1) != 0)) {
      local_40 = 0x43300000;
      uStack68 = (uint)*(ushort *)(*(int *)(iVar5 + 0x50) + 0x86);
      local_48 = 0x43300000;
      uStack60 = uVar4;
      FUN_8013afe0((double)(FLOAT_803e2484 *
                           (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803e2400)),
                   (double)(FLOAT_803e2484 *
                           (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e2400)),uVar1,
                   (int)uVar9,param_3,iVar5 + 0x18);
    }
    piVar2 = piVar2 + 1;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  FUN_80286124();
  return;
}

