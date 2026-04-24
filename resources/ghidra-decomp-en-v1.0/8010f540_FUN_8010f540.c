// Function: FUN_8010f540
// Entry: 8010f540
// Size: 480 bytes

/* WARNING: Removing unreachable block (ram,0x8010f6f8) */

void FUN_8010f540(int param_1,int param_2)

{
  short sVar1;
  int iVar2;
  short sVar3;
  short *psVar4;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f31;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (param_1 != 0) {
    iVar2 = (**(code **)(*DAT_803dca50 + 0xc))();
    psVar4 = *(short **)(iVar2 + 0xa4);
    sVar1 = *psVar4;
    if (param_2 == 0) {
      uStack52 = (int)sVar1 ^ 0x80000000;
      local_38 = 0x43300000;
      dVar6 = (double)FUN_80293e80((double)((FLOAT_803e1ac0 *
                                            (float)((double)CONCAT44(0x43300000,uStack52) -
                                                   DOUBLE_803e1ac8)) / FLOAT_803e1ac4));
      uStack44 = (int)*psVar4 ^ 0x80000000;
      local_30 = 0x43300000;
      dVar7 = (double)FUN_80294204((double)((FLOAT_803e1ac0 *
                                            (float)((double)CONCAT44(0x43300000,uStack44) -
                                                   DOUBLE_803e1ac8)) / FLOAT_803e1ac4));
    }
    else {
      uStack44 = (int)sVar1 ^ 0x80000000;
      local_30 = 0x43300000;
      dVar6 = (double)FUN_80293e80((double)((FLOAT_803e1ac0 *
                                            (float)((double)CONCAT44(0x43300000,uStack44) -
                                                   DOUBLE_803e1ac8)) / FLOAT_803e1ac4));
      dVar6 = -dVar6;
      uStack52 = (int)*psVar4 ^ 0x80000000;
      local_38 = 0x43300000;
      dVar7 = (double)FUN_80294204((double)((FLOAT_803e1ac0 *
                                            (float)((double)CONCAT44(0x43300000,uStack52) -
                                                   DOUBLE_803e1ac8)) / FLOAT_803e1ac4));
      dVar7 = -dVar7;
    }
    sVar3 = FUN_800217c0(dVar6,dVar7);
    *psVar4 = sVar3;
    FUN_80103708(iVar2,psVar4,&local_48,0);
    *psVar4 = sVar1;
    *(undefined4 *)(iVar2 + 0x18) = local_48;
    *(undefined4 *)(iVar2 + 0xb8) = local_48;
    *(undefined4 *)(iVar2 + 0x1c) = local_44;
    *(undefined4 *)(iVar2 + 0xbc) = local_44;
    *(undefined4 *)(iVar2 + 0x20) = local_40;
    *(undefined4 *)(iVar2 + 0xc0) = local_40;
    FUN_8000e034((double)*(float *)(iVar2 + 0x18),(double)*(float *)(iVar2 + 0x1c),
                 (double)*(float *)(iVar2 + 0x20),iVar2 + 0xc,iVar2 + 0x10,iVar2 + 0x14,
                 *(undefined4 *)(iVar2 + 0x30));
    *(byte *)(DAT_803dd598 + 8) = *(byte *)(DAT_803dd598 + 8) & 0x7f | 0x80;
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

