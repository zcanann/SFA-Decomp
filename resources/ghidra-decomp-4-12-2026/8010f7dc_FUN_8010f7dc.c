// Function: FUN_8010f7dc
// Entry: 8010f7dc
// Size: 480 bytes

/* WARNING: Removing unreachable block (ram,0x8010f994) */
/* WARNING: Removing unreachable block (ram,0x8010f7ec) */

void FUN_8010f7dc(int param_1,int param_2)

{
  short sVar1;
  int iVar2;
  int iVar3;
  short *psVar4;
  float local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  
  if (param_1 != 0) {
    iVar2 = (**(code **)(*DAT_803dd6d0 + 0xc))();
    psVar4 = *(short **)(iVar2 + 0xa4);
    sVar1 = *psVar4;
    if (param_2 == 0) {
      uStack_34 = (int)sVar1 ^ 0x80000000;
      local_38 = 0x43300000;
      FUN_802945e0();
      uStack_2c = (int)*psVar4 ^ 0x80000000;
      local_30 = 0x43300000;
      FUN_80294964();
    }
    else {
      uStack_2c = (int)sVar1 ^ 0x80000000;
      local_30 = 0x43300000;
      FUN_802945e0();
      uStack_34 = (int)*psVar4 ^ 0x80000000;
      local_38 = 0x43300000;
      FUN_80294964();
    }
    iVar3 = FUN_80021884();
    *psVar4 = (short)iVar3;
    FUN_801039a4(iVar2,psVar4,&local_48,(short *)0x0);
    *psVar4 = sVar1;
    *(float *)(iVar2 + 0x18) = local_48;
    *(float *)(iVar2 + 0xb8) = local_48;
    *(undefined4 *)(iVar2 + 0x1c) = local_44;
    *(undefined4 *)(iVar2 + 0xbc) = local_44;
    *(undefined4 *)(iVar2 + 0x20) = local_40;
    *(undefined4 *)(iVar2 + 0xc0) = local_40;
    FUN_8000e054((double)*(float *)(iVar2 + 0x18),(double)*(float *)(iVar2 + 0x1c),
                 (double)*(float *)(iVar2 + 0x20),(float *)(iVar2 + 0xc),(float *)(iVar2 + 0x10),
                 (float *)(iVar2 + 0x14),*(int *)(iVar2 + 0x30));
    *(byte *)(DAT_803de210 + 8) = *(byte *)(DAT_803de210 + 8) & 0x7f | 0x80;
  }
  return;
}

