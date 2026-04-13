// Function: FUN_8010f9e8
// Entry: 8010f9e8
// Size: 696 bytes

void FUN_8010f9e8(ushort *param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  short *psVar4;
  double dVar5;
  float local_48;
  float local_44;
  undefined auStack_40 [4];
  float local_3c [2];
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  psVar4 = *(short **)(param_1 + 0x52);
  if (psVar4 != (short *)0x0) {
    if (*(char *)(DAT_803de210 + 8) < '\0') {
      iVar2 = (**(code **)(*DAT_803dd6d0 + 0x18))();
      (**(code **)(*DAT_803dd6d0 + 0x38))
                ((double)FLOAT_803e275c,param_1,local_3c,auStack_40,&local_44,&local_48,0);
      uVar1 = FUN_80021884();
      iVar3 = (0x8000 - (uVar1 & 0xffff)) - (uint)*param_1;
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      *param_1 = *param_1 + (short)iVar3;
      (**(code **)(**(int **)(iVar2 + 4) + 0x18))
                ((double)*(float *)(psVar4 + 0xe),(double)local_48,param_1);
    }
    else {
      uStack_34 = (int)*psVar4 ^ 0x80000000;
      local_3c[1] = 176.0;
      dVar5 = (double)FUN_802945e0();
      *(float *)(param_1 + 0xc) =
           (float)((double)FLOAT_803e2750 * dVar5 + (double)*(float *)(psVar4 + 0xc));
      uStack_2c = (int)*psVar4 ^ 0x80000000;
      local_30 = 0x43300000;
      dVar5 = (double)FUN_80294964();
      *(float *)(param_1 + 0x10) =
           (float)((double)FLOAT_803e2750 * dVar5 + (double)*(float *)(psVar4 + 0x10));
      *(float *)(param_1 + 0xe) = FLOAT_803e2754 + *(float *)(psVar4 + 0xe);
      local_3c[0] = *(float *)(param_1 + 6) - *(float *)(psVar4 + 0xc);
      local_44 = *(float *)(param_1 + 10) - *(float *)(psVar4 + 0x10);
      uVar1 = FUN_80021884();
      uStack_24 = (0x8000 - (uVar1 & 0xffff)) - (uint)*param_1;
      if (0x8000 < (int)uStack_24) {
        uStack_24 = uStack_24 - 0xffff;
      }
      if ((int)uStack_24 < -0x8000) {
        uStack_24 = uStack_24 + 0xffff;
      }
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      dVar5 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e2748)
                           ,(double)FLOAT_803e2758,(double)FLOAT_803dc074);
      uStack_1c = (int)(short)*param_1 ^ 0x80000000;
      local_20 = 0x43300000;
      iVar2 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e2748) +
                   dVar5);
      local_18 = (longlong)iVar2;
      *param_1 = (ushort)iVar2;
      iVar2 = FUN_80021884();
      *param_1 = 0x8000 - (short)iVar2;
      param_1[1] = 0x800;
    }
    FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  return;
}

