// Function: FUN_8006f950
// Entry: 8006f950
// Size: 688 bytes

/* WARNING: Removing unreachable block (ram,0x8006fbe0) */

void FUN_8006f950(undefined4 param_1,undefined4 param_2,undefined param_3,uint param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  uint uVar7;
  short *psVar8;
  int iVar9;
  float *pfVar10;
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f31;
  undefined8 uVar13;
  undefined auStack88 [4];
  undefined auStack84 [12];
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar13 = FUN_802860dc();
  psVar8 = (short *)((ulonglong)uVar13 >> 0x20);
  pfVar10 = (float *)uVar13;
  if (psVar8[0x22] == 1) {
    DAT_803dcff0 = *(byte *)((int)psVar8 + 0xad);
  }
  else if (psVar8[0x23] == 0x416) {
    DAT_803dcff0 = 3;
  }
  iVar9 = FUN_80065768((double)*(float *)(psVar8 + 6),(double)*(float *)(psVar8 + 8),
                       (double)*(float *)(psVar8 + 10),psVar8,auStack88,auStack84,0);
  if (iVar9 == 0) {
    if ((param_4 & 0xff) == 1) {
      iVar9 = (uint)DAT_803dcff8 * 0x10;
      *(float *)(&DAT_80391de0 + iVar9) = *pfVar10;
      *(float *)(&DAT_80391de4 + iVar9) = FLOAT_803dee3c + pfVar10[1];
      *(float *)(&DAT_80391de8 + iVar9) = pfVar10[2];
      *(short *)(&DAT_80391dec + iVar9) = *psVar8;
      (&DAT_80391dee)[iVar9] = 0xff;
      (&DAT_80391def)[iVar9] = param_3;
      uVar7 = DAT_803dcff8 + 1;
      DAT_803dcff8 = (byte)uVar7;
      if (0xff < (uVar7 & 0xff)) {
        DAT_803dcff8 = 0;
      }
    }
    FUN_80247794(auStack84,auStack84);
    local_3c = FLOAT_803dee38;
    local_38 = FLOAT_803dee20;
    local_34 = FLOAT_803dee20;
    dVar12 = (double)FUN_8024782c(auStack84,&local_3c);
    if ((double)FLOAT_803dee58 <= ABS(dVar12)) {
      local_3c = FLOAT_803dee20;
      local_34 = FLOAT_803dee38;
    }
    FUN_8024784c(auStack84,&local_3c,&local_48);
    FUN_8024784c(&local_48,auStack84,&local_3c);
    FUN_80247794(&local_3c,&local_3c);
    FUN_80247794(&local_48,&local_48);
    dVar12 = (double)(float)(&DAT_80391dc0)[DAT_803dcff0];
    FUN_80247778(dVar12,&local_3c,&local_3c);
    FUN_80247778(dVar12,&local_48,&local_48);
    fVar1 = *pfVar10;
    fVar2 = pfVar10[1];
    fVar3 = pfVar10[2];
    fVar4 = fVar1 - local_3c;
    uVar7 = (uint)DAT_803dcff9;
    iVar9 = uVar7 * 0x38;
    (&DAT_80392de0)[uVar7 * 0xe] = fVar4 - local_48;
    fVar5 = fVar2 - local_38;
    (&DAT_80392de4)[uVar7 * 0xe] = fVar5 - local_44;
    fVar6 = fVar3 - local_34;
    (&DAT_80392de8)[uVar7 * 0xe] = fVar6 - local_40;
    fVar1 = fVar1 + local_3c;
    (&DAT_80392dec)[uVar7 * 0xe] = fVar1 - local_48;
    fVar2 = fVar2 + local_38;
    (&DAT_80392df0)[uVar7 * 0xe] = fVar2 - local_44;
    fVar3 = fVar3 + local_34;
    (&DAT_80392df4)[uVar7 * 0xe] = fVar3 - local_40;
    (&DAT_80392df8)[uVar7 * 0xe] = local_48 + fVar1;
    (&DAT_80392dfc)[uVar7 * 0xe] = local_44 + fVar2;
    (&DAT_80392e00)[uVar7 * 0xe] = local_40 + fVar3;
    (&DAT_80392e04)[uVar7 * 0xe] = local_48 + fVar4;
    (&DAT_80392e08)[uVar7 * 0xe] = local_44 + fVar5;
    (&DAT_80392e0c)[uVar7 * 0xe] = local_40 + fVar6;
    (&DAT_80392e10)[uVar7 * 0x1c] = -*psVar8;
    (&DAT_80392e12)[iVar9] = (char)param_4;
    (&DAT_80392e13)[iVar9] = 0xff;
    (&DAT_80392e14)[iVar9] = param_3;
    DAT_803dcff9 = (byte)(uVar7 + 1);
    if (0xff < (uVar7 + 1 & 0xff)) {
      DAT_803dcff9 = 0;
    }
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_80286128();
  return;
}

