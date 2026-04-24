// Function: FUN_80188814
// Entry: 80188814
// Size: 436 bytes

/* WARNING: Removing unreachable block (ram,0x801889a0) */

void FUN_80188814(short *param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f31;
  undefined auStack56 [16];
  undefined4 local_28;
  uint uStack36;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  uVar2 = (uint)*(byte *)(param_2 + 0x1b);
  if (uVar2 != 0) {
    local_28 = 0x43300000;
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e3b90) / FLOAT_803e3b88;
    if (*(float *)(param_1 + 4) == FLOAT_803e3b7c) {
      *(float *)(param_1 + 4) = FLOAT_803e3b78;
    }
    *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
    uStack36 = uVar2;
  }
  sVar1 = param_1[0x23];
  if (((sVar1 == 0x7a1) || (sVar1 == 0x7a2)) || (sVar1 == 0x7a3)) {
    iVar3 = *(int *)(param_1 + 0x5c);
    iVar4 = ***(int ***)(param_1 + 0x3e);
    FUN_80026e00(iVar4,0,iVar3);
    FUN_80026e00(iVar4,0,iVar3 + 0xc);
    for (iVar5 = 1; iVar5 < (int)(uint)*(ushort *)(iVar4 + 0xe4); iVar5 = iVar5 + 1) {
      FUN_80026e00(iVar4,iVar5,auStack56);
      FUN_80188798(auStack56,iVar3,iVar3 + 0xc);
    }
    FUN_80247778((double)*(float *)(param_1 + 4),iVar3,iVar3);
    FUN_80247778((double)*(float *)(param_1 + 4),iVar3 + 0xc,iVar3 + 0xc);
    dVar7 = (double)FUN_802477f0(iVar3 + 0xc);
    dVar8 = (double)FUN_802477f0(iVar3);
    if (dVar8 <= dVar7) {
      dVar7 = (double)FUN_802477f0(iVar3 + 0xc);
    }
    else {
      dVar7 = (double)FUN_802477f0(iVar3);
    }
    *(float *)(iVar3 + 0x18) = (float)dVar7;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return;
}

