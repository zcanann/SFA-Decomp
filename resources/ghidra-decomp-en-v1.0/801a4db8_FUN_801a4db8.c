// Function: FUN_801a4db8
// Entry: 801a4db8
// Size: 472 bytes

void FUN_801a4db8(undefined4 param_1,undefined4 param_2,int param_3,float *param_4)

{
  float fVar1;
  double dVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  
  uVar7 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar7 >> 0x20);
  iVar4 = (int)uVar7;
  *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar4 + 8);
  *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
  *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(iVar4 + 0x10);
  fVar1 = FLOAT_803e43f0;
  if (param_3 == 0) {
    *param_4 = FLOAT_803e43f0;
    param_4[1] = fVar1;
    param_4[2] = fVar1;
    local_40 = fVar1;
    local_3c = fVar1;
    local_38 = fVar1;
    iVar5 = **(int **)(*(int *)(iVar3 + 0x7c) + (uint)*(byte *)(iVar4 + 0x18) * 4);
    for (iVar6 = 0; dVar2 = DOUBLE_803e43f8, fVar1 = FLOAT_803e43f4,
        uStack44 = (uint)*(ushort *)(iVar5 + 0xe4), iVar6 < (int)uStack44; iVar6 = iVar6 + 1) {
      FUN_80026e00(iVar5,iVar6,&local_4c);
      local_40 = local_4c + local_40;
      local_3c = local_48 + local_3c;
      local_38 = local_44 + local_38;
    }
    local_30 = 0x43300000;
    *param_4 = local_40 *
               (FLOAT_803e43f4 / (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e43f8));
    uStack36 = (uint)*(ushort *)(iVar5 + 0xe4);
    local_28 = 0x43300000;
    param_4[1] = local_3c * (fVar1 / (float)((double)CONCAT44(0x43300000,uStack36) - dVar2));
    uStack28 = (uint)*(ushort *)(iVar5 + 0xe4);
    local_20 = 0x43300000;
    param_4[2] = local_38 * (fVar1 / (float)((double)CONCAT44(0x43300000,uStack28) - dVar2));
  }
  param_4[3] = *param_4;
  param_4[4] = param_4[1];
  param_4[5] = param_4[2];
  FUN_801a4f90(iVar3,param_4,iVar4);
  local_58 = *param_4;
  local_54 = param_4[1];
  local_50 = param_4[2];
  FUN_800218ac(iVar3,&local_58);
  fVar1 = *(float *)(iVar3 + 8);
  local_58 = local_58 * fVar1;
  local_54 = local_54 * fVar1;
  local_50 = local_50 * fVar1;
  *(undefined *)((int)param_4 + 0x67) = 0xff;
  *(undefined *)((int)param_4 + 0x66) = 0;
  FUN_80286128();
  return;
}

