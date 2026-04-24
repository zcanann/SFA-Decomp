// Function: FUN_801a2e80
// Entry: 801a2e80
// Size: 576 bytes

void FUN_801a2e80(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  undefined uVar1;
  double dVar2;
  float fVar3;
  uint uVar4;
  undefined uVar5;
  int iVar6;
  undefined4 uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  undefined8 uVar16;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  
  uVar16 = FUN_802860c0();
  iVar6 = (int)((ulonglong)uVar16 >> 0x20);
  iVar9 = (int)uVar16;
  iVar8 = (uint)*(byte *)(param_4 + 0x6e5) * 0x10;
  iVar12 = *(int *)(&DAT_80322da4 + iVar8);
  *(undefined4 *)(param_4 + 0x6d0) = *(undefined4 *)(&DAT_80322da8 + iVar8);
  uVar1 = (&DAT_80322dac)[(uint)*(byte *)(param_4 + 0x6e5) * 0x10];
  if (iVar12 != -1) {
    iVar14 = 0;
    iVar8 = param_4;
    iVar15 = param_4;
    for (iVar13 = 0; iVar13 < (int)(uint)*(byte *)(param_4 + 0x6d4); iVar13 = iVar13 + 1) {
      *(undefined *)(param_4 + iVar13 + 0x6d5) = 1;
      *(undefined *)(iVar15 + 0x6d) = uVar1;
      fVar3 = FLOAT_803e4368;
      if (param_3 == 0) {
        *(float *)(iVar15 + 4) = FLOAT_803e4368;
        *(float *)(iVar15 + 8) = fVar3;
        *(float *)(iVar15 + 0xc) = fVar3;
        iVar10 = **(int **)(*(int *)(iVar6 + 0x7c) + iVar14);
        local_5c = fVar3;
        local_58 = fVar3;
        local_54 = fVar3;
        for (iVar11 = 0; fVar3 = FLOAT_803e436c, dVar2 = DOUBLE_803e4360,
            uVar4 = (uint)*(ushort *)(iVar10 + 0xe4), iVar11 < (int)uVar4; iVar11 = iVar11 + 1) {
          FUN_80026e00(iVar10,iVar11,&local_68);
          local_5c = local_68 + local_5c;
          local_58 = local_64 + local_58;
          local_54 = local_60 + local_54;
        }
        local_50 = 0x43300000;
        *(float *)(iVar15 + 4) =
             local_5c *
             (FLOAT_803e436c / (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803e4360));
        uStack68 = (uint)*(ushort *)(iVar10 + 0xe4);
        local_48 = 0x43300000;
        *(float *)(iVar15 + 8) =
             local_58 * (fVar3 / (float)((double)CONCAT44(0x43300000,uStack68) - dVar2));
        uStack60 = (uint)*(ushort *)(iVar10 + 0xe4);
        local_40 = 0x43300000;
        *(float *)(iVar15 + 0xc) =
             local_54 * (fVar3 / (float)((double)CONCAT44(0x43300000,uStack60) - dVar2));
        uStack76 = uVar4;
      }
      *(undefined4 *)(iVar15 + 0x10) = *(undefined4 *)(iVar15 + 4);
      *(undefined4 *)(iVar15 + 0x14) = *(undefined4 *)(iVar15 + 8);
      *(undefined4 *)(iVar15 + 0x18) = *(undefined4 *)(iVar15 + 0xc);
      FUN_801a30c0(iVar6,iVar15,iVar9);
      *(undefined *)(iVar15 + 0x6b) = 0xff;
      iVar10 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x3e));
      if (iVar10 == 0) {
        uVar5 = 0;
      }
      else {
        uVar5 = 2;
      }
      *(undefined *)(iVar15 + 0x6a) = uVar5;
      uVar7 = FUN_801a2bdc(iVar6,iVar12,iVar15,iVar13);
      *(undefined4 *)(iVar8 + 0x690) = uVar7;
      iVar15 = iVar15 + 0x70;
      iVar14 = iVar14 + 4;
      iVar8 = iVar8 + 4;
    }
    iVar8 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x3e));
    *(bool *)(param_4 + 0x6e4) = iVar8 != 0;
  }
  FUN_8028610c();
  return;
}

