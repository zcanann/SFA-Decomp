// Function: FUN_800248b8
// Entry: 800248b8
// Size: 1476 bytes

void FUN_800248b8(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4)

{
  short sVar1;
  undefined4 uVar2;
  int iVar3;
  int *piVar4;
  undefined *puVar5;
  uint uVar6;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  uint uVar14;
  uint uVar15;
  double extraout_f1;
  undefined8 uVar16;
  int local_98;
  undefined auStack148 [4];
  undefined4 local_90 [16];
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  short local_3c;
  undefined local_34 [52];
  
  uVar16 = FUN_802860cc();
  uVar2 = (undefined4)((ulonglong)uVar16 >> 0x20);
  piVar4 = (int *)uVar16;
  iVar13 = *piVar4;
  local_98 = piVar4[(*(ushort *)(piVar4 + 6) & 1) + 3];
  *(float *)(param_3 + 4) = (float)(extraout_f1 * (double)*(float *)(param_3 + 0x14));
  uVar14 = 0;
  if ((*(ushort *)(iVar13 + 2) & 8) == 0) {
    iVar11 = 0;
    iVar3 = param_3;
    iVar12 = param_3;
    do {
      if (iVar11 == 0) {
        sVar1 = *(short *)(param_3 + 0x5a);
      }
      else {
        sVar1 = *(short *)(param_3 + 0x5c);
      }
      if (sVar1 != 0) {
        if (*(short *)(param_3 + 0x58) == 0) {
          iVar10 = 0;
        }
        else {
          iVar10 = 4 << iVar11;
        }
        local_34[0] = *(undefined *)(param_3 + iVar11 + 0x60);
        local_90[4] = *(undefined4 *)(iVar12 + 0x14);
        local_90[0] = *(undefined4 *)(iVar12 + 4);
        local_90[12] = *(undefined4 *)(iVar12 + 0x34);
        local_90[13] = *(undefined4 *)(iVar12 + 0x3c);
        if ((*(ushort *)(iVar13 + 2) & 0x40) == 0) {
          local_50._0_2_ = *(undefined2 *)(iVar3 + 0x44);
          local_50._2_2_ = *(undefined2 *)(iVar3 + 0x48);
        }
        else {
          local_50._0_2_ = 0;
          local_50._2_2_ = 1;
          local_90[6] = *(undefined4 *)(param_3 + (uint)*(ushort *)(iVar3 + 0x44) * 4 + 0x1c);
          local_90[7] = *(undefined4 *)(param_3 + (uint)*(ushort *)(iVar3 + 0x48) * 4 + 0x24);
        }
        local_90[1] = local_90[0];
        local_90[5] = local_90[4];
        local_3c = sVar1;
        local_34[1] = local_34[0];
        FUN_80024524(iVar13,auStack148,2);
        FUN_80006c6c(&local_98,uVar2,auStack148,*(undefined4 *)(iVar13 + 0x3c),
                     *(undefined *)(iVar13 + 0xf3),&DAT_80340740,param_4,iVar10);
        if (iVar10 != 0) {
          uVar14 = uVar14 | 1 << iVar11;
        }
      }
      iVar12 = iVar12 + 4;
      iVar3 = iVar3 + 2;
      iVar11 = iVar11 + 1;
    } while (iVar11 < 2);
    if (((*(short *)(param_3 + 0x5a) == 0) && (*(short *)(param_3 + 0x5c) == 0)) || (uVar14 != 0)) {
      uVar6 = 1;
      if (*(short *)(param_3 + 0x58) != 0) {
        uVar6 = 2;
      }
      local_90[6] = *(undefined4 *)(param_3 + 0x1c);
      local_90[7] = *(undefined4 *)(param_3 + 0x20);
      local_90[8] = *(undefined4 *)(param_3 + 0x24);
      local_90[9] = *(undefined4 *)(param_3 + 0x28);
      iVar3 = 0;
      if (uVar6 != 0) {
        if (8 < uVar6) {
          puVar5 = auStack148;
          uVar15 = uVar6 - 1 >> 3;
          iVar12 = param_3;
          iVar11 = param_3;
          puVar7 = puVar5;
          puVar8 = puVar5;
          if (0 < (int)(uVar6 - 8)) {
            do {
              *(undefined2 *)(puVar8 + 0x44) = *(undefined2 *)(iVar12 + 0x44);
              puVar9 = (undefined *)(param_3 + iVar3 + 0x60);
              puVar5[0x60] = *puVar9;
              *(undefined4 *)(puVar7 + 0x14) = *(undefined4 *)(iVar11 + 0x14);
              *(undefined4 *)(puVar7 + 4) = *(undefined4 *)(iVar11 + 4);
              *(undefined4 *)(puVar7 + 0x34) = *(undefined4 *)(iVar11 + 0x34);
              *(undefined2 *)(puVar8 + 0x46) = *(undefined2 *)(iVar12 + 0x46);
              puVar5[0x61] = puVar9[1];
              *(undefined4 *)(puVar7 + 0x18) = *(undefined4 *)(iVar11 + 0x18);
              *(undefined4 *)(puVar7 + 8) = *(undefined4 *)(iVar11 + 8);
              *(undefined4 *)(puVar7 + 0x38) = *(undefined4 *)(iVar11 + 0x38);
              *(undefined2 *)(puVar8 + 0x48) = *(undefined2 *)(iVar12 + 0x48);
              puVar5[0x62] = puVar9[2];
              *(undefined4 *)(puVar7 + 0x1c) = *(undefined4 *)(iVar11 + 0x1c);
              *(undefined4 *)(puVar7 + 0xc) = *(undefined4 *)(iVar11 + 0xc);
              *(undefined4 *)(puVar7 + 0x3c) = *(undefined4 *)(iVar11 + 0x3c);
              *(undefined2 *)(puVar8 + 0x4a) = *(undefined2 *)(iVar12 + 0x4a);
              puVar5[99] = puVar9[3];
              *(undefined4 *)(puVar7 + 0x20) = *(undefined4 *)(iVar11 + 0x20);
              *(undefined4 *)(puVar7 + 0x10) = *(undefined4 *)(iVar11 + 0x10);
              *(undefined4 *)(puVar7 + 0x40) = *(undefined4 *)(iVar11 + 0x40);
              *(undefined2 *)(puVar8 + 0x4c) = *(undefined2 *)(iVar12 + 0x4c);
              puVar5[100] = puVar9[4];
              *(undefined4 *)(puVar7 + 0x24) = *(undefined4 *)(iVar11 + 0x24);
              *(undefined4 *)(puVar7 + 0x14) = *(undefined4 *)(iVar11 + 0x14);
              *(undefined4 *)(puVar7 + 0x44) = *(undefined4 *)(iVar11 + 0x44);
              *(undefined2 *)(puVar8 + 0x4e) = *(undefined2 *)(iVar12 + 0x4e);
              puVar5[0x65] = puVar9[5];
              *(undefined4 *)(puVar7 + 0x28) = *(undefined4 *)(iVar11 + 0x28);
              *(undefined4 *)(puVar7 + 0x18) = *(undefined4 *)(iVar11 + 0x18);
              *(undefined4 *)(puVar7 + 0x48) = *(undefined4 *)(iVar11 + 0x48);
              *(undefined2 *)(puVar8 + 0x50) = *(undefined2 *)(iVar12 + 0x50);
              puVar5[0x66] = puVar9[6];
              *(undefined4 *)(puVar7 + 0x2c) = *(undefined4 *)(iVar11 + 0x2c);
              *(undefined4 *)(puVar7 + 0x1c) = *(undefined4 *)(iVar11 + 0x1c);
              *(undefined4 *)(puVar7 + 0x4c) = *(undefined4 *)(iVar11 + 0x4c);
              *(undefined2 *)(puVar8 + 0x52) = *(undefined2 *)(iVar12 + 0x52);
              puVar5[0x67] = puVar9[7];
              *(undefined4 *)(puVar7 + 0x30) = *(undefined4 *)(iVar11 + 0x30);
              *(undefined4 *)(puVar7 + 0x20) = *(undefined4 *)(iVar11 + 0x20);
              *(undefined4 *)(puVar7 + 0x50) = *(undefined4 *)(iVar11 + 0x50);
              iVar12 = iVar12 + 0x10;
              puVar8 = puVar8 + 0x10;
              puVar5 = puVar5 + 8;
              iVar11 = iVar11 + 0x20;
              puVar7 = puVar7 + 0x20;
              iVar3 = iVar3 + 8;
              uVar15 = uVar15 - 1;
            } while (uVar15 != 0);
          }
        }
        iVar11 = param_3 + iVar3 * 2;
        puVar7 = auStack148 + iVar3 * 2;
        puVar8 = auStack148 + iVar3;
        iVar10 = param_3 + iVar3 * 4;
        puVar5 = auStack148 + iVar3 * 4;
        iVar12 = uVar6 - iVar3;
        if (iVar3 < (int)uVar6) {
          do {
            *(undefined2 *)(puVar7 + 0x44) = *(undefined2 *)(iVar11 + 0x44);
            puVar8[0x60] = *(undefined *)(param_3 + iVar3 + 0x60);
            *(undefined4 *)(puVar5 + 0x14) = *(undefined4 *)(iVar10 + 0x14);
            *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(iVar10 + 4);
            *(undefined4 *)(puVar5 + 0x34) = *(undefined4 *)(iVar10 + 0x34);
            iVar11 = iVar11 + 2;
            puVar7 = puVar7 + 2;
            puVar8 = puVar8 + 1;
            iVar10 = iVar10 + 4;
            puVar5 = puVar5 + 4;
            iVar3 = iVar3 + 1;
            iVar12 = iVar12 + -1;
          } while (iVar12 != 0);
        }
      }
      local_3c = *(short *)(param_3 + 0x58);
      FUN_80024524(iVar13,auStack148);
      if ((*(byte *)(param_3 + 99) & 1) != 0) {
        uVar14 = uVar14 | 0x10;
      }
      if ((*(byte *)(param_3 + 99) & 4) != 0) {
        uVar14 = uVar14 | 0x20;
      }
      FUN_80006c6c(&local_98,uVar2,auStack148,*(undefined4 *)(iVar13 + 0x3c),
                   *(undefined *)(iVar13 + 0xf3),&DAT_80340740,param_4,uVar14);
    }
  }
  else {
    local_90[6] = *(undefined4 *)(param_3 + 0x1c);
    local_90[7] = *(undefined4 *)(param_3 + 0x20);
    local_90[8] = *(undefined4 *)(param_3 + 0x24);
    local_90[9] = *(undefined4 *)(param_3 + 0x28);
    local_50._0_2_ = *(undefined2 *)(param_3 + 0x44);
    local_34[0] = *(undefined *)(param_3 + 0x60);
    local_90[4] = *(undefined4 *)(param_3 + 0x14);
    local_90[0] = *(undefined4 *)(param_3 + 4);
    local_90[12] = *(undefined4 *)(param_3 + 0x34);
    uVar6 = (uint)(*(short *)(param_3 + 0x58) != 0);
    local_50._2_2_ = *(undefined2 *)(param_3 + uVar6 * 2 + 0x44);
    local_34[1] = *(undefined *)(param_3 + uVar6 + 0x60);
    iVar3 = param_3 + uVar6 * 4;
    local_90[5] = *(undefined4 *)(iVar3 + 0x14);
    local_90[1] = *(undefined4 *)(iVar3 + 4);
    local_90[13] = *(undefined4 *)(iVar3 + 0x34);
    local_3c = *(short *)(param_3 + 0x58);
    FUN_80024524(iVar13,auStack148,2);
    if ((*(byte *)(param_3 + 99) & 1) != 0) {
      uVar14 = 0x10;
    }
    if ((*(byte *)(param_3 + 99) & 4) != 0) {
      uVar14 = uVar14 | 0x20;
    }
    FUN_80006c6c(&local_98,uVar2,auStack148,*(undefined4 *)(iVar13 + 0x3c),
                 *(undefined *)(iVar13 + 0xf3),&DAT_80340740,param_4,uVar14 | 0x40);
  }
  FUN_80286118();
  return;
}

