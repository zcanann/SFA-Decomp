// Function: FUN_8002497c
// Entry: 8002497c
// Size: 1476 bytes

void FUN_8002497c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  short sVar1;
  float *pfVar2;
  int iVar3;
  int *piVar4;
  undefined *puVar5;
  undefined *puVar6;
  int iVar7;
  undefined *puVar8;
  undefined4 *puVar9;
  undefined *puVar10;
  uint uVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  uint uVar15;
  uint uVar16;
  double extraout_f1;
  undefined8 uVar17;
  int local_98;
  undefined auStack_94 [4];
  undefined4 local_90 [16];
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  short local_3c;
  undefined local_34 [52];
  
  uVar17 = FUN_80286830();
  pfVar2 = (float *)((ulonglong)uVar17 >> 0x20);
  piVar4 = (int *)uVar17;
  iVar14 = *piVar4;
  local_98 = piVar4[(*(ushort *)(piVar4 + 6) & 1) + 3];
  *(float *)(param_3 + 4) = (float)(extraout_f1 * (double)*(float *)(param_3 + 0x14));
  uVar15 = 0;
  if ((*(ushort *)(iVar14 + 2) & 8) == 0) {
    iVar12 = 0;
    iVar3 = param_3;
    iVar13 = param_3;
    do {
      if (iVar12 == 0) {
        sVar1 = *(short *)(param_3 + 0x5a);
      }
      else {
        sVar1 = *(short *)(param_3 + 0x5c);
      }
      if (sVar1 != 0) {
        if (*(short *)(param_3 + 0x58) == 0) {
          uVar11 = 0;
        }
        else {
          uVar11 = 4 << iVar12;
        }
        local_34[0] = *(undefined *)(param_3 + iVar12 + 0x60);
        local_90[4] = *(undefined4 *)(iVar13 + 0x14);
        local_90[0] = *(undefined4 *)(iVar13 + 4);
        local_90[0xc] = *(undefined4 *)(iVar13 + 0x34);
        local_90[0xd] = *(undefined4 *)(iVar13 + 0x3c);
        if ((*(ushort *)(iVar14 + 2) & 0x40) == 0) {
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
        FUN_800245e8(iVar14,(int)auStack_94,2);
        FUN_80006c6c(&local_98,pfVar2,(int)auStack_94,*(undefined4 *)(iVar14 + 0x3c),
                     (uint)*(byte *)(iVar14 + 0xf3),-0x7fcbec60,param_4,uVar11);
        if (uVar11 != 0) {
          uVar15 = uVar15 | 1 << iVar12;
        }
      }
      iVar13 = iVar13 + 4;
      iVar3 = iVar3 + 2;
      iVar12 = iVar12 + 1;
    } while (iVar12 < 2);
    if (((*(short *)(param_3 + 0x5a) == 0) && (*(short *)(param_3 + 0x5c) == 0)) || (uVar15 != 0)) {
      uVar11 = 1;
      if (*(short *)(param_3 + 0x58) != 0) {
        uVar11 = 2;
      }
      local_90[6] = *(undefined4 *)(param_3 + 0x1c);
      local_90[7] = *(undefined4 *)(param_3 + 0x20);
      local_90[8] = *(undefined4 *)(param_3 + 0x24);
      local_90[9] = *(undefined4 *)(param_3 + 0x28);
      iVar3 = 0;
      if (uVar11 != 0) {
        if (8 < uVar11) {
          puVar5 = auStack_94;
          uVar16 = uVar11 - 1 >> 3;
          iVar13 = param_3;
          iVar12 = param_3;
          puVar6 = puVar5;
          puVar8 = puVar5;
          if (0 < (int)(uVar11 - 8)) {
            do {
              *(undefined2 *)(puVar8 + 0x44) = *(undefined2 *)(iVar13 + 0x44);
              puVar10 = (undefined *)(param_3 + iVar3 + 0x60);
              puVar5[0x60] = *puVar10;
              *(undefined4 *)(puVar6 + 0x14) = *(undefined4 *)(iVar12 + 0x14);
              *(undefined4 *)(puVar6 + 4) = *(undefined4 *)(iVar12 + 4);
              *(undefined4 *)(puVar6 + 0x34) = *(undefined4 *)(iVar12 + 0x34);
              *(undefined2 *)(puVar8 + 0x46) = *(undefined2 *)(iVar13 + 0x46);
              puVar5[0x61] = puVar10[1];
              *(undefined4 *)(puVar6 + 0x18) = *(undefined4 *)(iVar12 + 0x18);
              *(undefined4 *)(puVar6 + 8) = *(undefined4 *)(iVar12 + 8);
              *(undefined4 *)(puVar6 + 0x38) = *(undefined4 *)(iVar12 + 0x38);
              *(undefined2 *)(puVar8 + 0x48) = *(undefined2 *)(iVar13 + 0x48);
              puVar5[0x62] = puVar10[2];
              *(undefined4 *)(puVar6 + 0x1c) = *(undefined4 *)(iVar12 + 0x1c);
              *(undefined4 *)(puVar6 + 0xc) = *(undefined4 *)(iVar12 + 0xc);
              *(undefined4 *)(puVar6 + 0x3c) = *(undefined4 *)(iVar12 + 0x3c);
              *(undefined2 *)(puVar8 + 0x4a) = *(undefined2 *)(iVar13 + 0x4a);
              puVar5[99] = puVar10[3];
              *(undefined4 *)(puVar6 + 0x20) = *(undefined4 *)(iVar12 + 0x20);
              *(undefined4 *)(puVar6 + 0x10) = *(undefined4 *)(iVar12 + 0x10);
              *(undefined4 *)(puVar6 + 0x40) = *(undefined4 *)(iVar12 + 0x40);
              *(undefined2 *)(puVar8 + 0x4c) = *(undefined2 *)(iVar13 + 0x4c);
              puVar5[100] = puVar10[4];
              *(undefined4 *)(puVar6 + 0x24) = *(undefined4 *)(iVar12 + 0x24);
              *(undefined4 *)(puVar6 + 0x14) = *(undefined4 *)(iVar12 + 0x14);
              *(undefined4 *)(puVar6 + 0x44) = *(undefined4 *)(iVar12 + 0x44);
              *(undefined2 *)(puVar8 + 0x4e) = *(undefined2 *)(iVar13 + 0x4e);
              puVar5[0x65] = puVar10[5];
              *(undefined4 *)(puVar6 + 0x28) = *(undefined4 *)(iVar12 + 0x28);
              *(undefined4 *)(puVar6 + 0x18) = *(undefined4 *)(iVar12 + 0x18);
              *(undefined4 *)(puVar6 + 0x48) = *(undefined4 *)(iVar12 + 0x48);
              *(undefined2 *)(puVar8 + 0x50) = *(undefined2 *)(iVar13 + 0x50);
              puVar5[0x66] = puVar10[6];
              *(undefined4 *)(puVar6 + 0x2c) = *(undefined4 *)(iVar12 + 0x2c);
              *(undefined4 *)(puVar6 + 0x1c) = *(undefined4 *)(iVar12 + 0x1c);
              *(undefined4 *)(puVar6 + 0x4c) = *(undefined4 *)(iVar12 + 0x4c);
              *(undefined2 *)(puVar8 + 0x52) = *(undefined2 *)(iVar13 + 0x52);
              puVar5[0x67] = puVar10[7];
              *(undefined4 *)(puVar6 + 0x30) = *(undefined4 *)(iVar12 + 0x30);
              *(undefined4 *)(puVar6 + 0x20) = *(undefined4 *)(iVar12 + 0x20);
              *(undefined4 *)(puVar6 + 0x50) = *(undefined4 *)(iVar12 + 0x50);
              iVar13 = iVar13 + 0x10;
              puVar8 = puVar8 + 0x10;
              puVar5 = puVar5 + 8;
              iVar12 = iVar12 + 0x20;
              puVar6 = puVar6 + 0x20;
              iVar3 = iVar3 + 8;
              uVar16 = uVar16 - 1;
            } while (uVar16 != 0);
          }
        }
        iVar12 = param_3 + iVar3 * 2;
        puVar6 = auStack_94 + iVar3 * 2;
        puVar8 = auStack_94 + iVar3;
        iVar7 = param_3 + iVar3 * 4;
        puVar9 = local_90 + iVar3 + -1;
        iVar13 = uVar11 - iVar3;
        if (iVar3 < (int)uVar11) {
          do {
            *(undefined2 *)(puVar6 + 0x44) = *(undefined2 *)(iVar12 + 0x44);
            puVar8[0x60] = *(undefined *)(param_3 + iVar3 + 0x60);
            puVar9[5] = *(undefined4 *)(iVar7 + 0x14);
            puVar9[1] = *(undefined4 *)(iVar7 + 4);
            puVar9[0xd] = *(undefined4 *)(iVar7 + 0x34);
            iVar12 = iVar12 + 2;
            puVar6 = puVar6 + 2;
            puVar8 = puVar8 + 1;
            iVar7 = iVar7 + 4;
            puVar9 = puVar9 + 1;
            iVar3 = iVar3 + 1;
            iVar13 = iVar13 + -1;
          } while (iVar13 != 0);
        }
      }
      local_3c = *(short *)(param_3 + 0x58);
      FUN_800245e8(iVar14,(int)auStack_94,uVar11);
      if ((*(byte *)(param_3 + 99) & 1) != 0) {
        uVar15 = uVar15 | 0x10;
      }
      if ((*(byte *)(param_3 + 99) & 4) != 0) {
        uVar15 = uVar15 | 0x20;
      }
      FUN_80006c6c(&local_98,pfVar2,(int)auStack_94,*(undefined4 *)(iVar14 + 0x3c),
                   (uint)*(byte *)(iVar14 + 0xf3),-0x7fcbec60,param_4,uVar15);
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
    local_90[0xc] = *(undefined4 *)(param_3 + 0x34);
    uVar11 = (uint)(*(short *)(param_3 + 0x58) != 0);
    local_50._2_2_ = *(undefined2 *)(param_3 + uVar11 * 2 + 0x44);
    local_34[1] = *(undefined *)(param_3 + uVar11 + 0x60);
    iVar3 = param_3 + uVar11 * 4;
    local_90[5] = *(undefined4 *)(iVar3 + 0x14);
    local_90[1] = *(undefined4 *)(iVar3 + 4);
    local_90[0xd] = *(undefined4 *)(iVar3 + 0x34);
    local_3c = *(short *)(param_3 + 0x58);
    FUN_800245e8(iVar14,(int)auStack_94,2);
    if ((*(byte *)(param_3 + 99) & 1) != 0) {
      uVar15 = 0x10;
    }
    if ((*(byte *)(param_3 + 99) & 4) != 0) {
      uVar15 = uVar15 | 0x20;
    }
    FUN_80006c6c(&local_98,pfVar2,(int)auStack_94,*(undefined4 *)(iVar14 + 0x3c),
                 (uint)*(byte *)(iVar14 + 0xf3),-0x7fcbec60,param_4,uVar15 | 0x40);
  }
  FUN_8028687c();
  return;
}

