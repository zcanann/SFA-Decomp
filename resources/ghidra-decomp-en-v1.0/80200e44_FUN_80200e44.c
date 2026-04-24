// Function: FUN_80200e44
// Entry: 80200e44
// Size: 1300 bytes

/* WARNING: Removing unreachable block (ram,0x80201330) */
/* WARNING: Removing unreachable block (ram,0x80201338) */

void FUN_80200e44(void)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  short sVar7;
  undefined4 *puVar5;
  undefined2 *puVar6;
  int iVar8;
  bool bVar9;
  undefined4 uVar10;
  int iVar11;
  undefined4 uVar12;
  int iVar13;
  int iVar14;
  undefined4 uVar15;
  undefined8 extraout_f1;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar16;
  undefined8 uVar17;
  float local_d8;
  int local_d4;
  int local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_50;
  uint uStack76;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar17 = FUN_802860cc();
  iVar2 = (int)((ulonglong)uVar17 >> 0x20);
  iVar8 = (int)uVar17;
  iVar13 = *(int *)(iVar2 + 0xb8);
  iVar14 = *(int *)(iVar13 + 0x40c);
  uVar12 = *(undefined4 *)(iVar14 + 0x30);
  *(byte *)(iVar14 + 0x14) = *(byte *)(iVar14 + 0x14) | 2;
  *(byte *)(iVar14 + 0x15) = *(byte *)(iVar14 + 0x15) & 0xfb;
  uVar17 = extraout_f1;
  iVar1 = FUN_80036c0c(*(undefined4 *)(iVar8 + 0x2d0),uVar12);
  if ((iVar1 == 0) && (FUN_80036f50(uVar12,&local_d0), local_d0 == 0)) {
    local_58 = FUN_8002b9ec();
    uVar12 = *(undefined4 *)(iVar14 + 0x24);
    local_60 = 0xf;
    local_5c = 1;
    iVar2 = FUN_800138c4(uVar12);
    if (iVar2 == 0) {
      FUN_80013958(uVar12,&local_60);
    }
    *(undefined *)(iVar14 + 0x34) = 1;
  }
  else {
    iVar1 = *(int *)(iVar8 + 0x2d0);
    bVar9 = false;
    piVar3 = (int *)FUN_80036f50(3,&local_d4);
    for (iVar11 = 0; iVar11 < local_d4; iVar11 = iVar11 + 1) {
      iVar4 = *piVar3;
      if ((*(short *)(iVar4 + 0x46) == 0x539) &&
         (iVar4 = (**(code **)(**(int **)(iVar4 + 0x68) + 0x24))(iVar4,0x83,0), iVar4 == iVar1)) {
        bVar9 = true;
      }
      piVar3 = piVar3 + 1;
    }
    if ((bVar9) || (iVar1 = FUN_80036e58(3,*(undefined4 *)(iVar8 + 0x2d0),0), iVar2 != iVar1)) {
      iVar1 = *(int *)(iVar13 + 0x40c);
      *(undefined *)(iVar8 + 0x34d) = 0x1f;
      if (*(char *)(iVar8 + 0x27a) != '\0') {
        FUN_80030334((double)FLOAT_803e62a8,iVar2,0xf,0);
        *(undefined *)(iVar8 + 0x346) = 0;
      }
      if ((*(int *)(iVar1 + 0x3c) == 0) ||
         (iVar14 = FUN_80036c0c(*(undefined4 *)(iVar8 + 0x2d0),uVar12), iVar14 == 0)) {
        uStack76 = (uint)*(byte *)(iVar13 + 0x406);
        local_50 = 0x43300000;
        dVar16 = (double)((float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e62e0) /
                         FLOAT_803e62c4);
        FUN_80202c78((double)FLOAT_803e62b4,dVar16,(double)FLOAT_803e62cc,uVar17,iVar2,
                     *(undefined4 *)(iVar8 + 0x2d0));
        if ((*(byte *)(iVar1 + 0x44) >> 5 & 1) != 0) {
          FUN_80202a2c(dVar16,iVar2,&DAT_8032971c,&DAT_8032972c,4);
        }
        uVar12 = FUN_8002b9ec();
        sVar7 = FUN_800385e8(iVar2,uVar12,&local_d8);
        bVar9 = false;
        iVar13 = (int)sVar7;
        if (iVar13 < 0) {
          iVar13 = -iVar13;
        }
        if ((iVar13 < 0x1c71) && (local_d8 < FLOAT_803e62d0)) {
          bVar9 = true;
        }
        if (bVar9) {
          puVar5 = (undefined4 *)FUN_800394a0();
          iVar13 = 1;
          do {
            puVar5 = puVar5 + 1;
            puVar6 = (undefined2 *)FUN_800395d8(iVar2,*puVar5);
            if (puVar6 != (undefined2 *)0x0) {
              puVar6[2] = 0;
              *puVar6 = 0;
            }
            iVar13 = iVar13 + 1;
          } while (iVar13 < 9);
          uVar12 = FUN_8002b9ec();
          *(undefined4 *)(iVar8 + 0x2d0) = uVar12;
          local_b8 = *(undefined4 *)(iVar1 + 0x30);
          local_bc = *(undefined4 *)(iVar1 + 0x2c);
          uVar12 = *(undefined4 *)(iVar1 + 0x24);
          local_c0 = *(undefined4 *)(iVar1 + 0x28);
          iVar2 = FUN_800138c4(uVar12);
          if (iVar2 == 0) {
            FUN_80013958(uVar12,&local_c0);
          }
          uVar12 = *(undefined4 *)(iVar1 + 0x24);
          local_cc = 2;
          local_c8 = 0;
          local_c4 = 0;
          iVar2 = FUN_800138c4(uVar12);
          if (iVar2 == 0) {
            FUN_80013958(uVar12,&local_cc);
          }
          *(undefined *)(iVar1 + 0x34) = 1;
        }
      }
      else {
        local_94 = *(undefined4 *)(iVar1 + 0x30);
        local_98 = *(undefined4 *)(iVar1 + 0x2c);
        uVar12 = *(undefined4 *)(iVar1 + 0x24);
        local_9c = *(undefined4 *)(iVar1 + 0x28);
        iVar2 = FUN_800138c4(uVar12);
        if (iVar2 == 0) {
          FUN_80013958(uVar12,&local_9c);
        }
        uVar12 = *(undefined4 *)(iVar1 + 0x24);
        local_a8 = 0xc;
        local_a4 = 0;
        local_a0 = 3;
        iVar2 = FUN_800138c4(uVar12);
        if (iVar2 == 0) {
          FUN_80013958(uVar12,&local_a8);
        }
        *(undefined *)(iVar1 + 0x34) = 1;
        local_ac = *(undefined4 *)(iVar1 + 0x3c);
        uVar12 = *(undefined4 *)(iVar1 + 0x24);
        local_b4 = 0xd;
        local_b0 = 1;
        iVar2 = FUN_800138c4(uVar12);
        if (iVar2 == 0) {
          FUN_80013958(uVar12,&local_b4);
        }
        *(undefined *)(iVar1 + 0x34) = 1;
      }
    }
    else {
      *(undefined4 *)(iVar14 + 0x3c) = *(undefined4 *)(iVar8 + 0x2d0);
      local_64 = *(undefined4 *)(iVar14 + 0x30);
      local_68 = *(undefined4 *)(iVar14 + 0x2c);
      uVar10 = *(undefined4 *)(iVar14 + 0x24);
      local_6c = *(undefined4 *)(iVar14 + 0x28);
      iVar2 = FUN_800138c4(uVar10);
      if (iVar2 == 0) {
        FUN_80013958(uVar10,&local_6c);
      }
      uVar10 = *(undefined4 *)(iVar14 + 0x24);
      local_78 = 0xc;
      local_74 = 0;
      local_70 = 3;
      iVar2 = FUN_800138c4(uVar10);
      if (iVar2 == 0) {
        FUN_80013958(uVar10,&local_78);
      }
      *(undefined *)(iVar14 + 0x34) = 1;
      uVar10 = *(undefined4 *)(iVar14 + 0x24);
      local_84 = 9;
      local_80 = 0;
      local_7c = uVar12;
      iVar2 = FUN_800138c4(uVar10);
      if (iVar2 == 0) {
        FUN_80013958(uVar10,&local_84);
      }
      *(undefined *)(iVar14 + 0x34) = 1;
      local_88 = *(undefined4 *)(iVar14 + 0x3c);
      uVar12 = *(undefined4 *)(iVar14 + 0x24);
      local_90 = 7;
      local_8c = 1;
      iVar2 = FUN_800138c4(uVar12);
      if (iVar2 == 0) {
        FUN_80013958(uVar12,&local_90);
      }
      *(undefined *)(iVar14 + 0x34) = 1;
    }
  }
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  FUN_80286118(0);
  return;
}

