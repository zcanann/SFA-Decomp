// Function: FUN_80200a70
// Entry: 80200a70
// Size: 980 bytes

/* WARNING: Removing unreachable block (ram,0x80200e1c) */
/* WARNING: Removing unreachable block (ram,0x80200e14) */
/* WARNING: Removing unreachable block (ram,0x80200e24) */

void FUN_80200a70(void)

{
  short sVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  undefined4 uVar14;
  undefined8 extraout_f1;
  double dVar15;
  double dVar16;
  undefined8 in_f29;
  double dVar17;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined8 uVar18;
  int local_98;
  undefined4 local_94;
  undefined4 local_90;
  int local_8c;
  undefined4 local_88;
  undefined4 local_84;
  int local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_60;
  uint uStack92;
  longlong local_58;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar14 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar18 = FUN_802860d0();
  iVar4 = (int)((ulonglong)uVar18 >> 0x20);
  iVar7 = (int)uVar18;
  iVar12 = *(int *)(iVar4 + 0xb8);
  iVar11 = *(int *)(iVar12 + 0x40c);
  uVar9 = *(undefined4 *)(iVar11 + 0x30);
  *(byte *)(iVar11 + 0x15) = *(byte *)(iVar11 + 0x15) & 0xfb;
  *(byte *)(iVar11 + 0x14) = *(byte *)(iVar11 + 0x14) | 2;
  uVar18 = extraout_f1;
  FUN_80137948(s__HAS_BALL____x___x_803297e8,*(undefined4 *)(iVar11 + 0x3c),
               *(undefined4 *)(iVar11 + 0x18));
  if (*(int *)(iVar11 + 0x3c) == 0) {
    local_68 = FUN_8002b9ec();
    uVar9 = *(undefined4 *)(iVar11 + 0x24);
    local_70 = 0xf;
    local_6c = 1;
    iVar4 = FUN_800138c4(uVar9);
    if (iVar4 == 0) {
      FUN_80013958(uVar9,&local_70);
    }
    *(undefined *)(iVar11 + 0x34) = 1;
  }
  else {
    if (*(char *)(iVar7 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e62a8,iVar4,0x11,0);
      *(undefined *)(iVar7 + 0x346) = 0;
    }
    *(float *)(iVar7 + 0x2a0) = FLOAT_803e6300;
    uStack92 = (uint)*(byte *)(iVar12 + 0x406);
    local_60 = 0x43300000;
    dVar17 = (double)((float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e62e0) /
                     FLOAT_803e62b8);
    if ((*(int *)(iVar11 + 0x18) == 0) && (sVar1 = *(short *)(iVar11 + 0x1c), sVar1 != -1)) {
      local_74 = *(undefined4 *)(iVar11 + 0x30);
      local_78 = *(undefined4 *)(iVar11 + 0x2c);
      uVar8 = *(undefined4 *)(iVar11 + 0x24);
      local_7c = *(undefined4 *)(iVar11 + 0x28);
      iVar5 = FUN_800138c4(uVar8);
      if (iVar5 == 0) {
        FUN_80013958(uVar8,&local_7c);
      }
      uVar8 = *(undefined4 *)(iVar11 + 0x24);
      local_88 = 9;
      local_84 = 0;
      local_80 = (int)sVar1;
      iVar5 = FUN_800138c4(uVar8);
      if (iVar5 == 0) {
        FUN_80013958(uVar8,&local_88);
      }
      *(undefined *)(iVar11 + 0x34) = 1;
      *(undefined2 *)(iVar11 + 0x1c) = 0xffff;
    }
    if ((*(byte *)(iVar11 + 0x44) >> 5 & 1) != 0) {
      FUN_80202a2c(dVar17,iVar4,&DAT_803296fc,&DAT_8032970c,4);
    }
    iVar5 = FUN_8002b9ec();
    dVar15 = (double)FUN_80021690(iVar4 + 0x18,iVar5 + 0x18);
    uStack92 = (uint)*(byte *)(iVar12 + 0x406);
    local_60 = 0x43300000;
    fVar2 = (float)(dVar15 - (double)FLOAT_803e6304) /
            (FLOAT_803e6308 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e62e0));
    fVar3 = FLOAT_803e62a8;
    if ((FLOAT_803e62a8 <= fVar2) && (fVar3 = fVar2, FLOAT_803e62b0 < fVar2)) {
      fVar3 = FLOAT_803e62b0;
    }
    iVar12 = (int)fVar3;
    local_58 = (longlong)iVar12;
    FUN_80137948(s__THROW_CHANCE__i_803297fc,iVar12);
    iVar5 = FUN_8002b9ec();
    iVar13 = 0;
    dVar15 = (double)FLOAT_803e62a8;
    piVar6 = (int *)FUN_80036f50(uVar9,&local_98);
    for (iVar10 = 0; iVar10 < local_98; iVar10 = iVar10 + 1) {
      if ((*piVar6 != iVar5) &&
         (dVar16 = (double)FUN_800216d0(iVar5 + 0x18,*piVar6 + 0x18), dVar15 < dVar16)) {
        iVar13 = *piVar6;
        dVar15 = dVar16;
      }
      piVar6 = piVar6 + 1;
    }
    if (((iVar13 != 0) && (FUN_802931a0(dVar15), iVar13 != iVar4)) &&
       (*(short *)(iVar13 + 0x46) == 0x539)) {
      *(int *)(iVar7 + 0x2d0) = iVar13;
      iVar7 = FUN_800221a0(0,iVar12);
      if (iVar7 == 0) {
        iVar4 = (**(code **)(**(int **)(iVar13 + 0x68) + 0x24))
                          (iVar13,0x82,*(undefined4 *)(iVar11 + 0x18));
        if (iVar4 != 0) {
          *(undefined4 *)(iVar11 + 0x3c) = 0;
          uVar9 = *(undefined4 *)(iVar11 + 0x24);
          local_94 = 10;
          local_90 = 1;
          local_8c = iVar13;
          iVar4 = FUN_800138c4(uVar9);
          if (iVar4 == 0) {
            FUN_80013958(uVar9,&local_94);
          }
          *(undefined *)(iVar11 + 0x34) = 1;
        }
      }
      else {
        FUN_80202c78((double)FLOAT_803e630c,dVar17,(double)FLOAT_803e62cc,uVar18,iVar4,iVar13);
      }
    }
  }
  __psq_l0(auStack8,uVar14);
  __psq_l1(auStack8,uVar14);
  __psq_l0(auStack24,uVar14);
  __psq_l1(auStack24,uVar14);
  __psq_l0(auStack40,uVar14);
  __psq_l1(auStack40,uVar14);
  FUN_8028611c(0);
  return;
}

