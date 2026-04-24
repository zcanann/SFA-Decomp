// Function: FUN_80112a28
// Entry: 80112a28
// Size: 856 bytes

/* WARNING: Removing unreachable block (ram,0x80112d58) */
/* WARNING: Removing unreachable block (ram,0x80112d50) */
/* WARNING: Removing unreachable block (ram,0x80112d60) */

void FUN_80112a28(void)

{
  undefined4 uVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  uint uVar6;
  uint in_r6;
  int unaff_r30;
  int iVar7;
  undefined4 uVar8;
  undefined8 in_f29;
  double dVar9;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  undefined8 uVar12;
  float local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar12 = FUN_802860dc();
  iVar4 = (int)((ulonglong)uVar12 >> 0x20);
  uVar6 = (uint)uVar12;
  iVar7 = *(int *)(iVar4 + 0x4c);
  dVar9 = (double)FLOAT_803e1c2c;
  local_5c = DAT_803e1c18;
  local_58 = DAT_803e1c1c;
  local_64 = DAT_803e1c20;
  local_60 = DAT_803e1c24;
  if (uVar6 == 0) {
    iVar7 = 0;
    goto LAB_80112d50;
  }
  cVar5 = FUN_8002e04c();
  if (cVar5 == '\0') {
    iVar7 = 0;
    goto LAB_80112d50;
  }
  if ((*(ushort *)(iVar7 + 0x22) & 0xf00) != 0) {
    iVar3 = ((int)(uVar6 & 0xf00) >> 8) + -1;
    if (3 < iVar3) {
      iVar3 = 3;
    }
    unaff_r30 = FUN_8002bdf4(0x30,*(undefined2 *)((int)&local_5c + iVar3 * 2));
    dVar9 = (double)FLOAT_803e1c54;
  }
  if (((int)*(short *)(iVar7 + 0x22) & 0xf000U) != 0) {
    iVar3 = ((int)(uVar6 & 0xf000) >> 0xc) + -1;
    if (3 < iVar3) {
      iVar3 = 3;
    }
    unaff_r30 = FUN_8002bdf4(0x30,*(undefined2 *)((int)&local_64 + iVar3 * 2));
    dVar9 = (double)FLOAT_803e1c54;
  }
  if ((*(ushort *)(iVar7 + 0x22) & 0xff) != 0) {
    if (uVar6 == 4) {
      unaff_r30 = FUN_8002bdf4(0x30,0x2cd);
      dVar9 = (double)FLOAT_803e1c54;
    }
    else if ((int)uVar6 < 4) {
      if (uVar6 == 2) {
        unaff_r30 = FUN_8002bdf4(0x30,9);
        dVar9 = (double)FLOAT_803e1c54;
      }
      else if ((int)uVar6 < 2) {
        if ((int)uVar6 < 1) goto LAB_80112cb4;
        unaff_r30 = FUN_8002bdf4(0x30,0x2cd);
        dVar9 = (double)FLOAT_803e1c54;
      }
      else {
        unaff_r30 = FUN_8002bdf4(0x30,0xb);
        dVar9 = (double)FLOAT_803e1c54;
      }
    }
    else {
      if (uVar6 != 6) {
        if ((int)uVar6 < 6) {
          dVar11 = (double)*(float *)(iVar4 + 0x18);
          dVar10 = (double)*(float *)(iVar4 + 0x1c);
          dVar9 = (double)*(float *)(iVar4 + 0x20);
          iVar7 = *(int *)(iVar4 + 0x4c);
          if (iVar7 != 0) {
            *(undefined4 *)(iVar4 + 0x18) = *(undefined4 *)(iVar7 + 8);
            *(undefined4 *)(iVar4 + 0x1c) = *(undefined4 *)(iVar7 + 0xc);
            *(undefined4 *)(iVar4 + 0x20) = *(undefined4 *)(iVar7 + 0x10);
          }
          local_68 = FLOAT_803e1c58;
          DAT_803dd5e4 = FUN_80036e58(4,iVar4,&local_68);
          *(float *)(iVar4 + 0x18) = (float)dVar11;
          *(float *)(iVar4 + 0x1c) = (float)dVar10;
          *(float *)(iVar4 + 0x20) = (float)dVar9;
          iVar7 = DAT_803dd5e4;
          if (DAT_803dd5e4 != 0) {
            uVar1 = *(undefined4 *)(iVar4 + 0xc);
            *(undefined4 *)(DAT_803dd5e4 + 0x18) = uVar1;
            *(undefined4 *)(DAT_803dd5e4 + 0xc) = uVar1;
            fVar2 = *(float *)(iVar4 + 0x10) + FLOAT_803e1c5c;
            *(float *)(DAT_803dd5e4 + 0x1c) = fVar2;
            *(float *)(DAT_803dd5e4 + 0x10) = fVar2;
            uVar1 = *(undefined4 *)(iVar4 + 0x14);
            *(undefined4 *)(DAT_803dd5e4 + 0x20) = uVar1;
            *(undefined4 *)(DAT_803dd5e4 + 0x14) = uVar1;
            iVar7 = DAT_803dd5e4;
          }
          goto LAB_80112d50;
        }
LAB_80112cb4:
        iVar7 = 0;
        goto LAB_80112d50;
      }
      unaff_r30 = FUN_8002bdf4(0x30,0x6a6);
      *(undefined *)(unaff_r30 + 0x1b) = 0;
      *(undefined *)(unaff_r30 + 0x22) = 0;
      *(undefined *)(unaff_r30 + 0x23) = 0x40;
      dVar9 = (double)FLOAT_803e1c60;
    }
  }
  *(undefined *)(unaff_r30 + 0x1a) = 0x14;
  *(undefined2 *)(unaff_r30 + 0x2c) = 0xffff;
  *(undefined2 *)(unaff_r30 + 0x1c) = 0xffff;
  *(undefined2 *)(unaff_r30 + 0x24) = 0xffff;
  *(undefined4 *)(unaff_r30 + 8) = *(undefined4 *)(iVar4 + 0xc);
  *(float *)(unaff_r30 + 0xc) = (float)((double)*(float *)(iVar4 + 0x10) + dVar9);
  *(undefined4 *)(unaff_r30 + 0x10) = *(undefined4 *)(iVar4 + 0x14);
  if ((in_r6 & 0xff) == 0) {
    *(undefined2 *)(unaff_r30 + 0x2e) = 1;
  }
  else {
    *(undefined2 *)(unaff_r30 + 0x2e) = 2;
  }
  *(undefined *)(unaff_r30 + 4) = *(undefined *)(iVar7 + 4);
  *(undefined *)(unaff_r30 + 6) = *(undefined *)(iVar7 + 6);
  *(undefined *)(unaff_r30 + 5) = *(undefined *)(iVar7 + 5);
  *(undefined *)(unaff_r30 + 7) = *(undefined *)(iVar7 + 7);
  DAT_803dd5e4 = FUN_8002df90(unaff_r30,5,(int)*(char *)(iVar4 + 0xac),0xffffffff,
                              *(undefined4 *)(iVar4 + 0x30));
  iVar7 = DAT_803dd5e4;
LAB_80112d50:
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  FUN_80286128(iVar7);
  return;
}

