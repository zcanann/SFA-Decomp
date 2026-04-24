// Function: FUN_80109efc
// Entry: 80109efc
// Size: 512 bytes

/* WARNING: Removing unreachable block (ram,0x8010a0d4) */
/* WARNING: Removing unreachable block (ram,0x8010a0cc) */
/* WARNING: Removing unreachable block (ram,0x8010a0dc) */

void FUN_80109efc(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  short *psVar1;
  int iVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  undefined8 uVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
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
  psVar1 = (short *)FUN_802860dc();
  iVar6 = *(int *)(psVar1 + 0x52);
  if (DAT_803dd558 == (int *)0x0) {
    DAT_803dd558 = (int *)FUN_80023cc8(0xf8,0xf,0);
  }
  *(undefined *)(DAT_803dd558 + 0x3d) = 1;
  *(undefined *)((int)DAT_803dd558 + 0xf5) = 0;
  iVar2 = FUN_80109b04((double)*(float *)(iVar6 + 0x18),(double)*(float *)(iVar6 + 0x1c),
                       (double)*(float *)(iVar6 + 0x20),*param_3,0x12);
  if (iVar2 == 0) {
    *(undefined *)((int)DAT_803dd558 + 0xf5) = 1;
  }
  else {
    *DAT_803dd558 = iVar2;
    iVar7 = *(int *)(iVar2 + 0x4c);
    dVar12 = (double)(*(float *)(iVar2 + 0x18) - *(float *)(iVar6 + 0x18));
    dVar11 = (double)(*(float *)(iVar2 + 0x1c) - *(float *)(iVar6 + 0x1c));
    dVar10 = (double)(*(float *)(iVar2 + 0x20) - *(float *)(iVar6 + 0x20));
    if ((*(byte *)(iVar7 + 0x1b) & 1) == 0) {
      sVar3 = *(short *)(iVar7 + 0x1c);
    }
    else {
      sVar3 = FUN_800217c0(dVar12,dVar10);
      sVar3 = -sVar3;
    }
    if ((*(byte *)(iVar7 + 0x1b) & 2) == 0) {
      sVar4 = *(short *)(iVar7 + 0x1e);
    }
    else {
      uVar9 = FUN_802931a0((double)(float)(dVar12 * dVar12 + (double)(float)(dVar10 * dVar10)));
      sVar4 = FUN_800217c0(dVar11,uVar9);
      sVar4 = sVar4 - *(short *)(iVar7 + 0x1e);
    }
    if ((*(byte *)(iVar7 + 0x1b) & 4) == 0) {
      sVar5 = *(short *)(iVar7 + 0x20);
    }
    else {
      sVar5 = *(short *)(iVar6 + 4);
    }
    dVar10 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar7 + 0x1a)) - DOUBLE_803e1880;
    *(undefined4 *)(psVar1 + 0xc) = *(undefined4 *)(iVar2 + 0x18);
    *(undefined4 *)(psVar1 + 0xe) = *(undefined4 *)(iVar2 + 0x1c);
    *(undefined4 *)(psVar1 + 0x10) = *(undefined4 *)(iVar2 + 0x20);
    *psVar1 = sVar3 + -0x8000;
    psVar1[1] = sVar4;
    psVar1[2] = sVar5;
    *(float *)(psVar1 + 0x5a) = (float)dVar10;
    FUN_8000e034((double)*(float *)(psVar1 + 0xc),(double)*(float *)(psVar1 + 0xe),
                 (double)*(float *)(psVar1 + 0x10),psVar1 + 6,psVar1 + 8,psVar1 + 10,
                 *(undefined4 *)(psVar1 + 0x18));
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  FUN_80286128();
  return;
}

