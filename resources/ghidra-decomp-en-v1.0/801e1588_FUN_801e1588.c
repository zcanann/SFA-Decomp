// Function: FUN_801e1588
// Entry: 801e1588
// Size: 1316 bytes

/* WARNING: Removing unreachable block (ram,0x801e1a8c) */

void FUN_801e1588(undefined4 param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  int *piVar16;
  int iVar17;
  int iVar18;
  undefined4 uVar19;
  double dVar20;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  fVar15 = DAT_802c2424;
  fVar14 = DAT_802c2420;
  fVar13 = DAT_802c241c;
  fVar12 = DAT_802c2418;
  fVar11 = DAT_802c2414;
  fVar10 = DAT_802c2410;
  fVar9 = DAT_802c240c;
  fVar8 = DAT_802c2408;
  fVar7 = DAT_802c2404;
  fVar6 = DAT_802c2400;
  fVar5 = DAT_802c23fc;
  fVar4 = DAT_802c23f8;
  uVar19 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  FUN_8005cdf8(0);
  FUN_800891f0(1);
  FUN_800891dc(0x29,0x4b,0xa9);
  FUN_80089710(7,1,0);
  dVar20 = (double)FUN_8008ed88();
  if ((double)FLOAT_803e56cc < dVar20) {
    FLOAT_803ddc24 = FLOAT_803e57a4;
    FLOAT_803ddc28 = FLOAT_803e57a4;
  }
  FLOAT_803ddc28 = -(FLOAT_803e57b4 * FLOAT_803db414 - FLOAT_803ddc28);
  if (FLOAT_803ddc28 < FLOAT_803e56cc) {
    FLOAT_803ddc28 = FLOAT_803e56cc;
  }
  uVar1 = (uint)(FLOAT_803ddc28 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)DAT_803dc084 - (uint)DAT_803dc080 ^ 0x80000000) -
                        DOUBLE_803e57c0) +
                (float)((double)CONCAT44(0x43300000,DAT_803dc080 ^ 0x80000000) - DOUBLE_803e57c0));
  DAT_803ddc38 = (undefined)uVar1;
  uVar2 = (uint)(FLOAT_803ddc28 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)bRam803dc085 - (uint)bRam803dc081 ^ 0x80000000) -
                        DOUBLE_803e57c0) +
                (float)((double)CONCAT44(0x43300000,bRam803dc081 ^ 0x80000000) - DOUBLE_803e57c0));
  uRam803ddc39 = (undefined)uVar2;
  uVar3 = (uint)(FLOAT_803ddc28 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)bRam803dc086 - (uint)bRam803dc082 ^ 0x80000000) -
                        DOUBLE_803e57c0) +
                (float)((double)CONCAT44(0x43300000,bRam803dc082 ^ 0x80000000) - DOUBLE_803e57c0));
  uRam803ddc3a = (undefined)uVar3;
  FUN_800895e0(7,uVar1 & 0xff,uVar2 & 0xff,uVar3 & 0xff,0x40,0x40);
  uVar1 = (uint)(FLOAT_803ddc28 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)DAT_803dc07c - (uint)DAT_803dc078 ^ 0x80000000) -
                        DOUBLE_803e57c0) +
                (float)((double)CONCAT44(0x43300000,DAT_803dc078 ^ 0x80000000) - DOUBLE_803e57c0));
  DAT_803ddc34 = (undefined)uVar1;
  uVar2 = (uint)(FLOAT_803ddc28 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)bRam803dc07d - (uint)bRam803dc079 ^ 0x80000000) -
                        DOUBLE_803e57c0) +
                (float)((double)CONCAT44(0x43300000,bRam803dc079 ^ 0x80000000) - DOUBLE_803e57c0));
  uRam803ddc35 = (undefined)uVar2;
  uVar3 = (uint)(FLOAT_803ddc28 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)bRam803dc07e - (uint)bRam803dc07a ^ 0x80000000) -
                        DOUBLE_803e57c0) +
                (float)((double)CONCAT44(0x43300000,bRam803dc07a ^ 0x80000000) - DOUBLE_803e57c0));
  uRam803ddc36 = (undefined)uVar3;
  FUN_80089510(7,uVar1 & 0xff,uVar2 & 0xff,uVar3 & 0xff);
  uVar1 = (uint)(FLOAT_803ddc28 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)DAT_803dc08c - (uint)DAT_803dc088 ^ 0x80000000) -
                        DOUBLE_803e57c0) +
                (float)((double)CONCAT44(0x43300000,DAT_803dc088 ^ 0x80000000) - DOUBLE_803e57c0));
  DAT_803ddc30 = (undefined)uVar1;
  uVar2 = (uint)(FLOAT_803ddc28 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)bRam803dc08d - (uint)bRam803dc089 ^ 0x80000000) -
                        DOUBLE_803e57c0) +
                (float)((double)CONCAT44(0x43300000,bRam803dc089 ^ 0x80000000) - DOUBLE_803e57c0));
  uRam803ddc31 = (undefined)uVar2;
  uVar3 = (uint)(FLOAT_803ddc28 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)bRam803dc08e - (uint)bRam803dc08a ^ 0x80000000) -
                        DOUBLE_803e57c0) +
                (float)((double)CONCAT44(0x43300000,bRam803dc08a ^ 0x80000000) - DOUBLE_803e57c0));
  uRam803ddc32 = (undefined)uVar3;
  FUN_80089578(7,uVar1 & 0xff,uVar2 & 0xff,uVar3 & 0xff);
  DAT_803ddc2d = (undefined)(int)(FLOAT_803ddc28 * FLOAT_803e57e0 + FLOAT_803e57f0);
  FUN_80089234(1);
  FUN_800891f8((double)(FLOAT_803ddc28 * (fVar13 - fVar10) + fVar10),
               (double)(FLOAT_803ddc28 * (fVar14 - fVar11) + fVar11),
               (double)(FLOAT_803ddc28 * (fVar15 - fVar12) + fVar12),(double)FLOAT_803e5724);
  if (*(char *)(param_2 + 0xab) == '\0') {
    FUN_800894a8((double)fVar4,(double)fVar5,(double)fVar6,7);
  }
  else {
    FUN_800894a8((double)fVar7,(double)fVar8,(double)fVar9,7);
  }
  piVar16 = (int *)FUN_8002b588(param_1);
  dVar20 = (double)FLOAT_803e57f4;
  for (iVar18 = 0; iVar18 < (int)(uint)*(byte *)(*piVar16 + 0xf8); iVar18 = iVar18 + 1) {
    iVar17 = FUN_80028424(*piVar16,iVar18);
    if (*(char *)(iVar17 + 0x29) == '\x01') {
      *(char *)(iVar17 + 0xc) = (char)(int)(dVar20 * (double)FLOAT_803ddc28);
    }
  }
  __psq_l0(auStack8,uVar19);
  __psq_l1(auStack8,uVar19);
  return;
}

