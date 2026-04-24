// Function: FUN_8003eeec
// Entry: 8003eeec
// Size: 1976 bytes

void FUN_8003eeec(undefined4 param_1,undefined4 param_2,int *param_3,int *param_4)

{
  undefined uVar1;
  undefined uVar2;
  byte bVar3;
  undefined uVar4;
  bool bVar5;
  ushort *puVar6;
  int iVar7;
  code *pcVar8;
  char cVar12;
  int *piVar9;
  uint *puVar10;
  float *pfVar11;
  int iVar13;
  int iVar14;
  int iVar15;
  uint uVar16;
  int iVar17;
  int iVar18;
  byte *pbVar19;
  uint uVar20;
  int *piVar21;
  double dVar22;
  double dVar23;
  undefined8 uVar24;
  undefined4 local_128;
  uint local_124;
  undefined4 uStack_120;
  undefined4 local_11c;
  int local_118;
  int local_114;
  float afStack_110 [12];
  float afStack_e0 [12];
  float afStack_b0 [12];
  undefined4 auStack_80 [12];
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  
  uVar24 = FUN_80286820();
  puVar6 = (ushort *)((ulonglong)uVar24 >> 0x20);
  iVar13 = (int)uVar24;
  bVar5 = false;
  uVar16 = param_4[4];
  uVar4 = *(undefined *)(*param_4 + ((int)uVar16 >> 3));
  iVar7 = *param_4 + ((int)uVar16 >> 3);
  uVar1 = *(undefined *)(iVar7 + 1);
  uVar2 = *(undefined *)(iVar7 + 2);
  param_4[4] = uVar16 + 6;
  uVar16 = (uint3)(CONCAT12(uVar2,CONCAT11(uVar1,uVar4)) >> (uVar16 & 7)) & 0x3f;
  pcVar8 = (code *)FUN_800285f8((int)param_3);
  if ((pcVar8 == (code *)0x0) || (cVar12 = (*pcVar8)(puVar6,param_3,uVar16), cVar12 == '\0')) {
    iVar7 = FUN_800284e8(*param_3,uVar16);
    piVar9 = (int *)FUN_8002867c((int)param_3,uVar16);
    FUN_80052a6c();
    uVar20 = 0;
    if (((*piVar9 != 0) || (piVar9[1] != 0)) && (*(uint *)(iVar7 + 0x34) != 0)) {
      uVar20 = FUN_8005383c(*(uint *)(iVar7 + 0x34));
      iVar14 = DAT_803dd8dc + 1;
      if (*piVar9 != 0) {
        iVar14 = DAT_803dd8dc + 2;
      }
      if (piVar9[1] != 0) {
        iVar14 = iVar14 + 1;
      }
      uVar20 = FUN_80050c54(uVar20,iVar14,(uint)*(byte *)(iVar7 + 0x42),*(uint *)(iVar7 + 0x24));
      uVar20 = uVar20 & 0xff;
    }
    if (*piVar9 != 0) {
      FUN_800514c4(*piVar9,*(char *)((int)puVar6 + 0xf1));
    }
    if (piVar9[1] == 0) {
      local_128 = DAT_803dc0cc;
      FUN_8025c428(3,(byte *)&local_128);
    }
    else {
      if (*(int *)(iVar7 + 0x1c) == 0) {
        local_11c = local_11c & 0xffffff00;
      }
      else {
        local_11c = CONCAT31(0xffffff,*(undefined *)(iVar7 + 0x22));
      }
      local_124 = local_11c;
      FUN_8025c428(3,(byte *)&local_124);
      FUN_8005126c(piVar9[1],*piVar9 != 0,(uint)*(byte *)(iVar7 + 0x20));
      if ((char)local_11c != '\0') {
        FUN_80051170(*piVar9 != 0);
      }
    }
    iVar14 = DAT_803dd8dc;
    if (DAT_803dd8cc == '\0') {
      bVar3 = *(byte *)(*(int *)(puVar6 + 0x28) + 0x5f);
      if (((bVar3 & 4) == 0) || (*(float **)(*(int *)(puVar6 + 0x32) + 0xc) == (float *)0x0)) {
        if ((bVar3 & 0x10) == 0) {
          if ((bVar3 & 4) == 0) {
            piVar21 = &DAT_803dd8e4;
            pbVar19 = &DAT_803dd8e0;
            for (iVar18 = 0; iVar18 < DAT_803dd8dc; iVar18 = iVar18 + 1) {
              iVar17 = FUN_8001da48(*piVar21);
              if (iVar17 != 0) {
                FUN_8001d8bc(*piVar21,&local_114,&local_118);
                if (local_114 == 2) {
                  bVar5 = true;
                }
                iVar15 = FUN_8001d8dc(*piVar21);
                FUN_800506d4(iVar17,iVar15,local_114,local_118,(uint)*pbVar19);
              }
              piVar21 = piVar21 + 1;
              pbVar19 = pbVar19 + 1;
            }
          }
        }
        else {
          FUN_8004d854();
          iVar14 = 0;
        }
      }
      else {
        FUN_80050298(*(float **)(*(int *)(puVar6 + 0x32) + 0xc));
        iVar14 = 0;
      }
    }
    else {
      FUN_8004d3ac();
      bVar5 = true;
      iVar14 = 0;
    }
    if (uVar20 != 0) {
      FUN_80050ba4(uVar20);
    }
    if (((*(uint *)(iVar7 + 0x18) != 0) && (*(int *)(iVar7 + 0x1c) == 0)) && (piVar9[1] != 0)) {
      FUN_8005383c(*(uint *)(iVar7 + 0x18));
      FUN_800510a8();
    }
    iVar18 = 0;
    if (((*(ushort *)(iVar13 + 0xe2) & 2) != 0) && ((*(byte *)(iVar13 + 0x24) & 2) == 0)) {
      iVar18 = 1;
    }
    cVar12 = FUN_8003ea84(puVar6,iVar7,piVar9,0x80,iVar18,iVar14);
    if (cVar12 == '\0') {
      FUN_80050fa4(*piVar9 != 0);
    }
    if ((*(uint *)(iVar7 + 0x3c) & 0x100000) != 0) {
      puVar10 = (uint *)FUN_8004c3cc(iVar7,1);
      iVar17 = *(int *)(*(int *)(puVar6 + 0x28) + 0xc);
      iVar15 = 0;
      for (uVar20 = (uint)*(byte *)(*(int *)(puVar6 + 0x28) + 0x59); uVar20 != 0;
          uVar20 = uVar20 - 1) {
        if (*(char *)((int)puVar10 + 5) == *(char *)(iVar17 + 1)) {
          iVar17 = *(int *)(puVar6 + 0x38) + iVar15 * 0x10;
          uStack_4c = (int)*(short *)(iVar17 + 8) ^ 0x80000000;
          local_50 = 0x43300000;
          dVar22 = (double)(FLOAT_803df6c8 *
                           (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803df6c0));
          uStack_44 = (int)*(short *)(iVar17 + 10) ^ 0x80000000;
          local_48 = 0x43300000;
          dVar23 = (double)(FLOAT_803df6c8 *
                           (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803df6c0));
          goto LAB_8003f328;
        }
        iVar17 = iVar17 + 2;
        iVar15 = iVar15 + 1;
      }
      dVar22 = (double)FLOAT_803df684;
      dVar23 = dVar22;
LAB_8003f328:
      FUN_80247a48(dVar22,dVar23,(double)FLOAT_803df684,auStack_80);
      FUN_8005383c(*puVar10);
      FUN_8004c4ac();
    }
    FUN_8003ea84(puVar6,iVar7,piVar9,0,iVar18,iVar14);
    cVar12 = FUN_8004c3c4();
    if ((cVar12 != '\0') && ((*(ushort *)(iVar13 + 2) & 0x100) == 0)) {
      FUN_80070658((undefined *)&uStack_120);
      FUN_8004e974(&uStack_120);
    }
    if ((*(uint *)(iVar7 + 0x3c) & 0x100) != 0) {
      pfVar11 = (float *)FUN_8000f56c();
      FUN_8002b554(puVar6,afStack_e0,'\0');
      FUN_80247618(pfVar11,afStack_e0,afStack_110);
      FUN_80247618((float *)&DAT_80397450,afStack_110,afStack_b0);
      FUN_8025d8c4(afStack_b0,0x24,0);
      FUN_8004daa4();
    }
    if ((*(byte *)(*(int *)(puVar6 + 0x28) + 0x5f) & 0x10) != 0) {
      FUN_8004d730(iVar7);
    }
    if (((*(byte *)((int)puVar6 + 0xe5) & 2) != 0) || ((*(byte *)((int)puVar6 + 0xe5) & 0x10) != 0))
    {
      local_11c = *(uint *)(puVar6 + 0x76);
      FUN_800527b4((char *)&local_11c);
    }
    if ((*(uint *)(iVar7 + 0x3c) & 0x20000) != 0) {
      FUN_801184e8();
    }
    FUN_80052a38();
    pcVar8 = (code *)FUN_80028588((int)param_3);
    if (pcVar8 == (code *)0x0) {
      uVar16 = 1;
      if (((*(char *)((int)puVar6 + 0x37) != -1) || ((*(uint *)(iVar7 + 0x3c) & 0x40000000) != 0))
         || (bVar5)) {
        FUN_8025cce8(1,4,5,5);
        if ((*(ushort *)(iVar13 + 2) & 0x400) == 0) {
          if ((*(ushort *)(iVar13 + 2) & 0x2000) == 0) {
            FUN_8007048c(1,3,0);
            FUN_8025c754(7,0,0,7,0);
          }
          else {
            uVar16 = 0;
            FUN_8007048c(1,3,1);
            FUN_8025c754(4,(uint)DAT_803dd8bc,0,4,(uint)DAT_803dd8bc);
          }
        }
        else {
          FUN_8007048c(0,3,0);
          FUN_8025c754(7,0,0,7,0);
        }
      }
      else if ((*(uint *)(iVar7 + 0x3c) & 0x400) == 0) {
        FUN_8025cce8(0,1,0,5);
        if ((*(ushort *)(iVar13 + 2) & 0x400) == 0) {
          FUN_8007048c(1,3,1);
        }
        else {
          FUN_8007048c(0,3,0);
        }
        FUN_8025c754(7,0,0,7,0);
      }
      else {
        FUN_8025cce8(0,1,0,5);
        if ((*(ushort *)(iVar13 + 2) & 0x400) == 0) {
          FUN_8007048c(1,3,1);
        }
        else {
          FUN_8007048c(0,3,0);
        }
        FUN_8025c754(4,0x40,0,4,0x40);
      }
      if ((*(uint *)(iVar7 + 0x3c) & 0x400) != 0) {
        uVar16 = 0;
      }
      FUN_80070434(uVar16);
    }
    else {
      (*pcVar8)(puVar6,param_3,uVar16);
    }
    if ((*(uint *)(iVar7 + 0x3c) & 8) == 0) {
      FUN_80259288(0);
    }
    else {
      FUN_80259288(2);
    }
  }
  FUN_8028686c();
  return;
}

