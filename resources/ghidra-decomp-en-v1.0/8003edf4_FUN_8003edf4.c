// Function: FUN_8003edf4
// Entry: 8003edf4
// Size: 1976 bytes

void FUN_8003edf4(undefined4 param_1,undefined4 param_2,undefined4 *param_3,int *param_4)

{
  undefined uVar1;
  undefined uVar2;
  byte bVar3;
  undefined uVar4;
  uint3 uVar5;
  bool bVar6;
  int iVar7;
  int iVar8;
  code *pcVar9;
  char cVar14;
  int *piVar10;
  undefined4 uVar11;
  undefined4 *puVar12;
  undefined4 uVar13;
  int iVar15;
  int iVar16;
  int iVar17;
  uint uVar18;
  int iVar19;
  undefined1 *puVar20;
  double dVar21;
  double dVar22;
  undefined8 uVar23;
  undefined4 local_128;
  uint local_124;
  undefined auStack288 [4];
  undefined4 local_11c;
  undefined4 local_118;
  int local_114;
  undefined auStack272 [48];
  undefined auStack224 [48];
  undefined auStack176 [48];
  undefined auStack128 [48];
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  
  uVar23 = FUN_802860bc();
  iVar7 = (int)((ulonglong)uVar23 >> 0x20);
  iVar15 = (int)uVar23;
  bVar6 = false;
  uVar18 = param_4[4];
  uVar4 = *(undefined *)(*param_4 + ((int)uVar18 >> 3));
  iVar8 = *param_4 + ((int)uVar18 >> 3);
  uVar1 = *(undefined *)(iVar8 + 1);
  uVar2 = *(undefined *)(iVar8 + 2);
  param_4[4] = uVar18 + 6;
  uVar5 = CONCAT12(uVar2,CONCAT11(uVar1,uVar4)) >> (uVar18 & 7) & 0x3f;
  pcVar9 = (code *)FUN_80028534(param_3);
  if ((pcVar9 == (code *)0x0) || (cVar14 = (*pcVar9)(iVar7,param_3,uVar5), cVar14 == '\0')) {
    iVar8 = FUN_80028424(*param_3,uVar5);
    piVar10 = (int *)FUN_800285b8(param_3,uVar5);
    FUN_800528f0();
    cVar14 = '\0';
    if (((*piVar10 != 0) || (piVar10[1] != 0)) && (*(int *)(iVar8 + 0x34) != 0)) {
      uVar11 = FUN_800536c0();
      iVar16 = DAT_803dcc5c + 1;
      if (*piVar10 != 0) {
        iVar16 = DAT_803dcc5c + 2;
      }
      if (piVar10[1] != 0) {
        iVar16 = iVar16 + 1;
      }
      cVar14 = FUN_80050ad8(uVar11,iVar16,*(undefined *)(iVar8 + 0x42),*(undefined4 *)(iVar8 + 0x24)
                           );
    }
    if (*piVar10 != 0) {
      FUN_80051348(*piVar10,*(undefined *)(iVar7 + 0xf1));
    }
    if (piVar10[1] == 0) {
      local_128 = DAT_803db46c;
      FUN_8025bcc4(3,&local_128);
    }
    else {
      if (*(int *)(iVar8 + 0x1c) == 0) {
        local_11c = local_11c & 0xffffff00;
      }
      else {
        local_11c = CONCAT31(0xffff00,*(undefined *)(iVar8 + 0x22)) | 0xff00;
      }
      local_124 = local_11c;
      FUN_8025bcc4(3,&local_124);
      FUN_800510f0(piVar10[1],*piVar10 != 0,*(undefined *)(iVar8 + 0x20));
      if ((char)local_11c != '\0') {
        FUN_80050ff4(*piVar10 != 0);
      }
    }
    iVar16 = DAT_803dcc5c;
    if (DAT_803dcc4c == '\0') {
      bVar3 = *(byte *)(*(int *)(iVar7 + 0x50) + 0x5f);
      if (((bVar3 & 4) == 0) || (*(int *)(*(int *)(iVar7 + 100) + 0xc) == 0)) {
        if ((bVar3 & 0x10) == 0) {
          if ((bVar3 & 4) == 0) {
            puVar12 = &DAT_803dcc64;
            puVar20 = &DAT_803dcc60;
            for (iVar19 = 0; iVar19 < DAT_803dcc5c; iVar19 = iVar19 + 1) {
              iVar17 = FUN_8001d984(*puVar12);
              if (iVar17 != 0) {
                FUN_8001d7f8(*puVar12,&local_114,&local_118);
                if (local_114 == 2) {
                  bVar6 = true;
                }
                uVar11 = FUN_8001d818(*puVar12);
                FUN_80050558(iVar17,uVar11,local_114,local_118,*puVar20);
              }
              puVar12 = puVar12 + 1;
              puVar20 = puVar20 + 1;
            }
          }
        }
        else {
          FUN_8004d6d8();
          iVar16 = 0;
        }
      }
      else {
        FUN_8005011c();
        iVar16 = 0;
      }
    }
    else {
      FUN_8004d230();
      bVar6 = true;
      iVar16 = 0;
    }
    if (cVar14 != '\0') {
      FUN_80050a28(cVar14);
    }
    if (((*(int *)(iVar8 + 0x18) != 0) && (*(int *)(iVar8 + 0x1c) == 0)) && (piVar10[1] != 0)) {
      FUN_800536c0();
      FUN_80050f2c();
    }
    uVar11 = 0;
    if (((*(ushort *)(iVar15 + 0xe2) & 2) != 0) && ((*(byte *)(iVar15 + 0x24) & 2) == 0)) {
      uVar11 = 1;
    }
    cVar14 = FUN_8003e98c(iVar7,iVar8,piVar10,0x80,uVar11,iVar16);
    if (cVar14 == '\0') {
      FUN_80050e28(*piVar10 != 0);
    }
    if ((*(uint *)(iVar8 + 0x3c) & 0x100000) != 0) {
      puVar12 = (undefined4 *)FUN_8004c250(iVar8,1);
      iVar19 = *(int *)(*(int *)(iVar7 + 0x50) + 0xc);
      iVar17 = 0;
      for (uVar18 = (uint)*(byte *)(*(int *)(iVar7 + 0x50) + 0x59); uVar18 != 0; uVar18 = uVar18 - 1
          ) {
        if (*(char *)((int)puVar12 + 5) == *(char *)(iVar19 + 1)) {
          iVar19 = *(int *)(iVar7 + 0x70) + iVar17 * 0x10;
          uStack76 = (int)*(short *)(iVar19 + 8) ^ 0x80000000;
          local_50 = 0x43300000;
          dVar21 = (double)(FLOAT_803dea48 *
                           (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dea40));
          uStack68 = (int)*(short *)(iVar19 + 10) ^ 0x80000000;
          local_48 = 0x43300000;
          dVar22 = (double)(FLOAT_803dea48 *
                           (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dea40));
          goto LAB_8003f230;
        }
        iVar19 = iVar19 + 2;
        iVar17 = iVar17 + 1;
      }
      dVar21 = (double)FLOAT_803dea04;
      dVar22 = dVar21;
LAB_8003f230:
      FUN_802472e4(dVar21,dVar22,(double)FLOAT_803dea04,auStack128);
      uVar13 = FUN_800536c0(*puVar12);
      FUN_8004c330(uVar13,auStack128);
    }
    FUN_8003e98c(iVar7,iVar8,piVar10,0,uVar11,iVar16);
    cVar14 = FUN_8004c248();
    if ((cVar14 != '\0') && ((*(ushort *)(iVar15 + 2) & 0x100) == 0)) {
      FUN_800704dc(auStack288);
      FUN_8004e7f8(auStack288);
    }
    if ((*(uint *)(iVar8 + 0x3c) & 0x100) != 0) {
      uVar11 = FUN_8000f54c();
      FUN_8002b47c(iVar7,auStack224,0);
      FUN_80246eb4(uVar11,auStack224,auStack272);
      FUN_80246eb4(&DAT_803967f0,auStack272,auStack176);
      FUN_8025d160(auStack176,0x24,0);
      FUN_8004d928();
    }
    if ((*(byte *)(*(int *)(iVar7 + 0x50) + 0x5f) & 0x10) != 0) {
      FUN_8004d5b4(iVar8);
    }
    if (((*(byte *)(iVar7 + 0xe5) & 2) != 0) || ((*(byte *)(iVar7 + 0xe5) & 0x10) != 0)) {
      local_11c = *(uint *)(iVar7 + 0xec);
      FUN_80052638(&local_11c);
    }
    if ((*(uint *)(iVar8 + 0x3c) & 0x20000) != 0) {
      FUN_80118240();
    }
    FUN_800528bc();
    pcVar9 = (code *)FUN_800284c4(param_3);
    if (pcVar9 == (code *)0x0) {
      uVar11 = 1;
      if (((*(char *)(iVar7 + 0x37) != -1) || ((*(uint *)(iVar8 + 0x3c) & 0x40000000) != 0)) ||
         (bVar6)) {
        FUN_8025c584(1,4,5,5);
        if ((*(ushort *)(iVar15 + 2) & 0x400) == 0) {
          if ((*(ushort *)(iVar15 + 2) & 0x2000) == 0) {
            FUN_80070310(1,3,0);
            FUN_8025bff0(7,0,0,7,0);
          }
          else {
            uVar11 = 0;
            FUN_80070310(1,3,1);
            FUN_8025bff0(4,DAT_803dcc3c,0,4,DAT_803dcc3c);
          }
        }
        else {
          FUN_80070310(0,3,0);
          FUN_8025bff0(7,0,0,7,0);
        }
      }
      else if ((*(uint *)(iVar8 + 0x3c) & 0x400) == 0) {
        FUN_8025c584(0,1,0,5);
        if ((*(ushort *)(iVar15 + 2) & 0x400) == 0) {
          FUN_80070310(1,3,1);
        }
        else {
          FUN_80070310(0,3,0);
        }
        FUN_8025bff0(7,0,0,7,0);
      }
      else {
        FUN_8025c584(0,1,0,5);
        if ((*(ushort *)(iVar15 + 2) & 0x400) == 0) {
          FUN_80070310(1,3,1);
        }
        else {
          FUN_80070310(0,3,0);
        }
        FUN_8025bff0(4,0x40,0,4,0x40);
      }
      if ((*(uint *)(iVar8 + 0x3c) & 0x400) != 0) {
        uVar11 = 0;
      }
      FUN_800702b8(uVar11);
    }
    else {
      (*pcVar9)(iVar7,param_3,uVar5);
    }
    if ((*(uint *)(iVar8 + 0x3c) & 8) == 0) {
      FUN_80258b24(0);
    }
    else {
      FUN_80258b24(2);
    }
  }
  FUN_80286108(uVar5);
  return;
}

