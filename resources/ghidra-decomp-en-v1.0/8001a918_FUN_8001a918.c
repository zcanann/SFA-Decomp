// Function: FUN_8001a918
// Entry: 8001a918
// Size: 1100 bytes

/* WARNING: Removing unreachable block (ram,0x8001a980) */

void FUN_8001a918(void)

{
  undefined4 *puVar1;
  bool bVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  short sVar10;
  undefined4 uVar6;
  undefined4 uVar7;
  ushort *puVar8;
  undefined4 *puVar9;
  int iVar11;
  int iVar12;
  int iVar13;
  uint *puVar14;
  int iVar15;
  undefined4 unaff_r26;
  int iVar16;
  undefined4 unaff_r27;
  int iVar17;
  int iVar18;
  int iVar19;
  uint local_40;
  undefined local_3c;
  undefined local_3b;
  undefined local_3a;
  
  FUN_802860c4();
  uVar4 = FUN_80022d3c(0);
  puVar5 = (undefined4 *)FUN_80023cc8(0x120,0x1a,0);
  sVar10 = FUN_80242f20();
  if (sVar10 == 1) {
    unaff_r27 = 0x4d000;
    unaff_r26 = 0x90ee4;
    DAT_803dc9e4 = 4;
    DAT_803dc968 = '\x01';
  }
  else if (sVar10 == 0) {
    unaff_r27 = 0x3000;
    unaff_r26 = 0x10120;
    DAT_803dc9e4 = 0;
    DAT_803dc968 = '\0';
  }
  uVar6 = FUN_80023cc8(unaff_r27,0x1a,0);
  uVar7 = FUN_80023cc8(unaff_r26,0x1a,0);
  FUN_80243004(uVar7,uVar6);
  if (DAT_8033af98 == 0) {
    if (DAT_803dc968 == '\0') {
      DAT_8033af90 = (uint *)&DAT_802c9880;
      DAT_8033af98 = 0x2b;
      DAT_8033af94 = &DAT_802c9d64;
      DAT_8033af9c = 7;
    }
    else {
      DAT_8033af90 = &DAT_802c8f40;
      DAT_8033af98 = 0x55;
      DAT_8033af94 = &DAT_802c982c;
      DAT_8033af9c = 7;
    }
  }
  DAT_8033afa0 = FUN_80054c98(0x200,0x60,0,0,0,0,0,1,1);
  DAT_802c86e0 = (undefined2)DAT_8033af98;
  DAT_802c86e4 = 0x30;
  DAT_802c86e5 = 0x20;
  DAT_802c86e8 = 0;
  DAT_802c86ea = 0x18;
  iVar16 = 0;
  sVar10 = 0;
  puVar14 = DAT_8033af90;
  iVar15 = DAT_8033af98;
  do {
    bVar2 = iVar15 == 0;
    iVar15 = iVar15 + -1;
    if (bVar2) {
      FUN_802419e8(DAT_8033afa0 + 0x60,0x20000);
      FUN_80023800(uVar6);
      FUN_80023800(uVar7);
      FUN_80023800(puVar5);
      FUN_80022d3c(uVar4);
      DAT_8033afac = 2;
      FUN_80286110();
      return;
    }
    if (DAT_803dc968 == '\0') {
      local_3c = (undefined)*puVar14;
      local_3b = 0;
    }
    else {
      puVar8 = &DAT_802c8d40;
      iVar17 = 0x7f;
      do {
        if ((uint)*puVar8 == *puVar14) {
          uVar3 = (uint)puVar8[1];
          goto LAB_8001ab18;
        }
        if ((uint)puVar8[1] == *puVar14) {
          uVar3 = (uint)puVar8[2];
          goto LAB_8001ab18;
        }
        puVar8 = puVar8 + 2;
        iVar17 = iVar17 + -1;
      } while (iVar17 != 0);
      uVar3 = 0;
LAB_8001ab18:
      if (uVar3 >> 8 == 0) {
        local_3b = 0;
        local_3c = (char)uVar3;
      }
      else {
        local_3c = (undefined)(uVar3 >> 8);
        local_3a = 0;
        local_3b = (char)uVar3;
      }
    }
    FUN_8024363c(&local_3c,&local_40);
    if ((int)(uint)DAT_802c86e8 < (int)local_40) {
      DAT_802c86e8 = (ushort)local_40;
    }
    iVar17 = (int)local_40 >> 3;
    if ((local_40 & 7) != 0) {
      iVar17 = iVar17 + 1;
    }
    iVar18 = 8;
    puVar9 = puVar5;
    do {
      *puVar9 = 0;
      puVar9[1] = 0;
      puVar9[2] = 0;
      puVar9[3] = 0;
      puVar9[4] = 0;
      puVar9[5] = 0;
      puVar9[6] = 0;
      puVar9[7] = 0;
      puVar9[8] = 0;
      puVar9 = puVar9 + 9;
      iVar18 = iVar18 + -1;
    } while (iVar18 != 0);
    FUN_80243338(&local_3c,puVar5,0,6,&local_40);
    if (0x200 < iVar16 + 0x18) {
      iVar16 = 0;
      sVar10 = sVar10 + 0x18;
    }
    *(short *)(puVar14 + 1) = (short)iVar16;
    *(short *)((int)puVar14 + 6) = sVar10;
    *(undefined *)(puVar14 + 2) = 0;
    *(undefined *)((int)puVar14 + 9) = 0;
    *(undefined *)((int)puVar14 + 10) = 0;
    *(undefined *)((int)puVar14 + 0xb) = 0;
    *(char *)(puVar14 + 3) = (char)local_40;
    *(undefined *)((int)puVar14 + 0xd) = 0x18;
    *(undefined *)((int)puVar14 + 0xe) = 6;
    *(undefined *)((int)puVar14 + 0xf) = 0;
    uVar3 = (int)(uint)*(ushort *)(puVar14 + 1) >> 3;
    iVar18 = (int)(uint)*(ushort *)((int)puVar14 + 6) >> 3;
    iVar11 = iVar18 + 3;
    puVar9 = puVar5;
    for (; iVar18 < iVar11; iVar18 = iVar18 + 1) {
      iVar13 = uVar3 << 5;
      iVar19 = (uVar3 + 3) - uVar3;
      if (uVar3 < uVar3 + 3) {
        do {
          iVar12 = DAT_8033afa0 + iVar13 + iVar18 * DAT_803db3c4;
          *(undefined4 *)(iVar12 + 0x60) = *puVar9;
          *(undefined4 *)(iVar12 + 100) = puVar9[1];
          *(undefined4 *)(iVar12 + 0x68) = puVar9[2];
          *(undefined4 *)(iVar12 + 0x6c) = puVar9[3];
          *(undefined4 *)(iVar12 + 0x70) = puVar9[4];
          *(undefined4 *)(iVar12 + 0x74) = puVar9[5];
          *(undefined4 *)(iVar12 + 0x78) = puVar9[6];
          puVar1 = puVar9 + 7;
          puVar9 = puVar9 + 8;
          *(undefined4 *)(iVar12 + 0x7c) = *puVar1;
          iVar13 = iVar13 + 0x20;
          iVar19 = iVar19 + -1;
        } while (iVar19 != 0);
      }
    }
    iVar16 = iVar16 + iVar17 * 8;
    puVar14 = puVar14 + 4;
  } while( true );
}

