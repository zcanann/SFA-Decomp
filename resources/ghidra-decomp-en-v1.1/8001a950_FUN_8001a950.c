// Function: FUN_8001a950
// Entry: 8001a950
// Size: 1224 bytes

/* WARNING: Removing unreachable block (ram,0x8001a9b8) */

void FUN_8001a950(void)

{
  undefined4 *puVar1;
  bool bVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  ushort uVar9;
  char *pcVar5;
  uint uVar6;
  ushort *puVar7;
  undefined4 *puVar8;
  int iVar10;
  uint uVar11;
  int iVar12;
  int iVar13;
  uint *puVar14;
  int iVar15;
  int unaff_r26;
  int iVar16;
  int unaff_r27;
  short sVar17;
  int iVar18;
  int iVar19;
  int iVar20;
  uint local_40;
  byte local_3c;
  byte local_3b;
  undefined local_3a;
  
  FUN_80286824();
  uVar3 = FUN_80022e00(0);
  puVar4 = (undefined4 *)FUN_80023d8c(0x120,0x1a);
  uVar9 = FUN_80243618();
  if (uVar9 == 1) {
    unaff_r27 = 0x4d000;
    unaff_r26 = 0x90ee4;
    DAT_803dd664 = 4;
    DAT_803dd5e8 = 1;
    DAT_8033bbf0 = (uint *)&DAT_802c99f8;
    DAT_8033bbf8 = 0x55;
    DAT_8033bbf4 = &DAT_802ca2e4;
    DAT_8033bbfc = 7;
  }
  else if (uVar9 == 0) {
    unaff_r27 = 0x3000;
    unaff_r26 = 0x10120;
    DAT_803dd5e8 = 0;
    DAT_8033bbf0 = (uint *)&DAT_802c94c0;
    DAT_8033bbf8 = 0x2b;
    DAT_803dd664 = 0;
    DAT_8033bbf4 = &DAT_802c99a4;
    DAT_8033bbfc = 7;
  }
  pcVar5 = (char *)FUN_80023d8c(unaff_r27,0x1a);
  uVar6 = FUN_80023d8c(unaff_r26,0x1a);
  FUN_802436fc(uVar6,pcVar5);
  DAT_8033bc00 = FUN_80054e14(0x200,0x60,0,'\0',0,0,0,1,1);
  DAT_802c8e60 = (undefined2)DAT_8033bbf8;
  DAT_802c8e64 = 0x30;
  DAT_802c8e65 = 0x20;
  DAT_802c8e68 = 0;
  DAT_802c8e6a = 0x18;
  iVar16 = 0;
  sVar17 = 0;
  puVar14 = DAT_8033bbf0;
  iVar15 = DAT_8033bbf8;
  do {
    bVar2 = iVar15 == 0;
    iVar15 = iVar15 + -1;
    if (bVar2) {
      FUN_802420e0(DAT_8033bc00 + 0x60,0x20000);
      FUN_800238c4((uint)pcVar5);
      FUN_800238c4(uVar6);
      FUN_800238c4((uint)puVar4);
      FUN_80022e00(uVar3);
      DAT_8033bc0c = 2;
      FUN_80286870();
      return;
    }
    if (DAT_803dd664 == 4) {
      uVar11 = *puVar14;
      puVar7 = &DAT_802ca338;
      iVar18 = 0x4d;
      do {
        if (*puVar7 == uVar11) {
          uVar11 = (uint)puVar7[1];
          goto LAB_8001abcc;
        }
        if (puVar7[1] == uVar11) {
          uVar11 = (uint)puVar7[2];
          goto LAB_8001abcc;
        }
        if (puVar7[2] == uVar11) {
          uVar11 = (uint)puVar7[3];
          goto LAB_8001abcc;
        }
        if (puVar7[3] == uVar11) {
          uVar11 = (uint)puVar7[4];
          goto LAB_8001abcc;
        }
        if (puVar7[4] == uVar11) {
          uVar11 = (uint)puVar7[5];
          goto LAB_8001abcc;
        }
        if (puVar7[5] == uVar11) {
          uVar11 = (uint)puVar7[6];
          goto LAB_8001abcc;
        }
        if (puVar7[6] == uVar11) {
          uVar11 = (uint)puVar7[7];
          goto LAB_8001abcc;
        }
        if (puVar7[7] == uVar11) {
          uVar11 = (uint)puVar7[8];
          goto LAB_8001abcc;
        }
        if (puVar7[8] == uVar11) {
          uVar11 = (uint)puVar7[9];
          goto LAB_8001abcc;
        }
        if (puVar7[9] == uVar11) {
          uVar11 = (uint)puVar7[10];
          goto LAB_8001abcc;
        }
        puVar7 = puVar7 + 10;
        iVar18 = iVar18 + -1;
      } while (iVar18 != 0);
      uVar11 = 0;
LAB_8001abcc:
      if (uVar11 >> 8 == 0) {
        local_3b = 0;
        local_3c = (byte)uVar11;
      }
      else {
        local_3c = (byte)(uVar11 >> 8);
        local_3a = 0;
        local_3b = (byte)uVar11;
      }
    }
    else {
      local_3c = (byte)*puVar14;
      local_3b = 0;
    }
    FUN_80243d34(&local_3c,&local_40);
    if ((int)(uint)DAT_802c8e68 < (int)local_40) {
      DAT_802c8e68 = (ushort)local_40;
    }
    iVar18 = (int)local_40 >> 3;
    if ((local_40 & 7) != 0) {
      iVar18 = iVar18 + 1;
    }
    iVar19 = 8;
    puVar8 = puVar4;
    do {
      *puVar8 = 0;
      puVar8[1] = 0;
      puVar8[2] = 0;
      puVar8[3] = 0;
      puVar8[4] = 0;
      puVar8[5] = 0;
      puVar8[6] = 0;
      puVar8[7] = 0;
      puVar8[8] = 0;
      puVar8 = puVar8 + 9;
      iVar19 = iVar19 + -1;
    } while (iVar19 != 0);
    FUN_80243a30(&local_3c,(int)puVar4,0,6,&local_40);
    if (0x200 < iVar16 + 0x18) {
      iVar16 = 0;
      sVar17 = sVar17 + 0x18;
    }
    *(short *)(puVar14 + 1) = (short)iVar16;
    *(short *)((int)puVar14 + 6) = sVar17;
    *(undefined *)(puVar14 + 2) = 0;
    *(undefined *)((int)puVar14 + 9) = 0;
    *(undefined *)((int)puVar14 + 10) = 0;
    *(undefined *)((int)puVar14 + 0xb) = 0;
    *(char *)(puVar14 + 3) = (char)local_40;
    *(undefined *)((int)puVar14 + 0xd) = 0x18;
    *(undefined *)((int)puVar14 + 0xe) = 6;
    *(undefined *)((int)puVar14 + 0xf) = 0;
    uVar11 = (int)(uint)*(ushort *)(puVar14 + 1) >> 3;
    iVar19 = (int)(uint)*(ushort *)((int)puVar14 + 6) >> 3;
    iVar10 = iVar19 + 3;
    puVar8 = puVar4;
    for (; iVar19 < iVar10; iVar19 = iVar19 + 1) {
      iVar13 = uVar11 << 5;
      iVar20 = (uVar11 + 3) - uVar11;
      if (uVar11 < uVar11 + 3) {
        do {
          iVar12 = DAT_8033bc00 + iVar13 + iVar19 * DAT_803dc024;
          *(undefined4 *)(iVar12 + 0x60) = *puVar8;
          *(undefined4 *)(iVar12 + 100) = puVar8[1];
          *(undefined4 *)(iVar12 + 0x68) = puVar8[2];
          *(undefined4 *)(iVar12 + 0x6c) = puVar8[3];
          *(undefined4 *)(iVar12 + 0x70) = puVar8[4];
          *(undefined4 *)(iVar12 + 0x74) = puVar8[5];
          *(undefined4 *)(iVar12 + 0x78) = puVar8[6];
          puVar1 = puVar8 + 7;
          puVar8 = puVar8 + 8;
          *(undefined4 *)(iVar12 + 0x7c) = *puVar1;
          iVar13 = iVar13 + 0x20;
          iVar20 = iVar20 + -1;
        } while (iVar20 != 0);
      }
    }
    iVar16 = iVar16 + iVar18 * 8;
    puVar14 = puVar14 + 4;
  } while( true );
}

