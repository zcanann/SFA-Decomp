// Function: FUN_80054620
// Entry: 80054620
// Size: 1912 bytes

/* WARNING: Removing unreachable block (ram,0x800547d0) */
/* WARNING: Removing unreachable block (ram,0x8005481c) */

void FUN_80054620(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  undefined2 uVar2;
  uint uVar3;
  undefined4 *puVar4;
  int *piVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  undefined4 in_r10;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  undefined4 *puVar13;
  undefined4 *puVar14;
  undefined4 *unaff_r24;
  uint unaff_r25;
  uint uVar15;
  undefined4 uVar16;
  int iVar17;
  undefined8 extraout_f1;
  undefined8 uVar18;
  undefined8 extraout_f1_00;
  longlong lVar19;
  uint local_58;
  uint local_54 [21];
  
  lVar19 = FUN_80286810();
  iVar7 = (int)((ulonglong)lVar19 >> 0x20);
  uVar6 = (uint)lVar19;
  uVar18 = extraout_f1;
  if (((lVar19 < 0) && ((-iVar7 & 0x8000U) != 0)) && ((-iVar7 & 0x7fffU) == 0x82e)) {
    uVar18 = FUN_8007d858();
  }
  iVar8 = 0;
  piVar5 = DAT_803dda44;
  iVar17 = DAT_803dda3c;
  if (0 < DAT_803dda3c) {
    do {
      if (iVar7 == *piVar5) {
        *(short *)(DAT_803dda44[iVar8 * 4 + 1] + 0xe) =
             *(short *)(DAT_803dda44[iVar8 * 4 + 1] + 0xe) + 1;
        goto LAB_80054d94;
      }
      piVar5 = piVar5 + 4;
      iVar8 = iVar8 + 1;
      iVar17 = iVar17 + -1;
    } while (iVar17 != 0);
  }
  iVar17 = FUN_800431a4();
  bVar1 = iVar17 == 0;
  if (!bVar1) {
    FUN_80243e74();
  }
  if (lVar19 < 0) {
    uVar9 = -iVar7;
  }
  else if ((lVar19 < 0xbb800000000) ||
          (uVar9 = (uint)*(ushort *)(DAT_803dda40 + iVar7 * 2), uVar9 == 0)) {
    uVar9 = (uint)*(ushort *)(DAT_803dda40 + iVar7 * 2);
  }
  else {
    uVar9 = uVar9 + 1;
  }
  uVar15 = uVar9 & 0xffff;
  if ((uVar9 & 0x8000) == 0) {
    if (lVar19 < 0xbb800000000) {
      iVar17 = 0;
      uVar16 = 0x23;
    }
    else {
      iVar17 = 2;
      uVar16 = 0x4f;
    }
  }
  else {
    iVar17 = 1;
    uVar16 = 0x20;
    uVar15 = uVar9 & 0x7fff;
  }
  if ((&DAT_8037ed08)[iVar17] <= (int)uVar15) {
    uVar15 = 0;
  }
  iVar8 = 0;
  DAT_8037ed14 = (int *)FUN_80043860(0x24);
  for (piVar5 = DAT_8037ed14; *piVar5 != -1; piVar5 = piVar5 + 1) {
    iVar8 = iVar8 + 1;
  }
  DAT_8037ed08 = iVar8 + -1;
  iVar8 = 0;
  DAT_8037ed18 = (int *)FUN_80043860(0x21);
  for (piVar5 = DAT_8037ed18; *piVar5 != -1; piVar5 = piVar5 + 1) {
    iVar8 = iVar8 + 1;
  }
  DAT_8037ed0c = iVar8 + -1;
  uVar9 = *(uint *)((int)(&DAT_8037ed14)[iVar17] + uVar15 * 4);
  uVar12 = uVar9 >> 0x18 & 0x3f;
  if (uVar12 == 1) {
    if (iVar17 == 0) {
      uVar18 = FUN_80048928(uVar9,uVar15,local_54,&local_58,1,0,0);
    }
    else if (iVar17 == 2) {
      uVar18 = FUN_80048ae0(uVar9,uVar15,local_54,&local_58,1,0,0);
    }
    else {
      uVar18 = FUN_80048658(uVar18,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar9,
                            uVar15,local_54,&local_58,1,0,0,in_r10);
    }
    *DAT_803dda38 = 0;
    DAT_803dda38[1] = local_54[0];
    if (local_58 == 0xffffffff) {
      DAT_803dda38[2] = local_54[0];
    }
    else {
      DAT_803dda38[2] = local_58;
    }
  }
  else if (iVar17 == 0) {
    uVar18 = FUN_80048928(uVar9,uVar15,local_54,&local_58,uVar12,(uint)DAT_803dda38,2);
  }
  else if (iVar17 == 2) {
    uVar18 = FUN_80048ae0(uVar9,uVar15,local_54,&local_58,uVar12,(uint)DAT_803dda38,2);
  }
  else {
    uVar18 = FUN_80048658(uVar18,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar9,
                          uVar15,local_54,&local_58,uVar12,(uint)DAT_803dda38,2,in_r10);
  }
  puVar14 = (undefined4 *)0x0;
  iVar8 = (uVar9 & 0xffffff) * 2;
  puVar13 = (undefined4 *)0x0;
  for (uVar11 = 0; (int)uVar11 < (int)uVar12; uVar11 = uVar11 + 1) {
    if (1 < uVar12) {
      if (iVar17 == 0) {
        uVar18 = FUN_80048928(uVar9,uVar15,local_54,&local_58,uVar11,(uint)DAT_803dda38,1);
      }
      else if (iVar17 == 2) {
        uVar18 = FUN_80048ae0(uVar9,uVar15,local_54,&local_58,uVar11,(uint)DAT_803dda38,1);
      }
      else {
        uVar18 = FUN_80048658(uVar18,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar9,
                              uVar15,local_54,&local_58,uVar11,(uint)DAT_803dda38,1,in_r10);
      }
    }
    unaff_r25 = local_54[0];
    uVar3 = local_58;
    uVar10 = local_54[0];
    if (local_58 != 0xffffffff) {
      FUN_80023d80(1);
      unaff_r24 = (undefined4 *)FUN_80023d8c(unaff_r25,DAT_803dc268);
      uVar18 = FUN_80023d80(0);
      uVar10 = uVar3;
      if (unaff_r24 == (undefined4 *)0x0) {
        DAT_803dda2c = 1;
        iVar7 = FUN_800431a4();
        if ((iVar7 == 0) || (bVar1)) {
          if (!bVar1) {
            FUN_80243e9c();
          }
        }
        else {
          FUN_80243e9c();
        }
        goto LAB_80054d94;
      }
    }
    uVar2 = (undefined2)(uVar12 << 8);
    if ((local_58 == 0xffffffff) || (unaff_r24 != (undefined4 *)0x0)) {
      if (local_58 == 0xffffffff) {
        puVar4 = (undefined4 *)
                 FUN_80046644(uVar18,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar16,
                              0,iVar8 + DAT_803dda38[uVar11],uVar10,(uint *)0x0,uVar15,0,in_r10);
        *(undefined *)((int)puVar4 + 0x49) = 1;
        if ((uVar6 & 0xff) != 0) {
          uVar6 = 0;
        }
        *(undefined2 *)((int)puVar4 + 0xe) = 1;
        uVar18 = extraout_f1_00;
      }
      else {
        uVar18 = FUN_80046644(uVar18,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar16,
                              unaff_r24,iVar8 + DAT_803dda38[uVar11],uVar10,(uint *)0x0,uVar15,0,
                              in_r10);
        puVar4 = unaff_r24;
      }
      if (local_58 != 0xffffffff) {
        FUN_80242114((uint)puVar4,unaff_r25);
      }
      *puVar4 = 0;
      if (puVar13 != (undefined4 *)0x0) {
        *puVar13 = puVar4;
      }
      unaff_r24 = puVar4;
      if (uVar11 == 0) {
        *(undefined2 *)(puVar4 + 4) = uVar2;
        puVar14 = puVar4;
      }
      else {
        *(undefined2 *)(puVar4 + 4) = 1;
      }
    }
    else {
      if (uVar11 == 0) {
        DAT_803dda2c = 1;
        iVar7 = FUN_800431a4();
        if ((iVar7 == 0) || (bVar1)) {
          if (!bVar1) {
            FUN_80243e9c();
          }
        }
        else {
          FUN_80243e9c();
        }
        goto LAB_80054d94;
      }
      *(undefined2 *)(puVar14 + 4) = uVar2;
      uVar11 = uVar12;
      puVar4 = puVar13;
    }
    puVar13 = puVar4;
  }
  puVar14[0x13] = unaff_r25;
  iVar8 = 0;
  piVar5 = DAT_803dda44;
  iVar17 = DAT_803dda3c;
  if (0 < DAT_803dda3c) {
    do {
      if (*piVar5 == -1) break;
      piVar5 = piVar5 + 4;
      iVar8 = iVar8 + 1;
      iVar17 = iVar17 + -1;
    } while (iVar17 != 0);
  }
  if (iVar8 == DAT_803dda3c) {
    DAT_803dda3c = DAT_803dda3c + 1;
  }
  DAT_803dda44[iVar8 * 4] = iVar7;
  DAT_803dda44[iVar8 * 4 + 1] = (int)puVar14;
  *(char *)(DAT_803dda44 + iVar8 * 4 + 2) = (char)uVar6;
  uVar6 = FUN_80023cec(DAT_803dda44[iVar8 * 4 + 1]);
  DAT_803dda44[iVar8 * 4 + 3] = uVar6;
  if (DAT_803dda3c < 0x2bd) {
    for (; puVar14 != (undefined4 *)0x0; puVar14 = (undefined4 *)*puVar14) {
      FUN_80053ed4((int)puVar14);
    }
    iVar7 = FUN_800431a4();
    if ((iVar7 == 0) || (bVar1)) {
      if (!bVar1) {
        FUN_80243e9c();
      }
    }
    else {
      FUN_80243e9c();
    }
  }
  else {
    iVar7 = FUN_800431a4();
    if ((iVar7 == 0) || (bVar1)) {
      if (!bVar1) {
        FUN_80243e9c();
      }
    }
    else {
      FUN_80243e9c();
    }
  }
LAB_80054d94:
  FUN_8028685c();
  return;
}

