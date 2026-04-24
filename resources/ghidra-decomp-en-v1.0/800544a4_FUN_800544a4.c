// Function: FUN_800544a4
// Entry: 800544a4
// Size: 1912 bytes

/* WARNING: Removing unreachable block (ram,0x80054654) */
/* WARNING: Removing unreachable block (ram,0x800546a0) */

void FUN_800544a4(void)

{
  bool bVar1;
  undefined2 uVar2;
  int iVar3;
  undefined4 *puVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  uint uVar10;
  undefined4 *puVar11;
  uint uVar12;
  undefined4 *unaff_r24;
  undefined4 *puVar13;
  int unaff_r25;
  uint uVar14;
  undefined4 uVar15;
  uint uVar16;
  undefined4 uVar17;
  int iVar18;
  ulonglong uVar19;
  int local_58;
  int local_54 [21];
  
  uVar19 = FUN_802860ac();
  iVar6 = (int)(uVar19 >> 0x20);
  uVar16 = (uint)uVar19;
  uVar17 = 1;
  if ((((longlong)uVar19 < 0) && ((-iVar6 & 0x8000U) != 0)) && ((-iVar6 & 0x7fffU) == 0x82e)) {
    FUN_8007d6dc(&DAT_803db60c);
  }
  iVar7 = 0;
  piVar5 = DAT_803dcdc4;
  iVar18 = DAT_803dcdbc;
  if (0 < DAT_803dcdbc) {
    do {
      if (iVar6 == *piVar5) {
        puVar13 = (undefined4 *)DAT_803dcdc4[iVar7 * 4 + 1];
        *(short *)((int)puVar13 + 0xe) = *(short *)((int)puVar13 + 0xe) + 1;
        if (((uVar19 & 0xff) != 0) && (*(char *)(DAT_803dcdc4 + iVar7 * 4 + 2) != '\0')) {
          puVar13 = (undefined4 *)(iVar7 + 1);
        }
        goto LAB_80054c18;
      }
      piVar5 = piVar5 + 4;
      iVar7 = iVar7 + 1;
      iVar18 = iVar18 + -1;
    } while (iVar18 != 0);
  }
  iVar18 = FUN_800430ac(0);
  bVar1 = iVar18 == 0;
  if (!bVar1) {
    uVar17 = FUN_8024377c();
  }
  if ((longlong)uVar19 < 0) {
    uVar8 = -iVar6;
  }
  else if (((longlong)uVar19 < 0xbb800000000) ||
          (uVar8 = (uint)*(ushort *)(DAT_803dcdc0 + iVar6 * 2), uVar8 == 0)) {
    uVar8 = (uint)*(ushort *)(DAT_803dcdc0 + iVar6 * 2);
  }
  else {
    uVar8 = uVar8 + 1;
  }
  uVar14 = uVar8 & 0xffff;
  if ((uVar8 & 0x8000) == 0) {
    if ((longlong)uVar19 < 0xbb800000000) {
      iVar18 = 0;
      uVar15 = 0x23;
    }
    else {
      iVar18 = 2;
      uVar15 = 0x4f;
    }
  }
  else {
    iVar18 = 1;
    uVar15 = 0x20;
    uVar14 = uVar8 & 0x7fff;
  }
  if ((&DAT_8037e0a8)[iVar18] <= (int)uVar14) {
    uVar14 = 0;
  }
  iVar7 = 0;
  DAT_8037e0b4 = (int *)FUN_800436e4(0x24);
  for (piVar5 = DAT_8037e0b4; *piVar5 != -1; piVar5 = piVar5 + 1) {
    iVar7 = iVar7 + 1;
  }
  DAT_8037e0a8 = iVar7 + -1;
  iVar7 = 0;
  DAT_8037e0b8 = (int *)FUN_800436e4(0x21);
  for (piVar5 = DAT_8037e0b8; *piVar5 != -1; piVar5 = piVar5 + 1) {
    iVar7 = iVar7 + 1;
  }
  DAT_8037e0ac = iVar7 + -1;
  uVar8 = *(uint *)((int)(&DAT_8037e0b4)[iVar18] + uVar14 * 4);
  uVar12 = uVar8 >> 0x18 & 0x3f;
  if (uVar12 == 1) {
    if (iVar18 == 0) {
      FUN_800487ac(uVar8,uVar14,local_54,&local_58,1,0,0);
    }
    else if (iVar18 == 2) {
      FUN_80048964(uVar8,uVar14,local_54,&local_58,1,0,0);
    }
    else {
      FUN_800484dc(uVar8,uVar14,local_54,&local_58,1,0,0);
    }
    *DAT_803dcdb8 = 0;
    DAT_803dcdb8[1] = local_54[0];
    if (local_58 == -1) {
      DAT_803dcdb8[2] = local_54[0];
    }
    else {
      DAT_803dcdb8[2] = local_58;
    }
  }
  else if (iVar18 == 0) {
    FUN_800487ac(uVar8,uVar14,local_54,&local_58,uVar12,DAT_803dcdb8,2);
  }
  else if (iVar18 == 2) {
    FUN_80048964(uVar8,uVar14,local_54,&local_58,uVar12,DAT_803dcdb8,2);
  }
  else {
    FUN_800484dc(uVar8,uVar14,local_54,&local_58,uVar12,DAT_803dcdb8,2);
  }
  puVar13 = (undefined4 *)0x0;
  iVar7 = (uVar8 & 0xffffff) * 2;
  puVar11 = (undefined4 *)0x0;
  for (uVar10 = 0; (int)uVar10 < (int)uVar12; uVar10 = uVar10 + 1) {
    if (1 < uVar12) {
      if (iVar18 == 0) {
        FUN_800487ac(uVar8,uVar14,local_54,&local_58,uVar10,DAT_803dcdb8,1);
      }
      else if (iVar18 == 2) {
        FUN_80048964(uVar8,uVar14,local_54,&local_58,uVar10,DAT_803dcdb8,1);
      }
      else {
        FUN_800484dc(uVar8,uVar14,local_54,&local_58,uVar10,DAT_803dcdb8,1);
      }
    }
    unaff_r25 = local_54[0];
    iVar3 = local_58;
    iVar9 = local_54[0];
    if (local_58 != -1) {
      FUN_80023cbc(1);
      unaff_r24 = (undefined4 *)FUN_80023cc8(unaff_r25,DAT_803db608,0);
      FUN_80023cbc(0);
      iVar9 = iVar3;
      if (unaff_r24 == (undefined4 *)0x0) {
        DAT_803dcdac = 1;
        iVar6 = FUN_800430ac(0);
        if ((iVar6 == 0) || (bVar1)) {
          if (!bVar1) {
            FUN_802437a4(uVar17);
          }
        }
        else {
          FUN_802437a4(uVar17);
        }
        if ((uVar16 & 0xff) == 0) {
          puVar13 = (undefined4 *)DAT_803dcdc4[1];
        }
        else {
          puVar13 = (undefined4 *)0x1;
        }
        goto LAB_80054c18;
      }
    }
    uVar2 = (undefined2)(uVar12 << 8);
    if ((local_58 == -1) || (unaff_r24 != (undefined4 *)0x0)) {
      if (local_58 == -1) {
        puVar4 = (undefined4 *)FUN_800464c8(uVar15,0,iVar7 + DAT_803dcdb8[uVar10],iVar9,0,uVar14,0);
        *(undefined *)((int)puVar4 + 0x49) = 1;
        if ((uVar16 & 0xff) != 0) {
          uVar16 = 0;
        }
        *(undefined2 *)((int)puVar4 + 0xe) = 1;
      }
      else {
        FUN_800464c8(uVar15,unaff_r24,iVar7 + DAT_803dcdb8[uVar10],iVar9,0,uVar14,0);
        puVar4 = unaff_r24;
      }
      if (local_58 != -1) {
        FUN_80241a1c(puVar4,unaff_r25);
      }
      *puVar4 = 0;
      if (puVar11 != (undefined4 *)0x0) {
        *puVar11 = puVar4;
      }
      unaff_r24 = puVar4;
      if (uVar10 == 0) {
        *(undefined2 *)(puVar4 + 4) = uVar2;
        puVar13 = puVar4;
      }
      else {
        *(undefined2 *)(puVar4 + 4) = 1;
      }
    }
    else {
      if (uVar10 == 0) {
        DAT_803dcdac = 1;
        iVar6 = FUN_800430ac(0);
        if ((iVar6 == 0) || (bVar1)) {
          if (!bVar1) {
            FUN_802437a4(uVar17);
          }
        }
        else {
          FUN_802437a4(uVar17);
        }
        if ((uVar16 & 0xff) == 0) {
          puVar13 = (undefined4 *)DAT_803dcdc4[1];
        }
        else {
          puVar13 = (undefined4 *)0x1;
        }
        goto LAB_80054c18;
      }
      *(undefined2 *)(puVar13 + 4) = uVar2;
      uVar10 = uVar12;
      puVar4 = puVar11;
    }
    puVar11 = puVar4;
  }
  puVar13[0x13] = unaff_r25;
  iVar7 = 0;
  piVar5 = DAT_803dcdc4;
  iVar18 = DAT_803dcdbc;
  if (0 < DAT_803dcdbc) {
    do {
      if (*piVar5 == -1) break;
      piVar5 = piVar5 + 4;
      iVar7 = iVar7 + 1;
      iVar18 = iVar18 + -1;
    } while (iVar18 != 0);
  }
  if (iVar7 == DAT_803dcdbc) {
    DAT_803dcdbc = DAT_803dcdbc + 1;
  }
  DAT_803dcdc4[iVar7 * 4] = iVar6;
  DAT_803dcdc4[iVar7 * 4 + 1] = (int)puVar13;
  *(char *)(DAT_803dcdc4 + iVar7 * 4 + 2) = (char)uVar16;
  iVar6 = FUN_80023c28(DAT_803dcdc4[iVar7 * 4 + 1]);
  DAT_803dcdc4[iVar7 * 4 + 3] = iVar6;
  puVar11 = puVar13;
  if (DAT_803dcdbc < 0x2bd) {
    for (; puVar11 != (undefined4 *)0x0; puVar11 = (undefined4 *)*puVar11) {
      FUN_80053d58(puVar11);
    }
    iVar6 = FUN_800430ac(0);
    if ((iVar6 == 0) || (bVar1)) {
      if (!bVar1) {
        FUN_802437a4(uVar17);
      }
    }
    else {
      FUN_802437a4(uVar17);
    }
    if ((uVar16 & 0xff) != 0) {
      puVar13 = (undefined4 *)(iVar7 + 1);
    }
  }
  else {
    iVar6 = FUN_800430ac(0);
    if ((iVar6 == 0) || (bVar1)) {
      if (!bVar1) {
        FUN_802437a4(uVar17);
      }
    }
    else {
      FUN_802437a4(uVar17);
    }
    if ((uVar16 & 0xff) == 0) {
      puVar13 = (undefined4 *)DAT_803dcdc4[1];
    }
    else {
      puVar13 = (undefined4 *)0x1;
    }
  }
LAB_80054c18:
  FUN_802860f8(puVar13);
  return;
}

