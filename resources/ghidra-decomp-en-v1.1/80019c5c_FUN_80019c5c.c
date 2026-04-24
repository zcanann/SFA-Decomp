// Function: FUN_80019c5c
// Entry: 80019c5c
// Size: 1504 bytes

/* WARNING: Removing unreachable block (ram,0x8001a21c) */
/* WARNING: Removing unreachable block (ram,0x8001a214) */
/* WARNING: Removing unreachable block (ram,0x80019c74) */
/* WARNING: Removing unreachable block (ram,0x80019c6c) */

void FUN_80019c5c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  byte bVar2;
  byte bVar3;
  undefined4 uVar4;
  uint uVar5;
  undefined *in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined *puVar9;
  float *pfVar10;
  float *pfVar11;
  undefined *puVar12;
  int iVar13;
  double dVar14;
  undefined8 uVar15;
  double in_f30;
  double dVar16;
  double in_f31;
  double dVar17;
  double in_ps30_1;
  double in_ps31_1;
  undefined4 local_48 [12];
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  dVar14 = (double)FUN_8028683c();
  puVar8 = &DAT_8033b1a0;
  puVar9 = &DAT_8033bc40;
  iVar6 = 7;
  do {
    if (*(int *)(puVar9 + 0x44) == 2) {
      dVar14 = (double)FUN_8001ae18();
    }
    puVar9 = puVar9 + 0x4c;
    bVar1 = iVar6 != 0;
    iVar6 = iVar6 + -1;
  } while (bVar1);
  iVar6 = 0;
  puVar9 = &DAT_8033bba0;
  do {
    bVar2 = puVar9[0x24];
    uVar5 = (uint)bVar2;
    if (uVar5 != 0xff) {
      puVar12 = &DAT_8033bc40;
      if ((((DAT_8033bc8a != '\0') && (puVar12 = &DAT_8033bc8c, DAT_8033bcd6 != '\0')) &&
          (puVar12 = (undefined *)0x8033bcd8, DAT_8033bd22 != '\0')) &&
         (((puVar12 = (undefined *)0x8033bd24, DAT_8033bd6e != '\0' &&
           (puVar12 = (undefined *)0x8033bd70, DAT_8033bdba != '\0')) &&
          ((puVar12 = (undefined *)0x8033bdbc, DAT_8033be06 != '\0' &&
           ((puVar12 = (undefined *)0x8033be08, DAT_8033be52 != '\0' &&
            (puVar12 = (undefined *)0x8033be54, DAT_8033be9e != '\0')))))))) {
        puVar12 = (undefined *)0x0;
      }
      if (puVar12 != (undefined *)0x0) {
        bVar3 = puVar9[0x25];
        *(undefined4 *)(puVar12 + 0x44) = 1;
        puVar12[0x48] = bVar2;
        puVar12[0x49] = bVar3;
        puVar12[0x4a] = 1;
        puVar12[0x4b] = (char)iVar6;
        FUN_8028fde8(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,-0x7fcc56a0,
                     s_gametext__s__s_bin_802ca9f4,(&PTR_s_Animtest_802c7a1c)[uVar5],
                     (&PTR_s_English_802c7b50)[(uint)bVar3 * 2],in_r7,in_r8,in_r9,in_r10);
        uVar15 = FUN_80015994(puVar12);
        uVar5 = 1;
        in_r6 = &LAB_8001b484;
        uVar4 = FUN_8001599c(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        *(undefined4 *)(puVar12 + 0x3c) = uVar4;
        dVar14 = (double)FUN_80015994(0);
        puVar9[0x24] = 0xff;
        puVar9[0x25] = 6;
      }
    }
    puVar9 = puVar9 + 0x28;
    iVar6 = iVar6 + 1;
  } while (iVar6 < 4);
  puVar9 = &DAT_8033bc40;
  iVar6 = 7;
  do {
    if (((*(int *)(puVar9 + 0x44) == 5) || (*(int *)(puVar9 + 0x44) == 6)) &&
       (*(uint *)(puVar9 + 0x3c) != 0)) {
      dVar14 = (double)FUN_800238c4(*(uint *)(puVar9 + 0x3c));
      *(undefined4 *)(puVar9 + 0x3c) = 0;
      *(undefined4 *)(puVar9 + 0x40) = 0;
      puVar9[0x4a] = 0;
    }
    puVar9 = puVar9 + 0x4c;
    bVar1 = iVar6 != 0;
    iVar6 = iVar6 + -1;
  } while (bVar1);
  iVar7 = 8;
  pfVar10 = (float *)&DAT_8033a620;
  pfVar11 = (float *)&DAT_8033a600;
  dVar16 = (double)FLOAT_803df384;
  dVar17 = (double)FLOAT_803df39c;
  iVar6 = -0x7fcc5980;
  while( true ) {
    iVar13 = iVar6;
    pfVar10 = pfVar10 + -1;
    pfVar11 = pfVar11 + -1;
    iVar6 = iVar13 + -0xc;
    bVar1 = iVar7 == 0;
    iVar7 = iVar7 + -1;
    if (bVar1) break;
    if (dVar16 < (double)*pfVar10) {
      dVar14 = (double)*pfVar11;
      *pfVar11 = (float)(dVar14 + (double)FLOAT_803dc074);
      if (dVar17 < (double)*pfVar11) {
        *pfVar10 = (float)dVar16;
        *pfVar11 = (float)dVar16;
        dVar14 = (double)FUN_8028fde8(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,**(int **)(iVar13 + -4),&DAT_803dc034,uVar5,in_r6,in_r7,in_r8
                                      ,in_r9,in_r10);
      }
    }
  }
  if (*(int *)(DAT_803dd66c + 0x1c) == 1) {
    dVar14 = (double)*(float *)(DAT_803dd66c + 0x20);
    *(float *)(DAT_803dd66c + 0x20) = (float)(dVar14 + (double)FLOAT_803dc074);
  }
  else {
    *(float *)(DAT_803dd66c + 0x20) = FLOAT_803df384;
  }
  puVar9 = &DAT_802c7b80;
  iVar6 = 0x25;
  do {
    *(ushort *)(puVar9 + 0x1c) = *(ushort *)(puVar9 + 0x1c) & 0xfffe;
    *(ushort *)(puVar9 + 0x3c) = *(ushort *)(puVar9 + 0x3c) & 0xfffe;
    *(ushort *)(puVar9 + 0x5c) = *(ushort *)(puVar9 + 0x5c) & 0xfffe;
    *(ushort *)(puVar9 + 0x7c) = *(ushort *)(puVar9 + 0x7c) & 0xfffe;
    puVar9 = puVar9 + 0x80;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  DAT_803dd61c = 0;
  DAT_803dd62a = 0;
  DAT_803dd628 = 0;
  iVar6 = DAT_803dd648;
  while (bVar1 = iVar6 != 0, iVar6 = iVar6 + -1, bVar1) {
    switch(*puVar8) {
    case 1:
      dVar14 = (double)FUN_80016914(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      break;
    case 2:
      dVar14 = (double)FUN_800165c4(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    puVar8[1],puVar8[2],puVar8[3]);
      break;
    case 3:
      DAT_803dd624 = (undefined)puVar8[4];
      DAT_803dd626 = (undefined)puVar8[2];
      DAT_803dd627 = (undefined)puVar8[1];
      DAT_803dd625 = (undefined)puVar8[3];
      break;
    case 4:
      uVar4 = puVar8[3];
      iVar7 = puVar8[1];
      *(short *)(&DAT_802c7b98 + iVar7 * 0x20) = (short)puVar8[2];
      *(short *)(&DAT_802c7b9a + iVar7 * 0x20) = (short)uVar4;
      break;
    case 5:
      if (DAT_803dd64c != (undefined *)0x0) {
        dVar14 = (double)FUN_80015ebc();
      }
      break;
    case 6:
      dVar14 = (double)FUN_80015ebc();
      break;
    case 7:
      uVar4 = puVar8[4];
      iVar7 = puVar8[2];
      *(short *)(&DAT_802c7b98 + iVar7 * 0x20) = (short)puVar8[3];
      *(short *)(&DAT_802c7b9a + iVar7 * 0x20) = (short)uVar4;
      dVar14 = (double)FUN_80015ebc();
      break;
    case 8:
      if (puVar8[1] == 0xff) {
        DAT_803dd64c = (undefined *)0x0;
      }
      else {
        DAT_803dd64c = &DAT_802c7b80 + puVar8[1] * 0x20;
      }
      break;
    case 9:
      dVar14 = (double)(*(code *)puVar8[1])();
      break;
    case 10:
      DAT_803dd628 = (undefined2)puVar8[2];
      DAT_803dd62a = (undefined2)puVar8[1];
      break;
    case 0xb:
      DAT_803dd62a = 0;
      DAT_803dd628 = 0;
      break;
    case 0xc:
      DAT_803dd604 = puVar8[1];
      break;
    case 0xd:
      DAT_803dd608 = puVar8[2];
      DAT_803dd60c = puVar8[1];
      break;
    case 0xe:
      DAT_803dd611 = (undefined)puVar8[2];
      DAT_803dd612 = (undefined)puVar8[1];
      DAT_803dd610 = (undefined)puVar8[3];
      break;
    case 0xf:
      DAT_803dd668 = puVar8[1];
      DAT_803dd66c = &DAT_8033bba0 + DAT_803dd668 * 0x28;
      if (DAT_803dd668 == 2) {
        local_48[0] = DAT_803dc028;
        dVar14 = (double)FUN_80075534(0,0,0xa00,0x780,local_48);
        DAT_803dd61c = 0;
      }
    }
    puVar8 = puVar8 + 5;
  }
  if (DAT_803dd61c == 0) {
    FUN_8000b844(0,0x397);
  }
  DAT_803dd648 = 0;
  DAT_803dd644 = &DAT_8033a9a0;
  iVar7 = 0x94;
  iVar6 = -0x7fd37200;
  while( true ) {
    bVar1 = iVar7 == 0;
    iVar7 = iVar7 + -1;
    if (bVar1) break;
    *(undefined2 *)(iVar6 + -8) = 0;
    *(undefined2 *)(iVar6 + -6) = 0;
    iVar6 = iVar6 + -0x20;
  }
  DAT_803dd64c = (undefined *)0x0;
  FUN_80286888();
  return;
}

