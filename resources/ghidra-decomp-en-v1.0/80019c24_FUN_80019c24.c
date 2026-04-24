// Function: FUN_80019c24
// Entry: 80019c24
// Size: 1504 bytes

/* WARNING: Removing unreachable block (ram,0x8001a1dc) */
/* WARNING: Removing unreachable block (ram,0x8001a1e4) */

void FUN_80019c24(void)

{
  bool bVar1;
  byte bVar2;
  byte bVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined *puVar9;
  float *pfVar10;
  float *pfVar11;
  undefined *puVar12;
  int iVar13;
  undefined4 uVar14;
  undefined8 in_f30;
  double dVar15;
  undefined8 in_f31;
  double dVar16;
  undefined4 local_48 [12];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar14 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  FUN_802860d8();
  puVar8 = &DAT_8033a540;
  puVar9 = &DAT_8033afe0;
  iVar6 = 7;
  do {
    if (*(int *)(puVar9 + 0x44) == 2) {
      FUN_8001ad64(puVar9);
    }
    puVar9 = puVar9 + 0x4c;
    bVar1 = iVar6 != 0;
    iVar6 = iVar6 + -1;
  } while (bVar1);
  iVar6 = 0;
  puVar9 = &DAT_8033af40;
  do {
    bVar2 = puVar9[0x24];
    if (bVar2 != 0xff) {
      puVar12 = &DAT_8033afe0;
      if ((((DAT_8033b02a != '\0') && (puVar12 = &DAT_8033b02c, DAT_8033b076 != '\0')) &&
          (puVar12 = (undefined *)0x8033b078, DAT_8033b0c2 != '\0')) &&
         (((puVar12 = (undefined *)0x8033b0c4, DAT_8033b10e != '\0' &&
           (puVar12 = (undefined *)0x8033b110, DAT_8033b15a != '\0')) &&
          ((puVar12 = (undefined *)0x8033b15c, DAT_8033b1a6 != '\0' &&
           ((puVar12 = (undefined *)0x8033b1a8, DAT_8033b1f2 != '\0' &&
            (puVar12 = (undefined *)0x8033b1f4, DAT_8033b23e != '\0')))))))) {
        puVar12 = (undefined *)0x0;
      }
      if (puVar12 != (undefined *)0x0) {
        bVar3 = puVar9[0x25];
        *(undefined4 *)(puVar12 + 0x44) = 1;
        puVar12[0x48] = bVar2;
        puVar12[0x49] = bVar3;
        puVar12[0x4a] = 1;
        puVar12[0x4b] = (char)iVar6;
        FUN_8028f688(&DAT_80339d00,s_gametext__s__s_bin_802c9e70,(&PTR_s_Animtest_802c729c)[bVar2],
                     (&PTR_s_English_802c73d0)[(uint)bVar3 * 2]);
        FUN_8001595c(puVar12);
        uVar4 = FUN_80015964(&DAT_80339d00,puVar12 + 0x40,1,&LAB_8001b3d0);
        *(undefined4 *)(puVar12 + 0x3c) = uVar4;
        FUN_8001595c(0);
        puVar9[0x24] = 0xff;
        puVar9[0x25] = 6;
      }
    }
    puVar9 = puVar9 + 0x28;
    iVar6 = iVar6 + 1;
  } while (iVar6 < 4);
  puVar9 = &DAT_8033afe0;
  iVar6 = 7;
  do {
    if (((*(int *)(puVar9 + 0x44) == 5) || (*(int *)(puVar9 + 0x44) == 6)) &&
       (*(int *)(puVar9 + 0x3c) != 0)) {
      FUN_80023800();
      *(undefined4 *)(puVar9 + 0x3c) = 0;
      *(undefined4 *)(puVar9 + 0x40) = 0;
      puVar9[0x4a] = 0;
    }
    puVar9 = puVar9 + 0x4c;
    bVar1 = iVar6 != 0;
    iVar6 = iVar6 + -1;
  } while (bVar1);
  iVar7 = 8;
  pfVar10 = (float *)&DAT_803399c0;
  pfVar11 = (float *)0x803399a0;
  dVar15 = (double)FLOAT_803de704;
  dVar16 = (double)FLOAT_803de71c;
  iVar6 = -0x7fcc65e0;
  while( true ) {
    iVar13 = iVar6;
    pfVar10 = pfVar10 + -1;
    pfVar11 = pfVar11 + -1;
    iVar6 = iVar13 + -0xc;
    bVar1 = iVar7 == 0;
    iVar7 = iVar7 + -1;
    if (bVar1) break;
    if ((dVar15 < (double)*pfVar10) &&
       (*pfVar11 = *pfVar11 + FLOAT_803db414, dVar16 < (double)*pfVar11)) {
      *pfVar10 = (float)dVar15;
      *pfVar11 = (float)dVar15;
      FUN_8028f688(**(undefined4 **)(iVar13 + -4),&DAT_803db3d4);
    }
  }
  if (*(int *)(DAT_803dc9ec + 0x1c) == 1) {
    *(float *)(DAT_803dc9ec + 0x20) = *(float *)(DAT_803dc9ec + 0x20) + FLOAT_803db414;
  }
  else {
    *(float *)(DAT_803dc9ec + 0x20) = FLOAT_803de704;
  }
  puVar9 = &DAT_802c7400;
  iVar6 = 0x25;
  do {
    *(ushort *)(puVar9 + 0x1c) = *(ushort *)(puVar9 + 0x1c) & 0xfffe;
    *(ushort *)(puVar9 + 0x3c) = *(ushort *)(puVar9 + 0x3c) & 0xfffe;
    *(ushort *)(puVar9 + 0x5c) = *(ushort *)(puVar9 + 0x5c) & 0xfffe;
    *(ushort *)(puVar9 + 0x7c) = *(ushort *)(puVar9 + 0x7c) & 0xfffe;
    puVar9 = puVar9 + 0x80;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  DAT_803dc99c = 0;
  DAT_803dc9aa = 0;
  DAT_803dc9a8 = 0;
  iVar6 = DAT_803dc9c8;
  while (bVar1 = iVar6 != 0, iVar6 = iVar6 + -1, bVar1) {
    switch(*puVar8) {
    case 1:
      FUN_800168dc(puVar8[1],puVar8[2]);
      break;
    case 2:
      FUN_8001658c(puVar8[1],puVar8[2],puVar8[3]);
      break;
    case 3:
      DAT_803dc9a4 = (undefined)puVar8[4];
      DAT_803dc9a5 = (undefined)puVar8[3];
      DAT_803dc9a6 = (undefined)puVar8[2];
      DAT_803dc9a7 = (undefined)puVar8[1];
      break;
    case 4:
      uVar4 = puVar8[3];
      iVar7 = puVar8[1];
      *(short *)(&DAT_802c7418 + iVar7 * 0x20) = (short)puVar8[2];
      *(short *)(&DAT_802c741a + iVar7 * 0x20) = (short)uVar4;
      break;
    case 5:
      if (DAT_803dc9cc != (undefined *)0x0) {
        puVar9 = DAT_803dc9cc + 0x7fd38c00;
        FUN_80015e84(puVar8[1],
                     ((int)puVar9 >> 5) + (uint)((int)puVar9 < 0 && ((uint)puVar9 & 0x1f) != 0));
      }
      break;
    case 6:
      FUN_80015e84(puVar8[1],puVar8[2]);
      break;
    case 7:
      uVar5 = puVar8[4];
      iVar7 = puVar8[2];
      uVar4 = puVar8[1];
      *(short *)(&DAT_802c7418 + iVar7 * 0x20) = (short)puVar8[3];
      *(short *)(&DAT_802c741a + iVar7 * 0x20) = (short)uVar5;
      FUN_80015e84(uVar4);
      break;
    case 8:
      if (puVar8[1] == 0xff) {
        DAT_803dc9cc = (undefined *)0x0;
      }
      else {
        DAT_803dc9cc = &DAT_802c7400 + puVar8[1] * 0x20;
      }
      break;
    case 9:
      (*(code *)puVar8[1])();
      break;
    case 10:
      DAT_803dc9a8 = (undefined2)puVar8[2];
      DAT_803dc9aa = (undefined2)puVar8[1];
      break;
    case 0xb:
      DAT_803dc9aa = 0;
      DAT_803dc9a8 = 0;
      break;
    case 0xc:
      DAT_803dc984 = puVar8[1];
      break;
    case 0xd:
      DAT_803dc988 = puVar8[2];
      DAT_803dc98c = puVar8[1];
      break;
    case 0xe:
      DAT_803dc990 = (undefined)puVar8[3];
      DAT_803dc991 = (undefined)puVar8[2];
      DAT_803dc992 = (undefined)puVar8[1];
      break;
    case 0xf:
      DAT_803dc9e8 = puVar8[1];
      DAT_803dc9ec = &DAT_8033af40 + DAT_803dc9e8 * 0x28;
      if (DAT_803dc9e8 == 2) {
        local_48[0] = DAT_803db3c8;
        FUN_800753b8(0,0,0xa00,0x780,local_48);
        DAT_803dc99c = 0;
      }
    }
    puVar8 = puVar8 + 5;
  }
  if (DAT_803dc99c == 0) {
    FUN_8000b824(0,0x397);
  }
  DAT_803dc9c8 = 0;
  DAT_803dc9c4 = &DAT_80339d40;
  iVar7 = 0x94;
  iVar6 = -0x7fd37980;
  while( true ) {
    bVar1 = iVar7 == 0;
    iVar7 = iVar7 + -1;
    if (bVar1) break;
    *(undefined2 *)(iVar6 + -8) = 0;
    *(undefined2 *)(iVar6 + -6) = 0;
    iVar6 = iVar6 + -0x20;
  }
  DAT_803dc9cc = (undefined *)0x0;
  __psq_l0(auStack8,uVar14);
  __psq_l1(auStack8,uVar14);
  __psq_l0(auStack24,uVar14);
  __psq_l1(auStack24,uVar14);
  FUN_80286124();
  return;
}

