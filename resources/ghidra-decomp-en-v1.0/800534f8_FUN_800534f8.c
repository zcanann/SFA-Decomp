// Function: FUN_800534f8
// Entry: 800534f8
// Size: 456 bytes

/* WARNING: Removing unreachable block (ram,0x80053690) */
/* WARNING: Removing unreachable block (ram,0x80053688) */
/* WARNING: Removing unreachable block (ram,0x80053698) */

void FUN_800534f8(void)

{
  uint uVar1;
  byte bVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 *puVar5;
  float *pfVar6;
  uint uVar7;
  undefined4 uVar8;
  double dVar9;
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
  iVar4 = 0;
  puVar5 = &DAT_8037e000;
  do {
    uVar3 = FUN_80054c98(0x20,0x20,6,0,0,0,0,1,1);
    *puVar5 = uVar3;
    *(undefined *)((int)puVar5 + 0x1a) = 0;
    puVar5 = puVar5 + 7;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 6);
  uVar7 = 0;
  DAT_803dcda5 = 0;
  pfVar6 = (float *)&DAT_8030d028;
  dVar11 = (double)FLOAT_803deb48;
  dVar12 = (double)FLOAT_803deb50;
  do {
    dVar10 = (double)pfVar6[1];
    iVar4 = (uint)DAT_803dcda5 * 0x1c;
    (&DAT_8037e00c)[iVar4] = 0xff;
    (&DAT_8037e00d)[iVar4] = 0xff;
    (&DAT_8037e00e)[iVar4] = 0xff;
    dVar9 = (double)FUN_802927a4((double)*pfVar6,(double)FLOAT_803deb4c);
    bVar2 = DAT_803dcda5;
    iVar4 = (uint)DAT_803dcda5 * 0x1c;
    uVar1 = uVar7 & 1;
    (&DAT_8037e000)[(uint)DAT_803dcda5 * 7 + uVar1 + 4] = (float)(dVar11 / dVar9);
    *(char *)((int)&DAT_8037e000 + uVar1 + 0x18 + iVar4) = (char)(int)(dVar12 * dVar10);
    (&DAT_8037e01b)[iVar4] = 1;
    if (uVar1 != 0) {
      DAT_803dcda5 = bVar2 + 1;
    }
    pfVar6 = pfVar6 + 2;
    uVar7 = uVar7 + 1;
  } while ((int)uVar7 < 6);
  (&DAT_8037e01b)[(uint)DAT_803dcda5 * 0x1c] = 0;
  uVar7 = DAT_803dcda5 + 1 & 0xff;
  (&DAT_8037e01b)[uVar7 * 0x1c] = 0;
  uVar7 = uVar7 + 1 & 0xff;
  DAT_803dcda5 = (char)uVar7 + '\x01';
  (&DAT_8037e01b)[uVar7 * 0x1c] = 0;
  DAT_803dcda0 = FUN_80054d54(0x5dc);
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  return;
}

