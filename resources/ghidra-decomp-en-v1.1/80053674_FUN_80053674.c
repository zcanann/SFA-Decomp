// Function: FUN_80053674
// Entry: 80053674
// Size: 456 bytes

/* WARNING: Removing unreachable block (ram,0x80053814) */
/* WARNING: Removing unreachable block (ram,0x8005380c) */
/* WARNING: Removing unreachable block (ram,0x80053804) */
/* WARNING: Removing unreachable block (ram,0x80053694) */
/* WARNING: Removing unreachable block (ram,0x8005368c) */
/* WARNING: Removing unreachable block (ram,0x80053684) */

void FUN_80053674(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  byte bVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int iVar8;
  undefined4 *puVar9;
  uint uVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  
  iVar8 = 0;
  puVar9 = &DAT_8037ec60;
  do {
    uVar4 = 0;
    uVar5 = 0;
    uVar6 = 0;
    uVar7 = 1;
    uVar3 = FUN_80054e14(0x20,0x20,6,'\0',0,0,0,1,1);
    *puVar9 = uVar3;
    *(undefined *)((int)puVar9 + 0x1a) = 0;
    puVar9 = puVar9 + 7;
    iVar8 = iVar8 + 1;
  } while (iVar8 < 6);
  uVar10 = 0;
  DAT_803dda25 = 0;
  puVar9 = &DAT_8030dbe8;
  dVar14 = (double)FLOAT_803df7c8;
  dVar15 = (double)FLOAT_803df7d0;
  do {
    dVar13 = (double)(float)puVar9[1];
    iVar8 = (uint)DAT_803dda25 * 0x1c;
    (&DAT_8037ec6c)[iVar8] = 0xff;
    (&DAT_8037ec6d)[iVar8] = 0xff;
    (&DAT_8037ec6e)[iVar8] = 0xff;
    dVar12 = (double)FLOAT_803df7cc;
    dVar11 = (double)FUN_80292f04();
    bVar2 = DAT_803dda25;
    iVar8 = (uint)DAT_803dda25 * 0x1c;
    uVar1 = uVar10 & 1;
    (&DAT_8037ec60)[(uint)DAT_803dda25 * 7 + uVar1 + 4] = (float)(dVar14 / dVar11);
    *(char *)((int)&DAT_8037ec60 + uVar1 + 0x18 + iVar8) = (char)(int)(dVar15 * dVar13);
    (&DAT_8037ec7b)[iVar8] = 1;
    if (uVar1 != 0) {
      DAT_803dda25 = bVar2 + 1;
    }
    puVar9 = puVar9 + 2;
    uVar10 = uVar10 + 1;
  } while ((int)uVar10 < 6);
  (&DAT_8037ec7b)[(uint)DAT_803dda25 * 0x1c] = 0;
  uVar10 = DAT_803dda25 + 1 & 0xff;
  (&DAT_8037ec7b)[uVar10 * 0x1c] = 0;
  DAT_803dda25 = (char)(uVar10 + 1) + '\x01';
  (&DAT_8037ec7b)[(uVar10 + 1 & 0xff) * 0x1c] = 0;
  DAT_803dda20 = FUN_80054ed0(dVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x5dc,
                              uVar10,0,&DAT_8037ec7b,uVar4,uVar5,uVar6,uVar7);
  return;
}

