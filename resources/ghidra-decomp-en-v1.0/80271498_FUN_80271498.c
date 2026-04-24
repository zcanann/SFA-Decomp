// Function: FUN_80271498
// Entry: 80271498
// Size: 792 bytes

void FUN_80271498(uint param_1)

{
  byte bVar1;
  float fVar2;
  uint uVar3;
  char cVar5;
  undefined2 uVar4;
  uint uVar6;
  float *pfVar7;
  code **ppcVar8;
  undefined *puVar9;
  char *pcVar10;
  code **ppcVar11;
  undefined4 *puVar12;
  undefined *puVar13;
  char *pcVar14;
  undefined2 *puVar15;
  bool bVar16;
  double dVar17;
  undefined2 local_54 [6];
  undefined2 local_48 [8];
  
  if (DAT_803bd154 != 0) {
    FUN_80278418(param_1);
    uVar3 = (uint)DAT_803de239;
    FUN_80271398(&DAT_803bcfd0 + uVar3 * 3,&LAB_80270184);
    FUN_80271398(&DAT_803bcfd4 + uVar3 * 3,&LAB_80270fe8);
    FUN_80271398(&DAT_803bcfd8 + uVar3 * 3,&LAB_80270938);
    DAT_803de239 = DAT_803de239 + 1 & 0x1f;
    cVar5 = FUN_8028324c();
    if (cVar5 == '\0') {
      if ((DAT_803de260 | DAT_803de25c) != 0) {
        dVar17 = (double)FLOAT_803e77d0;
        pfVar7 = (float *)&DAT_803bd364;
        uVar6 = 0;
        uVar3 = 1;
        do {
          if ((DAT_803de260 & uVar3) != 0) {
            *pfVar7 = pfVar7[1] - pfVar7[3] * (pfVar7[1] - pfVar7[2]);
            fVar2 = pfVar7[3];
            pfVar7[3] = fVar2 - pfVar7[4];
            if ((double)(fVar2 - pfVar7[4]) <= dVar17) {
              *pfVar7 = pfVar7[1];
              bVar1 = *(byte *)(pfVar7 + 0xb);
              if (bVar1 == 2) {
                FUN_8026d0c4(pfVar7[10]);
              }
              else if (bVar1 < 2) {
                if (bVar1 != 0) {
                  FUN_8026d278(pfVar7[10]);
                }
              }
              else if (bVar1 < 4) {
                FUN_8026d630(pfVar7[10],0,0);
              }
              DAT_803de260 = DAT_803de260 & ~uVar3;
              if ((DAT_803de260 == 0) && (DAT_803de25c == 0)) break;
            }
          }
          if ((DAT_803de25c & uVar3) != 0) {
            pfVar7[5] = pfVar7[6] - pfVar7[8] * (pfVar7[6] - pfVar7[7]);
            fVar2 = pfVar7[8];
            pfVar7[8] = fVar2 - pfVar7[9];
            if ((double)(fVar2 - pfVar7[9]) <= dVar17) {
              pfVar7[5] = pfVar7[6];
              DAT_803de25c = DAT_803de25c & ~uVar3;
              if ((DAT_803de25c == 0) && (DAT_803de260 == 0)) break;
            }
          }
          uVar6 = uVar6 + 1;
          uVar3 = uVar3 << 1;
          pfVar7 = pfVar7 + 0xc;
        } while (uVar6 < 0x20);
      }
      uVar3 = 0;
      puVar13 = &DAT_803de24c;
      puVar9 = &DAT_803de23c;
      ppcVar11 = (code **)&DAT_803bd9c4;
      ppcVar8 = (code **)&DAT_803bda04;
      pcVar14 = &DAT_803de254;
      pcVar10 = &DAT_803de244;
      puVar12 = &DAT_803bd9a4;
      do {
        if (*pcVar14 != -1) {
          uVar6 = 0;
          puVar15 = local_48;
          do {
            uVar4 = FUN_80282858(uVar3 & 0xff,uVar6 & 0xff,*pcVar14,*puVar13);
            uVar6 = uVar6 + 1;
            *puVar15 = uVar4;
            puVar15 = puVar15 + 1;
          } while (uVar6 < 4);
          (**ppcVar11)(1,local_48,*puVar12);
        }
        if (*pcVar10 != -1) {
          uVar6 = 0;
          puVar15 = local_54;
          do {
            uVar4 = FUN_80282914(uVar3 & 0xff,uVar6 & 0xff,*pcVar10,*puVar9);
            uVar6 = uVar6 + 1;
            *puVar15 = uVar4;
            puVar15 = puVar15 + 1;
          } while (uVar6 < 4);
          (**ppcVar8)(1,local_54,puVar12[0x10]);
        }
        uVar3 = uVar3 + 1;
        pcVar14 = pcVar14 + 1;
        puVar13 = puVar13 + 1;
        puVar12 = puVar12 + 1;
        ppcVar11 = ppcVar11 + 1;
        pcVar10 = pcVar10 + 1;
        puVar9 = puVar9 + 1;
        ppcVar8 = ppcVar8 + 1;
      } while (uVar3 < 8);
    }
    FUN_80283f34();
    bVar16 = CARRY4(DAT_803de27c,param_1);
    DAT_803de27c = DAT_803de27c + param_1;
    DAT_803de278 = DAT_803de278 + (uint)bVar16;
  }
  return;
}

