// Function: FUN_80271bfc
// Entry: 80271bfc
// Size: 792 bytes

void FUN_80271bfc(uint param_1)

{
  byte bVar1;
  float fVar2;
  uint uVar3;
  char cVar5;
  uint uVar4;
  uint uVar6;
  float *pfVar7;
  undefined4 *puVar8;
  byte *pbVar9;
  byte *pbVar10;
  undefined4 *puVar11;
  undefined4 *puVar12;
  byte *pbVar13;
  byte *pbVar14;
  undefined2 *puVar15;
  bool bVar16;
  double dVar17;
  undefined2 local_54 [6];
  undefined2 local_48 [8];
  
  if (DAT_803bddb4 != 0) {
    FUN_80278b7c(param_1);
    uVar3 = (uint)DAT_803deeb9;
    FUN_80271afc(&DAT_803bdc30 + uVar3 * 3,&LAB_802708e8);
    FUN_80271afc(&DAT_803bdc34 + uVar3 * 3,&LAB_8027174c);
    FUN_80271afc(&DAT_803bdc38 + uVar3 * 3,&LAB_8027109c);
    DAT_803deeb9 = DAT_803deeb9 + 1 & 0x1f;
    cVar5 = FUN_802839b0();
    if (cVar5 == '\0') {
      if (DAT_803deee0 != 0 || DAT_803deedc != 0) {
        dVar17 = (double)FLOAT_803e8468;
        pfVar7 = (float *)&DAT_803bdfc4;
        uVar6 = 0;
        uVar3 = 1;
        do {
          if ((DAT_803deee0 & uVar3) != 0) {
            *pfVar7 = pfVar7[1] - pfVar7[3] * (pfVar7[1] - pfVar7[2]);
            fVar2 = pfVar7[3];
            pfVar7[3] = fVar2 - pfVar7[4];
            if ((double)(fVar2 - pfVar7[4]) <= dVar17) {
              *pfVar7 = pfVar7[1];
              bVar1 = *(byte *)(pfVar7 + 0xb);
              if (bVar1 == 2) {
                FUN_8026d828((uint)pfVar7[10]);
              }
              else if (bVar1 < 2) {
                if (bVar1 != 0) {
                  FUN_8026d9dc((uint)pfVar7[10]);
                }
              }
              else if (bVar1 < 4) {
                FUN_8026dd94((uint)pfVar7[10],0,0);
              }
              DAT_803deee0 = DAT_803deee0 & ~uVar3;
              if ((DAT_803deee0 == 0) && (DAT_803deedc == 0)) break;
            }
          }
          if ((DAT_803deedc & uVar3) != 0) {
            pfVar7[5] = pfVar7[6] - pfVar7[8] * (pfVar7[6] - pfVar7[7]);
            fVar2 = pfVar7[8];
            pfVar7[8] = fVar2 - pfVar7[9];
            if ((double)(fVar2 - pfVar7[9]) <= dVar17) {
              pfVar7[5] = pfVar7[6];
              DAT_803deedc = DAT_803deedc & ~uVar3;
              if ((DAT_803deedc == 0) && (DAT_803deee0 == 0)) break;
            }
          }
          uVar6 = uVar6 + 1;
          uVar3 = uVar3 << 1;
          pfVar7 = pfVar7 + 0xc;
        } while (uVar6 < 0x20);
      }
      uVar3 = 0;
      pbVar13 = &DAT_803deecc;
      pbVar9 = &DAT_803deebc;
      puVar11 = &DAT_803be624;
      puVar8 = &DAT_803be664;
      pbVar14 = &DAT_803deed4;
      pbVar10 = &DAT_803deec4;
      puVar12 = &DAT_803be604;
      do {
        if (*pbVar14 != 0xff) {
          uVar6 = 0;
          puVar15 = local_48;
          do {
            uVar4 = FUN_80282fbc(uVar3 & 0xff,uVar6 & 0xff,(uint)*pbVar14,(uint)*pbVar13);
            uVar6 = uVar6 + 1;
            *puVar15 = (short)uVar4;
            puVar15 = puVar15 + 1;
          } while (uVar6 < 4);
          (*(code *)*puVar11)(1,local_48,*puVar12);
        }
        if (*pbVar10 != 0xff) {
          uVar6 = 0;
          puVar15 = local_54;
          do {
            uVar4 = FUN_80283078(uVar3 & 0xff,uVar6 & 0xff,(uint)*pbVar10,(uint)*pbVar9);
            uVar6 = uVar6 + 1;
            *puVar15 = (short)uVar4;
            puVar15 = puVar15 + 1;
          } while (uVar6 < 4);
          (*(code *)*puVar8)(1,local_54,puVar12[0x10]);
        }
        uVar3 = uVar3 + 1;
        pbVar14 = pbVar14 + 1;
        pbVar13 = pbVar13 + 1;
        puVar12 = puVar12 + 1;
        puVar11 = puVar11 + 1;
        pbVar10 = pbVar10 + 1;
        pbVar9 = pbVar9 + 1;
        puVar8 = puVar8 + 1;
      } while (uVar3 < 8);
    }
    FUN_80284698();
    bVar16 = CARRY4(DAT_803deefc,param_1);
    DAT_803deefc = DAT_803deefc + param_1;
    DAT_803deef8 = DAT_803deef8 + (uint)bVar16;
  }
  return;
}

