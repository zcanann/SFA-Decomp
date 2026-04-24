// Function: FUN_802bb720
// Entry: 802bb720
// Size: 1468 bytes

void FUN_802bb720(void)

{
  byte bVar1;
  float fVar2;
  short sVar3;
  short *psVar4;
  int iVar5;
  undefined uVar9;
  int iVar6;
  short *psVar7;
  undefined4 uVar8;
  undefined *puVar10;
  uint uVar11;
  int iVar12;
  char cVar13;
  int iVar14;
  double dVar15;
  float local_88;
  short local_84;
  short local_82;
  short local_80;
  float local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined auStack108 [108];
  
  psVar4 = (short *)FUN_802860d4();
  iVar5 = FUN_8002b9ec();
  cVar13 = -1;
  iVar14 = *(int *)(psVar4 + 0x5c);
  *(undefined2 *)(iVar14 + 0xa86) = 5;
  *(byte *)((int)psVar4 + 0xaf) = *(byte *)((int)psVar4 + 0xaf) & 0xf7;
  *(undefined2 *)(*(int *)(psVar4 + 0x2a) + 0xb2) = 9;
  if (((&DAT_803350c4)[*(short *)(iVar14 + 0x274)] & 8) == 0) {
    if (((&DAT_803350c4)[*(short *)(iVar14 + 0x274)] & 2) == 0) {
      puVar10 = &DAT_8033509c;
    }
    else {
      puVar10 = &DAT_803350b0;
    }
    uVar9 = FUN_800353a4(psVar4,puVar10,1,*(undefined *)(iVar14 + 0xd00),iVar14 + 0xa94);
    *(undefined *)(iVar14 + 0xd00) = uVar9;
    if (*(char *)(iVar14 + 0xd00) != '\0') {
      FUN_8003a168(psVar4,iVar14 + 0x980);
      FUN_8003b310(psVar4,iVar14 + 0x980);
      goto LAB_802bbcc4;
    }
  }
  if (*(char *)(iVar14 + 0xa8a) == '\x02') {
    *(undefined *)(iVar14 + 0x25f) = 1;
    FUN_802bb4b4(psVar4,DAT_803db410,0xffffffff);
  }
  else {
    *(undefined *)(iVar14 + 0x25f) = 0;
    fVar2 = FLOAT_803e8234;
    *(float *)(iVar14 + 0x294) = FLOAT_803e8234;
    *(float *)(iVar14 + 0x284) = fVar2;
    *(float *)(iVar14 + 0x280) = fVar2;
    *(float *)(psVar4 + 0x12) = fVar2;
    *(float *)(psVar4 + 0x14) = fVar2;
    *(float *)(psVar4 + 0x16) = fVar2;
    (**(code **)(*DAT_803dcaa8 + 0x20))(psVar4,iVar14 + 4);
    FUN_802bb4b4(psVar4,DAT_803db410,0xffffffff);
  }
  if (*(char *)(iVar14 + 0xa8a) == '\0') {
    (**(code **)(*DAT_803dca60 + 0x20))(0);
  }
  else {
    (**(code **)(*DAT_803dca60 + 0x20))(1);
  }
  bVar1 = *(byte *)(iVar14 + 0xa8c);
  if ((bVar1 == 5) || ((bVar1 < 5 && (bVar1 == 0)))) {
    iVar12 = *(int *)(psVar4 + 0x5c);
    iVar6 = FUN_8002b9ec();
    if ((iVar6 == 0) ||
       ((dVar15 = (double)FUN_80021704(iVar6 + 0x18,psVar4 + 0xc), (double)FLOAT_803e8240 <= dVar15
        || (*(char *)(iVar12 + 0xa8a) != '\0')))) {
      *(undefined *)(iVar12 + 0x980) = 0;
    }
    else {
      *(undefined *)(iVar12 + 0x980) = 1;
      *(undefined4 *)(iVar12 + 0x984) = *(undefined4 *)(iVar6 + 0xc);
      *(undefined4 *)(iVar12 + 0x988) = *(undefined4 *)(iVar6 + 0x10);
      *(undefined4 *)(iVar12 + 0x98c) = *(undefined4 *)(iVar6 + 0x14);
    }
    FUN_8003b500((double)FLOAT_803e8234,psVar4,iVar14 + 0x980);
  }
  bVar1 = *(byte *)(iVar14 + 0xa8c);
  if (bVar1 != 2) {
    if (bVar1 < 2) {
      if (bVar1 != 0) {
LAB_802bb950:
        local_88 = FLOAT_803e8240;
        psVar7 = (short *)FUN_80036e58(0x13,psVar4,&local_88);
        if (((*(char *)(iVar14 + 0xa8a) != '\0') || (*(short *)(iVar14 + 0x274) != 7)) ||
           (dVar15 = (double)FUN_8002166c(iVar5 + 0x18,psVar4 + 0xc),
           (double)FLOAT_803e82b4 <= dVar15)) {
          if (*(char *)(iVar14 + 0xa8a) == '\x02') {
            if ((psVar7 == (short *)0x0) || ((*(byte *)((int)psVar7 + 0xaf) & 4) == 0)) {
              FUN_8011f3ec(0x13);
            }
            else {
              FUN_8011f3ec(0x15);
              if ((*(byte *)((int)psVar7 + 0xaf) & 1) != 0) {
                FUN_80014b3c(0,0x100);
                FUN_800200e8(0x3e3,0);
                bVar1 = *(byte *)(iVar14 + 0xa8c);
                if (bVar1 == 3) {
                  cVar13 = '\x01';
                }
                else if (bVar1 < 3) {
                  if (bVar1 == 1) {
                    cVar13 = '\0';
                  }
                }
                else if (bVar1 < 5) {
                  cVar13 = '\x02';
                }
                sVar3 = *psVar4 - *psVar7;
                if (0x8000 < sVar3) {
                  sVar3 = sVar3 + 1;
                }
                if (sVar3 < -0x8000) {
                  sVar3 = sVar3 + -1;
                }
                if (-1 < cVar13) {
                  iVar5 = cVar13 * 0x24;
                  FUN_800200e8(*(undefined2 *)(iVar5 + -0x7fccafb2),
                               (int)*(short *)(*(int *)(psVar7 + 0x26) + 0x1a));
                  uVar11 = 0;
                  if ((0x4000 < sVar3) || (sVar3 < -0x4000)) {
                    uVar11 = 1;
                  }
                  FUN_800200e8(*(undefined2 *)(iVar5 + -0x7fccafb0),(int)cVar13 ^ uVar11);
                }
                if ((sVar3 < 0x4001) && (-0x4001 < sVar3)) {
                  FUN_800200e8(0x5bb,1);
                }
                else {
                  FUN_800200e8(0x19,1);
                }
                *(undefined4 *)(iVar14 + 0x31c) = 0;
                (**(code **)(*DAT_803dca68 + 0x60))();
                (**(code **)(*DAT_803dcaac + 0x2c))();
              }
            }
          }
        }
        else if (((psVar7 != (short *)0x0) && ((*(byte *)((int)psVar7 + 0xaf) & 4) != 0)) &&
                (FUN_8011f3ec(0x14), (*(byte *)((int)psVar7 + 0xaf) & 1) != 0)) {
          uVar8 = FUN_800571e4();
          (**(code **)(*DAT_803dcaac + 0x24))(iVar5 + 0xc,0x584,uVar8,0);
          FUN_80014b3c(0,0x100);
          FUN_800200e8(0x3e3,1);
          sVar3 = *psVar4 - *psVar7;
          if (0x8000 < sVar3) {
            sVar3 = sVar3 + 1;
          }
          if (sVar3 < -0x8000) {
            sVar3 = sVar3 + -1;
          }
          if ((sVar3 < 0x4001) && (-0x4001 < sVar3)) {
            FUN_800200e8(0x5ba,1);
          }
          else {
            FUN_800200e8(0x18,1);
          }
          if (*(char *)(iVar14 + 0xa8c) == '\x03') {
            *(undefined2 *)(iVar14 + 0xa88) = 1000;
            (**(code **)(*DAT_803dca68 + 0x58))(1000,0x5d0);
          }
        }
      }
    }
    else if (bVar1 < 5) goto LAB_802bb950;
  }
  FUN_8003b310(psVar4,iVar14 + 0x980);
  local_78 = *(undefined4 *)(psVar4 + 6);
  local_74 = *(undefined4 *)(psVar4 + 8);
  local_70 = *(undefined4 *)(psVar4 + 10);
  local_84 = *psVar4;
  local_82 = psVar4[1];
  local_80 = psVar4[2];
  local_7c = FLOAT_803e8258;
  FUN_80021ee8(auStack108,&local_84);
  iVar5 = *(int *)(psVar4 + 0x32);
  FUN_800226cc((double)FLOAT_803e8234,(double)FLOAT_803e82ac,(double)FLOAT_803e82b0,auStack108,
               iVar5 + 0x20,iVar5 + 0x24,iVar5 + 0x28);
LAB_802bbcc4:
  FUN_80286120();
  return;
}

