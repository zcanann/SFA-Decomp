// Function: FUN_8005fbc4
// Entry: 8005fbc4
// Size: 612 bytes

void FUN_8005fbc4(void)

{
  bool bVar1;
  uint uVar2;
  uint3 uVar3;
  uint3 uVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  undefined *puVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined8 uVar14;
  int local_78 [4];
  uint local_68;
  undefined auStack100 [100];
  
  uVar14 = FUN_802860dc();
  iVar6 = (int)((ulonglong)uVar14 >> 0x20);
  uVar12 = 0;
  iVar11 = 0;
  uVar10 = (uint)uVar14 & 0xff;
  if (uVar10 == 1) {
    uVar13 = *(undefined4 *)(iVar6 + 0x7c);
    uVar10 = (uint)*(ushort *)(iVar6 + 0x86);
  }
  else if (uVar10 == 2) {
    uVar13 = *(undefined4 *)(iVar6 + 0x80);
    uVar10 = (uint)*(ushort *)(iVar6 + 0x88);
  }
  else {
    uVar13 = *(undefined4 *)(iVar6 + 0x78);
    uVar10 = (uint)*(ushort *)(iVar6 + 0x84);
    iVar11 = 1;
  }
  if (uVar10 != 0) {
    uVar7 = FUN_8000f54c();
    FUN_80246eb4(uVar7,iVar6 + 0xc,auStack100);
    if (iVar11 != 0) {
      FUN_8005faf8(iVar6,auStack100);
    }
    FUN_80013a64(local_78,uVar13,uVar10 << 3,uVar10 << 3);
    bVar1 = false;
    uVar10 = local_68;
    while (local_68 = uVar10, !bVar1) {
      puVar8 = (undefined *)(local_78[0] + ((int)local_68 >> 3));
      uVar10 = local_68 + 4;
      uVar3 = CONCAT12(puVar8[2],CONCAT11(puVar8[1],*puVar8)) >> (local_68 & 7);
      uVar4 = uVar3 & 0xf;
      if (uVar4 == 3) {
        local_68 = uVar10;
        FUN_8005f920(iVar11,iVar6,uVar12,local_78);
        uVar10 = local_68;
      }
      else if (uVar4 < 3) {
        if (uVar4 == 1) {
          local_68 = uVar10;
          uVar12 = FUN_8005f558(iVar11,iVar6,local_78);
          uVar10 = local_68;
        }
        else if ((uVar3 & 0xf) != 0) {
          local_68 = uVar10;
          FUN_8005ec80(iVar11,0,iVar6,uVar12,local_78,auStack100);
          uVar10 = local_68;
        }
      }
      else if (uVar4 == 5) {
        bVar1 = true;
      }
      else if (uVar4 < 5) {
        puVar8 = (undefined *)(local_78[0] + ((int)uVar10 >> 3));
        local_68 = local_68 + 8;
        uVar4 = CONCAT12(puVar8[2],CONCAT11(puVar8[1],*puVar8)) >> (uVar10 & 7);
        uVar2 = uVar4 & 0xf;
        iVar9 = 0;
        uVar10 = local_68;
        if ((uVar4 & 0xf) != 0) {
          if ((8 < uVar2) && (uVar10 = uVar2 - 1 >> 3, 0 < (int)(uVar2 - 8))) {
            do {
              local_68 = local_68 + 0x40;
              iVar9 = iVar9 + 8;
              uVar10 = uVar10 - 1;
            } while (uVar10 != 0);
          }
          iVar5 = uVar2 - iVar9;
          uVar10 = local_68;
          if (iVar9 < (int)uVar2) {
            do {
              local_68 = local_68 + 8;
              iVar5 = iVar5 + -1;
              uVar10 = local_68;
            } while (iVar5 != 0);
          }
        }
      }
    }
  }
  FUN_80286128();
  return;
}

