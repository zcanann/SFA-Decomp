// Function: FUN_802ba3ec
// Entry: 802ba3ec
// Size: 756 bytes

/* WARNING: Removing unreachable block (ram,0x802ba5b8) */

void FUN_802ba3ec(void)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint *puVar6;
  undefined4 unaff_r23;
  undefined4 unaff_r24;
  undefined4 unaff_r27;
  undefined4 unaff_r28;
  undefined4 unaff_r29;
  undefined4 unaff_r30;
  int iVar7;
  double dVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_802860c8();
  fVar2 = FLOAT_803e8234;
  iVar5 = (int)((ulonglong)uVar9 >> 0x20);
  puVar6 = (uint *)uVar9;
  puVar6[0xa5] = (uint)FLOAT_803e8234;
  puVar6[0xa1] = (uint)fVar2;
  puVar6[0xa0] = (uint)fVar2;
  *(float *)(iVar5 + 0x24) = fVar2;
  *(float *)(iVar5 + 0x28) = fVar2;
  *(float *)(iVar5 + 0x2c) = fVar2;
  *puVar6 = *puVar6 | 0x200000;
  iVar7 = *(int *)(iVar5 + 0xb8);
  iVar3 = FUN_8002b9ec();
  bVar1 = *(byte *)(iVar7 + 0xa8c);
  if (bVar1 == 4) {
    unaff_r30 = 0x4963b;
    unaff_r29 = 0x4963c;
    unaff_r28 = 0x4963d;
    unaff_r27 = 0x4963e;
    unaff_r24 = 0x8f9;
    unaff_r23 = 0x85d;
  }
  else if ((bVar1 < 4) && (bVar1 == 1)) {
    unaff_r30 = 0x1602;
    unaff_r29 = 0x454bc;
    unaff_r28 = 0x454b8;
    unaff_r27 = 0x454b9;
    unaff_r24 = 0x172;
    unaff_r23 = 0x9ed;
  }
  if ((*(char *)((int)puVar6 + 0x27a) != '\0') &&
     (puVar6[0xa8] = (uint)FLOAT_803e827c, *(short *)(iVar5 + 0xa0) != 0x13)) {
    FUN_80030334((double)FLOAT_803e8234,iVar5,0x13,0);
  }
  iVar4 = FUN_8001ffb4(unaff_r24);
  if ((((iVar4 == 0) || (iVar4 = FUN_8001ffb4(unaff_r23), iVar4 == 0)) || (iVar3 == 0)) ||
     (dVar8 = (double)FUN_80021704(iVar3 + 0x18,iVar5 + 0x18), (double)FLOAT_803e828c <= dVar8)) {
    *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) | 8;
    bVar1 = *(byte *)(iVar7 + 0xa91);
    if (bVar1 == 1) {
      dVar8 = (double)FUN_80021704(iVar3 + 0x18,iVar5 + 0x18);
      if (dVar8 < (double)FLOAT_803e8290) {
        iVar5 = FUN_8002e0b4(unaff_r30);
        if (iVar5 != 0) {
          FUN_8014c63c();
        }
        iVar5 = FUN_8002e0b4(unaff_r29);
        if (iVar5 != 0) {
          FUN_8014c63c();
        }
        *(undefined *)(iVar7 + 0xa91) = 2;
      }
    }
    else if ((bVar1 == 0) || (bVar1 < 3)) {
      if ((bVar1 == 0) ||
         (dVar8 = (double)FUN_80021704(iVar3 + 0x18,iVar5 + 0x18), (double)FLOAT_803e8240 < dVar8))
      {
        iVar5 = FUN_8002e0b4(unaff_r30);
        iVar3 = FUN_8002e0b4(unaff_r28);
        if ((iVar5 != 0) && (iVar3 != 0)) {
          FUN_8014c66c(iVar5);
        }
        iVar5 = FUN_8002e0b4(unaff_r29);
        iVar3 = FUN_8002e0b4(unaff_r27);
        if ((iVar5 != 0) && (iVar3 != 0)) {
          FUN_8014c66c(iVar5);
        }
        *(undefined *)(iVar7 + 0xa91) = 1;
      }
      else {
        iVar3 = FUN_8002208c((double)FLOAT_803e8294,(double)FLOAT_803e8284,iVar7 + 0xd08);
        if (iVar3 != 0) {
          FUN_8000bb18(iVar5,0x375);
        }
      }
    }
  }
  else {
    bVar1 = *(byte *)(iVar7 + 0xa8c);
    if (bVar1 == 4) {
      *(undefined *)(iVar7 + 0xa8d) = 9;
      FUN_800200e8(0x1db,1);
    }
    else if ((bVar1 < 4) && (bVar1 == 1)) {
      *(undefined *)(iVar7 + 0xa8d) = 0;
      FUN_800200e8(0x245,1);
      FUN_800200e8(0x27,1);
    }
    (**(code **)(*DAT_803dca54 + 0x48))(*(undefined *)(iVar7 + 0xa8d),iVar5,0xffffffff);
    FUN_80014b3c(0,0x100);
  }
  FUN_80286114(0);
  return;
}

