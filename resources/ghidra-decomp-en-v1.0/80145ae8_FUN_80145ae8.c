// Function: FUN_80145ae8
// Entry: 80145ae8
// Size: 1648 bytes

void FUN_80145ae8(void)

{
  undefined2 uVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  char cVar11;
  int iVar9;
  undefined4 uVar10;
  byte bVar12;
  uint uVar13;
  int iVar14;
  char local_38 [4];
  char local_34 [4];
  undefined4 local_30;
  
  iVar7 = FUN_802860d0();
  iVar14 = *(int *)(iVar7 + 0xb8);
  bVar2 = false;
  bVar3 = false;
  bVar4 = false;
  bVar5 = false;
  local_30 = DAT_803e23c8;
  iVar8 = FUN_8001ffb4(0x4e4);
  if (iVar8 == 0) {
    uVar13 = 0xffffffff;
  }
  else {
    if ((*(uint *)(iVar14 + 0x54) & 0x10) != 0) {
      *(undefined *)(iVar14 + 0xb) = 0;
    }
    uVar13 = *(byte *)(iVar14 + 0xb) | 9;
    cVar11 = *(char *)(iVar14 + 8);
    if (((cVar11 == '\b') || (cVar11 == '\r')) ||
       ((cVar11 == '\x0e' && (*(char *)(iVar14 + 10) == '\x01')))) {
      uVar13 = *(byte *)(iVar14 + 0xb) | 0x19;
      bVar3 = true;
    }
    else {
      iVar8 = FUN_80138fa8((double)FLOAT_803e2524,*(undefined4 *)(iVar14 + 4),1);
      if (iVar8 != 0) {
        bVar3 = true;
        bVar5 = true;
      }
    }
    if (*(char *)(iVar14 + 0xb) != '\0') {
      for (bVar12 = 0; bVar12 < *(byte *)(iVar14 + 0x798); bVar12 = bVar12 + 1) {
        iVar8 = iVar14 + (uint)bVar12 * 8;
        cVar11 = *(char *)(iVar8 + 0x74c);
        if (cVar11 == '\0') {
          if (*(short *)(*(int *)(iVar8 + 0x748) + 0x46) == 0x6a) {
            bVar4 = true;
          }
          bVar3 = true;
        }
        else if (cVar11 == '\x01') {
          bVar2 = true;
        }
      }
    }
    if (((*(uint *)(iVar14 + 0x54) & 0x10) == 0) && (iVar8 = FUN_8001ffb4(0x3f8), iVar8 != 0)) {
      FUN_8002b9ec();
      iVar8 = FUN_80296240();
      if ((iVar8 != 0) &&
         ((iVar8 = FUN_8001ffb4(0xd00), iVar8 == 0 &&
          (iVar8 = FUN_80296448(*(undefined4 *)(iVar14 + 4)), iVar8 == 0)))) {
        uVar13 = uVar13 | 0x20;
      }
    }
    iVar8 = FUN_8001ffb4(0xdd);
    if (iVar8 == 0) {
      uVar13 = uVar13 & 0xfffffffe;
    }
    iVar8 = FUN_8001ffb4(0x9e);
    if (iVar8 == 0) {
      uVar13 = uVar13 & 0xfffffffb;
    }
    iVar8 = FUN_8001ffb4(0x245);
    if (iVar8 == 0) {
      uVar13 = uVar13 & 0xffffffef;
    }
    *(undefined *)(iVar14 + 0xb) = 0;
    if ((bVar2) && ((*(uint *)(iVar14 + 0x54) & 0x200) == 0)) {
      *(float *)(iVar14 + 0x7b4) = FLOAT_803e24f8;
      if ((*(int *)(iVar14 + 0x7b0) == 0) && (cVar11 = FUN_8002e04c(), cVar11 != '\0')) {
        iVar8 = FUN_800221a0(0,1);
        uVar1 = *(undefined2 *)((int)&local_30 + iVar8 * 2);
        iVar8 = *(int *)(iVar7 + 0xb8);
        if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(iVar7 + 0xa0) || (*(short *)(iVar7 + 0xa0) < 0x29)) &&
            (iVar9 = FUN_8000b578(iVar7,0x10), iVar9 == 0)))) {
          FUN_800393f8(iVar7,iVar8 + 0x3a8,uVar1,0x500,0xffffffff,0);
        }
        uVar10 = FUN_8002bdf4(0x20,0x17c);
        local_34[0] = -1;
        local_34[1] = -1;
        local_34[2] = -1;
        if (*(int *)(iVar14 + 0x7a8) != 0) {
          local_34[*(byte *)(iVar14 + 0x7bc) >> 6] = '\x01';
        }
        if (*(int *)(iVar14 + 0x7b0) != 0) {
          local_34[*(byte *)(iVar14 + 0x7bc) >> 4 & 3] = '\x01';
        }
        if (*(int *)(iVar14 + 0x7b8) != 0) {
          local_34[*(byte *)(iVar14 + 0x7bc) >> 2 & 3] = '\x01';
        }
        if (local_34[0] == -1) {
          uVar6 = 0;
        }
        else if (local_34[1] == -1) {
          uVar6 = 1;
        }
        else if (local_34[2] == -1) {
          uVar6 = 2;
        }
        else if (local_34[3] == -1) {
          uVar6 = 3;
        }
        else {
          uVar6 = 0xffffffff;
        }
        *(byte *)(iVar14 + 0x7bc) =
             (byte)((uVar6 & 0xff) << 4) & 0x30 | *(byte *)(iVar14 + 0x7bc) & 0xcf;
        uVar10 = FUN_8002df90(uVar10,4,0xffffffff,0xffffffff,*(undefined4 *)(iVar7 + 0x30));
        *(undefined4 *)(iVar14 + 0x7b0) = uVar10;
        FUN_80037d2c(iVar7,*(undefined4 *)(iVar14 + 0x7b0),*(byte *)(iVar14 + 0x7bc) >> 4 & 3);
      }
    }
    else if ((*(int *)(iVar14 + 0x7b0) != 0) &&
            (*(float *)(iVar14 + 0x7b4) = *(float *)(iVar14 + 0x7b4) - FLOAT_803db414,
            *(float *)(iVar14 + 0x7b4) <= FLOAT_803e23dc)) {
      FUN_801389e0(iVar7,iVar14,iVar14 + 0x7b0);
    }
    if ((bVar3) && ((*(uint *)(iVar14 + 0x54) & 0x200) == 0)) {
      *(float *)(iVar14 + 0x7ac) = FLOAT_803e24f8;
      if ((*(int *)(iVar14 + 0x7a8) == 0) && (cVar11 = FUN_8002e04c(), cVar11 != '\0')) {
        iVar8 = FUN_800221a0(0,3);
        if (iVar8 == 0) {
          if (bVar4) {
            iVar8 = *(int *)(iVar7 + 0xb8);
            if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
               (((0x2f < *(short *)(iVar7 + 0xa0) || (*(short *)(iVar7 + 0xa0) < 0x29)) &&
                (iVar9 = FUN_8000b578(iVar7,0x10), iVar9 == 0)))) {
              FUN_800393f8(iVar7,iVar8 + 0x3a8,0x359,0x500,0xffffffff,0);
            }
          }
          else if ((((bVar5) &&
                    (iVar8 = *(int *)(iVar7 + 0xb8), (*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0)) &&
                   ((0x2f < *(short *)(iVar7 + 0xa0) || (*(short *)(iVar7 + 0xa0) < 0x29)))) &&
                  (iVar9 = FUN_8000b578(iVar7,0x10), iVar9 == 0)) {
            FUN_800393f8(iVar7,iVar8 + 0x3a8,0x358,0x500,0xffffffff,0);
          }
        }
        uVar10 = FUN_8002bdf4(0x20,0x175);
        local_38[0] = -1;
        local_38[1] = -1;
        local_38[2] = -1;
        if (*(int *)(iVar14 + 0x7a8) != 0) {
          local_38[*(byte *)(iVar14 + 0x7bc) >> 6] = '\x01';
        }
        if (*(int *)(iVar14 + 0x7b0) != 0) {
          local_38[*(byte *)(iVar14 + 0x7bc) >> 4 & 3] = '\x01';
        }
        if (*(int *)(iVar14 + 0x7b8) != 0) {
          local_38[*(byte *)(iVar14 + 0x7bc) >> 2 & 3] = '\x01';
        }
        if (local_38[0] == -1) {
          uVar6 = 0;
        }
        else if (local_38[1] == -1) {
          uVar6 = 1;
        }
        else if (local_38[2] == -1) {
          uVar6 = 2;
        }
        else if (local_38[3] == -1) {
          uVar6 = 3;
        }
        else {
          uVar6 = 0xffffffff;
        }
        *(byte *)(iVar14 + 0x7bc) = (byte)((uVar6 & 0xff) << 6) | *(byte *)(iVar14 + 0x7bc) & 0x3f;
        uVar10 = FUN_8002df90(uVar10,4,0xffffffff,0xffffffff,*(undefined4 *)(iVar7 + 0x30));
        *(undefined4 *)(iVar14 + 0x7a8) = uVar10;
        FUN_80037d2c(iVar7,*(undefined4 *)(iVar14 + 0x7a8),*(byte *)(iVar14 + 0x7bc) >> 6);
      }
    }
    else if ((*(int *)(iVar14 + 0x7a8) != 0) &&
            (*(float *)(iVar14 + 0x7ac) = *(float *)(iVar14 + 0x7ac) - FLOAT_803db414,
            *(float *)(iVar14 + 0x7ac) <= FLOAT_803e23dc)) {
      FUN_801389e0(iVar7,iVar14,iVar14 + 0x7a8);
    }
  }
  FUN_8028611c(uVar13);
  return;
}

