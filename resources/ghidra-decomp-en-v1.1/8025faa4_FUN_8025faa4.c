// Function: FUN_8025faa4
// Entry: 8025faa4
// Size: 2904 bytes

undefined4 FUN_8025faa4(int param_1,uint *param_2)

{
  uint *puVar1;
  uint *puVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint local_7c;
  uint local_78;
  uint local_74;
  uint local_70;
  uint local_6c;
  
  iVar8 = param_1 * 0x110;
  puVar2 = (uint *)(&DAT_803afec0)[param_1 * 0x44];
  puVar1 = (uint *)((int)puVar2 + 0x2fU & 0xffffffe0);
  iVar3 = FUN_802473cc();
  DAT_803dd268 = iVar3 * 0x41c64e6d + 0x3039;
  uVar10 = DAT_803dd268 >> 0x10 & 0x7000 | 0x7fec8000;
  uVar4 = FUN_8025f9e0();
  iVar3 = FUN_8025f89c(param_1,uVar10,(byte *)&local_7c,uVar4,0);
  if (iVar3 < 0) {
    uVar5 = 0xfffffffd;
  }
  else {
    uVar7 = uVar4 * 8 + 1;
    uVar6 = 0;
    if (uVar7 != 0) {
      if ((8 < uVar7) && (uVar11 = uVar4 & 0x1fffffff, uVar4 * 8 != 7)) {
        do {
          uVar10 = uVar10 >> 1 |
                   (~(uVar10 >> 0x17 ^ uVar10 >> 0xf ^ uVar10 ^ uVar10 >> 7) & 1) << 0x1e;
          uVar10 = uVar10 >> 1 |
                   (~(uVar10 >> 0x17 ^ uVar10 >> 0xf ^ uVar10 ^ uVar10 >> 7) & 1) << 0x1e;
          uVar10 = uVar10 >> 1 |
                   (~(uVar10 >> 0x17 ^ uVar10 >> 0xf ^ uVar10 ^ uVar10 >> 7) & 1) << 0x1e;
          uVar10 = uVar10 >> 1 |
                   (~(uVar10 >> 0x17 ^ uVar10 >> 0xf ^ uVar10 ^ uVar10 >> 7) & 1) << 0x1e;
          uVar10 = uVar10 >> 1 |
                   (~(uVar10 >> 0x17 ^ uVar10 >> 0xf ^ uVar10 ^ uVar10 >> 7) & 1) << 0x1e;
          uVar10 = uVar10 >> 1 |
                   (~(uVar10 >> 0x17 ^ uVar10 >> 0xf ^ uVar10 ^ uVar10 >> 7) & 1) << 0x1e;
          uVar10 = uVar10 >> 1 |
                   (~(uVar10 >> 0x17 ^ uVar10 >> 0xf ^ uVar10 ^ uVar10 >> 7) & 1) << 0x1e;
          uVar10 = uVar10 >> 1 |
                   (~(uVar10 >> 0x17 ^ uVar10 >> 0xf ^ uVar10 ^ uVar10 >> 7) & 1) << 0x1e;
          uVar6 = uVar6 + 8;
          uVar11 = uVar11 - 1;
        } while (uVar11 != 0);
      }
      iVar3 = uVar7 - uVar6;
      if (uVar6 < uVar7) {
        do {
          uVar10 = uVar10 >> 1 |
                   (~(uVar10 >> 0x17 ^ uVar10 >> 0xf ^ uVar10 ^ uVar10 >> 7) & 1) << 0x1e;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
    }
    *(uint *)(&DAT_803afe6c + iVar8) =
         uVar10 | ~(uVar10 >> 0x17 ^ uVar10 >> 0xf ^ uVar10 ^ uVar10 >> 7) << 0x1f;
    uVar10 = FUN_8025f730(*(uint *)(&DAT_803afe6c + iVar8));
    *(uint *)(&DAT_803afe6c + iVar8) = uVar10;
    uVar10 = FUN_8025f9e0();
    iVar3 = FUN_8025f89c(param_1,0,(byte *)&local_7c,uVar10 + 0x14,1);
    if (iVar3 < 0) {
      uVar5 = 0xfffffffd;
    }
    else {
      uVar4 = *(uint *)(&DAT_803afe6c + iVar8);
      iVar3 = 4;
      uVar6 = local_7c ^ uVar4;
      do {
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      *(uint *)(&DAT_803afe6c + iVar8) =
           uVar4 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1f;
      iVar3 = 4;
      uVar4 = *(uint *)(&DAT_803afe6c + iVar8);
      uVar7 = local_78 ^ uVar4;
      do {
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      *(uint *)(&DAT_803afe6c + iVar8) =
           uVar4 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1f;
      iVar3 = 4;
      uVar4 = *(uint *)(&DAT_803afe6c + iVar8);
      uVar11 = local_74 ^ uVar4;
      do {
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      *(uint *)(&DAT_803afe6c + iVar8) =
           uVar4 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1f;
      iVar3 = 4;
      uVar4 = *(uint *)(&DAT_803afe6c + iVar8);
      local_70 = local_70 ^ uVar4;
      do {
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      *(uint *)(&DAT_803afe6c + iVar8) =
           uVar4 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1f;
      uVar10 = uVar10 * 8;
      uVar9 = *(uint *)(&DAT_803afe6c + iVar8);
      uVar4 = 0;
      local_6c = local_6c ^ uVar9;
      if (uVar10 != 0) {
        if ((8 < uVar10) && (uVar12 = uVar10 - 1 >> 3, uVar10 != 8)) {
          do {
            uVar9 = uVar9 << 1 | ~(uVar9 << 0x17 ^ uVar9 << 0xf ^ uVar9 ^ uVar9 << 7) >> 0x1e & 2;
            uVar9 = uVar9 << 1 | ~(uVar9 << 0x17 ^ uVar9 << 0xf ^ uVar9 ^ uVar9 << 7) >> 0x1e & 2;
            uVar9 = uVar9 << 1 | ~(uVar9 << 0x17 ^ uVar9 << 0xf ^ uVar9 ^ uVar9 << 7) >> 0x1e & 2;
            uVar9 = uVar9 << 1 | ~(uVar9 << 0x17 ^ uVar9 << 0xf ^ uVar9 ^ uVar9 << 7) >> 0x1e & 2;
            uVar9 = uVar9 << 1 | ~(uVar9 << 0x17 ^ uVar9 << 0xf ^ uVar9 ^ uVar9 << 7) >> 0x1e & 2;
            uVar9 = uVar9 << 1 | ~(uVar9 << 0x17 ^ uVar9 << 0xf ^ uVar9 ^ uVar9 << 7) >> 0x1e & 2;
            uVar9 = uVar9 << 1 | ~(uVar9 << 0x17 ^ uVar9 << 0xf ^ uVar9 ^ uVar9 << 7) >> 0x1e & 2;
            uVar9 = uVar9 << 1 | ~(uVar9 << 0x17 ^ uVar9 << 0xf ^ uVar9 ^ uVar9 << 7) >> 0x1e & 2;
            uVar4 = uVar4 + 8;
            uVar12 = uVar12 - 1;
          } while (uVar12 != 0);
        }
        iVar3 = uVar10 - uVar4;
        if (uVar4 < uVar10) {
          do {
            uVar9 = uVar9 << 1 | ~(uVar9 << 0x17 ^ uVar9 << 0xf ^ uVar9 ^ uVar9 << 7) >> 0x1e & 2;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
      }
      *(uint *)(&DAT_803afe6c + iVar8) =
           uVar9 | ~(uVar9 << 0x17 ^ uVar9 << 0xf ^ uVar9 ^ uVar9 << 7) >> 0x1f;
      iVar3 = 4;
      uVar10 = 0;
      uVar4 = *(uint *)(&DAT_803afe6c + iVar8);
      do {
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
        uVar10 = uVar10 + 8;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      iVar3 = 0x21 - uVar10;
      if (uVar10 < 0x21) {
        do {
          uVar4 = uVar4 << 1 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1e & 2;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
      *(uint *)(&DAT_803afe6c + iVar8) =
           uVar4 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1f;
      *puVar1 = local_70;
      puVar1[1] = local_6c;
      *puVar2 = (uint)puVar1;
      puVar2[1] = 8;
      puVar2[3] = (uint)(puVar1 + 8);
      puVar2[2] = 0;
      FUN_802420e0((uint)puVar1,8);
      FUN_802420b0((uint)(puVar1 + 8),4);
      FUN_802420e0((uint)puVar2,0x10);
      *(undefined4 *)(&DAT_803afe74 + iVar8) = 0xff;
      *(undefined4 *)(&DAT_803afe7c + iVar8) = 0x32f840;
      *(undefined4 *)(&DAT_803afe80 + iVar8) = 0x160;
      *(undefined4 *)(&DAT_803afe84 + iVar8) = 0;
      *(undefined2 *)(&DAT_803afe94 + iVar8) = 0x10;
      *(undefined **)(&DAT_803afe98 + iVar8) = &LAB_802605fc;
      *(undefined4 *)(&DAT_803afe9c + iVar8) = 0;
      *(undefined **)(&DAT_803afea0 + iVar8) = &LAB_8026066c;
      *(undefined4 *)(&DAT_803afea4 + iVar8) = 0;
      FUN_802517c0((undefined4 *)(iVar8 + -0x7fc50190));
      *param_2 = uVar6;
      uVar5 = 0;
      param_2[1] = uVar7;
      param_2[2] = uVar11;
    }
  }
  return uVar5;
}

