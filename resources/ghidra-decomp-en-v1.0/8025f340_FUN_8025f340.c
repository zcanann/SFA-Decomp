// Function: FUN_8025f340
// Entry: 8025f340
// Size: 2904 bytes

undefined4 FUN_8025f340(int param_1,uint *param_2)

{
  uint *puVar1;
  uint **ppuVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  uint local_7c;
  uint local_78;
  uint local_74;
  uint local_70;
  uint local_6c;
  
  iVar9 = param_1 * 0x110;
  ppuVar2 = (uint **)(&DAT_803af260)[param_1 * 0x44];
  puVar1 = (uint *)((int)ppuVar2 + 0x2fU & 0xffffffe0);
  iVar3 = FUN_80246c68();
  DAT_803dc600 = iVar3 * 0x41c64e6d + 0x3039;
  uVar10 = DAT_803dc600 >> 0x10 & 0x7000 | 0x7fec8000;
  uVar4 = FUN_8025f27c();
  iVar3 = FUN_8025f138(param_1,uVar10,&local_7c,uVar4,0);
  if (iVar3 < 0) {
    uVar5 = 0xfffffffd;
  }
  else {
    uVar8 = uVar4 * 8 + 1;
    uVar6 = 0;
    if (uVar8 != 0) {
      if ((8 < uVar8) && (uVar11 = uVar4 & 0x1fffffff, uVar4 * 8 != 7)) {
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
      iVar3 = uVar8 - uVar6;
      if (uVar6 < uVar8) {
        do {
          uVar10 = uVar10 >> 1 |
                   (~(uVar10 >> 0x17 ^ uVar10 >> 0xf ^ uVar10 ^ uVar10 >> 7) & 1) << 0x1e;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
    }
    *(uint *)(&DAT_803af20c + iVar9) =
         uVar10 | ~(uVar10 >> 0x17 ^ uVar10 >> 0xf ^ uVar10 ^ uVar10 >> 7) << 0x1f;
    uVar5 = FUN_8025efcc(*(undefined4 *)(&DAT_803af20c + iVar9));
    *(undefined4 *)(&DAT_803af20c + iVar9) = uVar5;
    iVar3 = FUN_8025f27c();
    iVar7 = FUN_8025f138(param_1,0,&local_7c,iVar3 + 0x14,1);
    if (iVar7 < 0) {
      uVar5 = 0xfffffffd;
    }
    else {
      uVar10 = *(uint *)(&DAT_803af20c + iVar9);
      iVar7 = 4;
      local_7c = local_7c ^ uVar10;
      do {
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
      *(uint *)(&DAT_803af20c + iVar9) =
           uVar10 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1f;
      iVar7 = 4;
      uVar10 = *(uint *)(&DAT_803af20c + iVar9);
      local_78 = local_78 ^ uVar10;
      do {
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
      *(uint *)(&DAT_803af20c + iVar9) =
           uVar10 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1f;
      iVar7 = 4;
      uVar10 = *(uint *)(&DAT_803af20c + iVar9);
      local_74 = local_74 ^ uVar10;
      do {
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
      *(uint *)(&DAT_803af20c + iVar9) =
           uVar10 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1f;
      iVar7 = 4;
      uVar10 = *(uint *)(&DAT_803af20c + iVar9);
      local_70 = local_70 ^ uVar10;
      do {
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        uVar10 = uVar10 << 1 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1e & 2;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
      *(uint *)(&DAT_803af20c + iVar9) =
           uVar10 | ~(uVar10 << 0x17 ^ uVar10 << 0xf ^ uVar10 ^ uVar10 << 7) >> 0x1f;
      uVar10 = iVar3 * 8;
      uVar6 = *(uint *)(&DAT_803af20c + iVar9);
      uVar4 = 0;
      local_6c = local_6c ^ uVar6;
      if (uVar10 != 0) {
        if ((8 < uVar10) && (uVar8 = uVar10 - 1 >> 3, uVar10 != 8)) {
          do {
            uVar6 = uVar6 << 1 | ~(uVar6 << 0x17 ^ uVar6 << 0xf ^ uVar6 ^ uVar6 << 7) >> 0x1e & 2;
            uVar6 = uVar6 << 1 | ~(uVar6 << 0x17 ^ uVar6 << 0xf ^ uVar6 ^ uVar6 << 7) >> 0x1e & 2;
            uVar6 = uVar6 << 1 | ~(uVar6 << 0x17 ^ uVar6 << 0xf ^ uVar6 ^ uVar6 << 7) >> 0x1e & 2;
            uVar6 = uVar6 << 1 | ~(uVar6 << 0x17 ^ uVar6 << 0xf ^ uVar6 ^ uVar6 << 7) >> 0x1e & 2;
            uVar6 = uVar6 << 1 | ~(uVar6 << 0x17 ^ uVar6 << 0xf ^ uVar6 ^ uVar6 << 7) >> 0x1e & 2;
            uVar6 = uVar6 << 1 | ~(uVar6 << 0x17 ^ uVar6 << 0xf ^ uVar6 ^ uVar6 << 7) >> 0x1e & 2;
            uVar6 = uVar6 << 1 | ~(uVar6 << 0x17 ^ uVar6 << 0xf ^ uVar6 ^ uVar6 << 7) >> 0x1e & 2;
            uVar6 = uVar6 << 1 | ~(uVar6 << 0x17 ^ uVar6 << 0xf ^ uVar6 ^ uVar6 << 7) >> 0x1e & 2;
            uVar4 = uVar4 + 8;
            uVar8 = uVar8 - 1;
          } while (uVar8 != 0);
        }
        iVar3 = uVar10 - uVar4;
        if (uVar4 < uVar10) {
          do {
            uVar6 = uVar6 << 1 | ~(uVar6 << 0x17 ^ uVar6 << 0xf ^ uVar6 ^ uVar6 << 7) >> 0x1e & 2;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
      }
      *(uint *)(&DAT_803af20c + iVar9) =
           uVar6 | ~(uVar6 << 0x17 ^ uVar6 << 0xf ^ uVar6 ^ uVar6 << 7) >> 0x1f;
      iVar3 = 4;
      uVar10 = 0;
      uVar4 = *(uint *)(&DAT_803af20c + iVar9);
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
      *(uint *)(&DAT_803af20c + iVar9) =
           uVar4 | ~(uVar4 << 0x17 ^ uVar4 << 0xf ^ uVar4 ^ uVar4 << 7) >> 0x1f;
      *puVar1 = local_70;
      puVar1[1] = local_6c;
      *ppuVar2 = puVar1;
      ppuVar2[1] = (uint *)&DAT_00000008;
      ppuVar2[3] = puVar1 + 8;
      ppuVar2[2] = (uint *)0x0;
      FUN_802419e8(puVar1,8);
      FUN_802419b8(puVar1 + 8,4);
      FUN_802419e8(ppuVar2,0x10);
      *(undefined4 *)(&DAT_803af214 + iVar9) = 0xff;
      *(undefined4 *)(&DAT_803af21c + iVar9) = 0x32ebe0;
      *(undefined4 *)(&DAT_803af220 + iVar9) = 0x160;
      *(undefined4 *)(&DAT_803af224 + iVar9) = 0;
      *(undefined2 *)(&DAT_803af234 + iVar9) = 0x10;
      *(undefined **)(&DAT_803af238 + iVar9) = &LAB_8025fe98;
      *(undefined4 *)(&DAT_803af23c + iVar9) = 0;
      *(undefined **)(&DAT_803af240 + iVar9) = &DAT_8025ff08;
      *(undefined4 *)(&DAT_803af244 + iVar9) = 0;
      FUN_8025105c(iVar9 + -0x7fc50df0);
      *param_2 = local_7c;
      uVar5 = 0;
      param_2[1] = local_78;
      param_2[2] = local_74;
    }
  }
  return uVar5;
}

