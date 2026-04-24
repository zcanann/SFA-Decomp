// Function: FUN_80146780
// Entry: 80146780
// Size: 8672 bytes

void FUN_80146780(void)

{
  byte bVar1;
  short sVar2;
  undefined2 uVar3;
  short sVar4;
  bool bVar5;
  float fVar6;
  short *psVar7;
  int iVar8;
  char cVar13;
  undefined4 uVar9;
  byte *pbVar10;
  int iVar11;
  undefined4 *puVar12;
  int iVar14;
  uint uVar15;
  byte **ppbVar16;
  byte **ppbVar17;
  double dVar18;
  char local_d0 [4];
  char local_cc [4];
  char local_c8 [4];
  char local_c4 [4];
  char local_c0 [4];
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined auStack164 [13];
  char local_97;
  undefined4 local_28;
  uint uStack36;
  longlong local_20;
  
  psVar7 = (short *)FUN_802860d8();
  ppbVar17 = *(byte ***)(psVar7 + 0x5c);
  bVar5 = false;
  local_b8 = DAT_802c21c8;
  local_b4 = DAT_802c21cc;
  local_b0 = DAT_802c21d0;
  local_ac = DAT_802c21d4;
  local_a8 = DAT_802c21d8;
  local_bc = DAT_803e23c4;
  FUN_800dc398();
  iVar8 = FUN_8001ffb4(0x186);
  if (((iVar8 != 0) && (ppbVar17[499] == (byte *)0x0)) && (cVar13 = FUN_8002e04c(), cVar13 != '\0'))
  {
    FUN_80059c2c(auStack164);
    if (local_97 == '\0') {
      uVar9 = FUN_8002bdf4(0x20,0x254);
    }
    else {
      uVar9 = FUN_8002bdf4(0x20,0x244);
    }
    pbVar10 = (byte *)FUN_8002df90(uVar9,4,0xffffffff,0xffffffff,*(undefined4 *)(psVar7 + 0x18));
    ppbVar17[499] = pbVar10;
    FUN_80037d2c(psVar7,ppbVar17[499],3);
  }
  if (((uint)ppbVar17[0x15] & 0x40000000) != 0) {
    if (**ppbVar17 == (*ppbVar17)[1]) {
      iVar8 = *(int *)(psVar7 + 0x5c);
      if ((((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < psVar7[0x50] || (psVar7[0x50] < 0x29)))) &&
         (iVar11 = FUN_8000b578(psVar7,0x10), iVar11 == 0)) {
        FUN_800393f8(psVar7,iVar8 + 0x3a8,0x364,0x500,0xffffffff,0);
      }
    }
    else {
      iVar8 = *(int *)(psVar7 + 0x5c);
      if ((((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < psVar7[0x50] || (psVar7[0x50] < 0x29)))) &&
         (iVar11 = FUN_8000b578(psVar7,0x10), iVar11 == 0)) {
        FUN_800393f8(psVar7,iVar8 + 0x3a8,0x363,0x500,0xffffffff,0);
      }
    }
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xbfffffff);
  }
  uVar15 = (uint)*(char *)(ppbVar17 + 0xd6);
  FUN_80148bc8(s_hits___d__d__d__d__d__d__d__d_8031db7c,uVar15 & 1,uVar15 & 2,uVar15 & 4,uVar15 & 8,
               uVar15 & 0x10,uVar15 & 0x20,uVar15 & 0x40,uVar15 & 0x80);
  FUN_80148bc8(s__Energy___d__d_8031db9c,**ppbVar17,(*ppbVar17)[1]);
  if (((uint)ppbVar17[0x15] & 0x200) != 0) {
    FUN_80035f20(psVar7);
    if (((uint)ppbVar17[0x15] & 0x4000) == 0) {
      *(undefined *)(ppbVar17 + 2) = 1;
      *(undefined *)((int)ppbVar17 + 10) = 0;
      fVar6 = FLOAT_803e23dc;
      ppbVar17[0x1c7] = (byte *)FLOAT_803e23dc;
      ppbVar17[0x1c8] = (byte *)fVar6;
      ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xffffffef);
      ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffeffff);
      ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffdffff);
      ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffbffff);
      *(undefined *)((int)ppbVar17 + 0xd) = 0xff;
      *(undefined *)((int)ppbVar17 + 9) = 0;
      ppbVar17[4] = (byte *)fVar6;
      ppbVar17[5] = (byte *)fVar6;
      ppbVar17[0x38] = *(byte **)(psVar7 + 0xc);
      ppbVar17[0x39] = *(byte **)(psVar7 + 0xe);
      ppbVar17[0x3a] = *(byte **)(psVar7 + 0x10);
      (**(code **)(*DAT_803dcaa8 + 0x20))(psVar7,ppbVar17 + 0x3e);
      if ((psVar7[0x50] == 8) || (psVar7[0x50] == 7)) {
        ppbVar17[0xab] = (byte *)FLOAT_803e2414;
        ppbVar17[0xac] = (byte *)FLOAT_803e2544;
      }
      else {
        ppbVar17[0xab] = (byte *)FLOAT_803e23dc;
      }
    }
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xffffbdfe);
    bVar1 = *(byte *)((int)ppbVar17 + 0x82e);
    if ((bVar1 >> 5 & 1) == 0) {
      *(byte *)((int)ppbVar17 + 0x82e) = bVar1 & 0x7f | 0x80;
    }
    else {
      *(byte *)((int)ppbVar17 + 0x82e) = bVar1 & 0xdf;
    }
  }
  if ((ppbVar17[9] != (byte *)0x0) && ((*(ushort *)(ppbVar17[9] + 0xb0) & 0x40) != 0)) {
    if (((uint)ppbVar17[0x15] & 0x10) != 0) {
      ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xffffffef);
      *(undefined *)(ppbVar17 + 0xdd) = 2;
      (**(code **)(*DAT_803dcaa8 + 0x20))(psVar7,ppbVar17 + 0x3e);
      *(byte **)(psVar7 + 6) = ppbVar17[0x38];
      *(byte **)(psVar7 + 8) = ppbVar17[0x39];
      *(byte **)(psVar7 + 10) = ppbVar17[0x3a];
      *(byte **)(psVar7 + 0xc) = ppbVar17[0x38];
      *(byte **)(psVar7 + 0xe) = ppbVar17[0x39];
      *(byte **)(psVar7 + 0x10) = ppbVar17[0x3a];
      FUN_80035f8c(psVar7);
      iVar8 = 0;
      *(undefined *)((int)ppbVar17 + 9) = 0;
      fVar6 = FLOAT_803e23dc;
      ppbVar17[4] = (byte *)FLOAT_803e23dc;
      ppbVar17[5] = (byte *)fVar6;
      ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] | 0x80000);
      ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xffffdfff);
      if (((uint)ppbVar17[0x15] & 0x800) != 0) {
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffff7ff);
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] | 0x1000);
        ppbVar16 = ppbVar17;
        do {
          FUN_8017804c(ppbVar16[0x1c0]);
          ppbVar16 = ppbVar16 + 1;
          iVar8 = iVar8 + 1;
        } while (iVar8 < 7);
        FUN_8000db90(psVar7,0x3dc);
        iVar8 = *(int *)(psVar7 + 0x5c);
        if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < psVar7[0x50] || (psVar7[0x50] < 0x29)) &&
            (iVar11 = FUN_8000b578(psVar7,0x10), iVar11 == 0)))) {
          FUN_800393f8(psVar7,iVar8 + 0x3a8,0x29d,0,0xffffffff,0);
        }
      }
      FUN_8000db90(psVar7,0x13d);
    }
    *(undefined *)(ppbVar17 + 2) = 1;
    *(undefined *)((int)ppbVar17 + 10) = 0;
    fVar6 = FLOAT_803e23dc;
    ppbVar17[0x1c7] = (byte *)FLOAT_803e23dc;
    ppbVar17[0x1c8] = (byte *)fVar6;
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xffffffef);
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffeffff);
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffdffff);
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffbffff);
    *(undefined *)((int)ppbVar17 + 0xd) = 0xff;
    ppbVar17[9] = (byte *)0x0;
  }
  if ((((uint)ppbVar17[0x15] & 0x10) == 0) ||
     (iVar8 = (**(code **)(*DAT_803dca68 + 0x20))(0xc1), iVar8 == 0)) {
    iVar8 = (**(code **)(*DAT_803dca68 + 0x24))(&local_b8,5);
  }
  else {
    iVar8 = 0;
  }
  ppbVar16 = ppbVar17;
  for (uVar15 = (uint)*(byte *)(ppbVar17 + 0x1e6); uVar15 != 0; uVar15 = uVar15 - 1) {
    if (*(char *)((int)ppbVar16 + 0x74d) == iVar8) {
      bVar5 = true;
      break;
    }
    ppbVar16 = ppbVar16 + 2;
  }
  if ((((uint)ppbVar17[0x15] & 0x10) == 0) && (iVar11 = FUN_8013db3c(psVar7,ppbVar17), iVar11 == 2))
  {
    *(undefined *)(ppbVar17 + 2) = 0x11;
    goto LAB_80147d6c;
  }
  cVar13 = *(char *)(ppbVar17 + 2);
  if ((cVar13 == '\b') && (iVar8 == 4)) {
    *(byte *)(ppbVar17 + 0x1cd) = *(byte *)(ppbVar17 + 0x1cd) ^ 1;
    goto LAB_80147d6c;
  }
  if (((cVar13 == '\r') && (iVar8 == 4)) && (!bVar5)) {
    ppbVar17[0x1ca] = (byte *)0x1;
    goto LAB_80147d6c;
  }
  if ((cVar13 == '\x0e') && (iVar8 == 4)) {
    ppbVar17[0x1ca] = (byte *)0x1;
    goto LAB_80147d6c;
  }
  if (iVar8 == 0) {
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] | 0x30002);
    goto LAB_80147d6c;
  }
  pbVar10 = ppbVar17[0x15];
  if (((uint)pbVar10 & 0x10) != 0) {
    if (iVar8 == 3) {
      ppbVar17[0x15] = (byte *)((uint)pbVar10 | 0x40000);
    }
    goto LAB_80147d6c;
  }
  if (iVar8 == 3) {
    bVar5 = false;
    if (*(char *)((int)ppbVar17 + 0xd) == '\x03') {
      ppbVar16 = ppbVar17;
      for (uVar15 = (uint)*(byte *)(ppbVar17 + 0x1e6); uVar15 != 0; uVar15 = uVar15 - 1) {
        if (*(char *)((int)ppbVar16 + 0x74d) == '\x03') {
          bVar5 = true;
        }
        ppbVar16 = ppbVar16 + 2;
      }
    }
    else {
      bVar5 = true;
    }
    if (!bVar5) goto LAB_80147d6c;
    *(undefined *)((int)ppbVar17 + 0xd) = 3;
    iVar8 = FUN_80139260(ppbVar17,3);
    if (iVar8 == 0) {
      ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] | 0x40000);
      goto LAB_80147d6c;
    }
    sVar2 = *(short *)(ppbVar17[9] + 0x46);
    if (sVar2 != 0x26c) {
      if (sVar2 < 0x26c) {
        if (sVar2 != 0x131) {
          if (sVar2 < 0x131) {
            if ((sVar2 != 0x104) && ((0x103 < sVar2 || (sVar2 != 0x36)))) {
LAB_80147884:
              *(undefined *)(ppbVar17 + 2) = 8;
              goto LAB_80147d6c;
            }
          }
          else if (sVar2 != 0x19f) goto LAB_80147884;
        }
      }
      else {
        if (sVar2 == 0x6f0) {
          *(undefined *)(ppbVar17 + 2) = 0xe;
          goto LAB_80147d6c;
        }
        if (sVar2 < 0x6f0) {
          if ((sVar2 != 0x546) && ((0x545 < sVar2 || (sVar2 != 0x475)))) goto LAB_80147884;
        }
        else if (sVar2 != 0x7c3) goto LAB_80147884;
      }
    }
    *(undefined *)(ppbVar17 + 2) = 10;
    uStack36 = FUN_800221a0(500,0x2ee);
    uStack36 = uStack36 ^ 0x80000000;
    local_28 = 0x43300000;
    ppbVar17[0x1d0] = (byte *)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e2460);
    goto LAB_80147d6c;
  }
  if (2 < iVar8) {
    if (iVar8 == 5) {
      cVar13 = FUN_8002e04c();
      if (cVar13 != '\0') {
        *(undefined *)((int)ppbVar17 + 0xd) = 5;
        iVar8 = FUN_8002bdf4(0x18,0x112);
        *(undefined *)(iVar8 + 7) = 0xff;
        *(undefined *)(iVar8 + 4) = 2;
        *(undefined4 *)(iVar8 + 8) = *(undefined4 *)(psVar7 + 0xc);
        *(undefined4 *)(iVar8 + 0xc) = *(undefined4 *)(psVar7 + 0xe);
        *(undefined4 *)(iVar8 + 0x10) = *(undefined4 *)(psVar7 + 0x10);
        pbVar10 = (byte *)FUN_8002df90(iVar8,5,0xffffffff,0xffffffff,*(undefined4 *)(psVar7 + 0x18))
        ;
        ppbVar17[9] = pbVar10;
        if (ppbVar17[10] != ppbVar17[9] + 0x18) {
          ppbVar17[10] = ppbVar17[9] + 0x18;
          ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffffbff);
          *(undefined2 *)((int)ppbVar17 + 0xd2) = 0;
        }
        *(undefined *)((int)ppbVar17 + 10) = 0;
        *(undefined *)(ppbVar17 + 2) = 0xb;
      }
      goto LAB_80147d6c;
    }
    if (4 < iVar8) goto LAB_80147cd4;
    if (**ppbVar17 < 4) {
      cVar13 = FUN_8002e04c();
      if (cVar13 != '\0') {
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] | 4);
        *(undefined *)(ppbVar17 + 2) = 1;
        *(undefined *)((int)ppbVar17 + 10) = 0;
        fVar6 = FLOAT_803e23dc;
        ppbVar17[0x1c7] = (byte *)FLOAT_803e23dc;
        ppbVar17[0x1c8] = (byte *)fVar6;
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xffffffef);
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffeffff);
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffdffff);
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffbffff);
        *(undefined *)((int)ppbVar17 + 0xd) = 0xff;
        if (ppbVar17[0x1ee] == (byte *)0x0) {
          uVar9 = FUN_8002bdf4(0x20,0x17b);
          local_d0[0] = -1;
          local_d0[1] = -1;
          local_d0[2] = -1;
          if (ppbVar17[0x1ea] != (byte *)0x0) {
            local_d0[*(byte *)(ppbVar17 + 0x1ef) >> 6] = '\x01';
          }
          if (ppbVar17[0x1ec] != (byte *)0x0) {
            local_d0[*(byte *)(ppbVar17 + 0x1ef) >> 4 & 3] = '\x01';
          }
          if (ppbVar17[0x1ee] != (byte *)0x0) {
            local_d0[*(byte *)(ppbVar17 + 0x1ef) >> 2 & 3] = '\x01';
          }
          if (local_d0[0] == -1) {
            uVar15 = 0;
          }
          else if (local_d0[1] == -1) {
            uVar15 = 1;
          }
          else if (local_d0[2] == -1) {
            uVar15 = 2;
          }
          else if (local_d0[3] == -1) {
            uVar15 = 3;
          }
          else {
            uVar15 = 0xffffffff;
          }
          *(byte *)(ppbVar17 + 0x1ef) =
               (byte)((uVar15 & 0xff) << 2) & 0xc | *(byte *)(ppbVar17 + 0x1ef) & 0xf3;
          pbVar10 = (byte *)FUN_8002df90(uVar9,4,0xffffffff,0xffffffff,
                                         *(undefined4 *)(psVar7 + 0x18));
          ppbVar17[0x1ee] = pbVar10;
          FUN_80037d2c(psVar7,ppbVar17[0x1ee],*(byte *)(ppbVar17 + 0x1ef) >> 2 & 3);
          fVar6 = FLOAT_803e23dc;
          ppbVar17[0x1f0] = (byte *)FLOAT_803e23dc;
          ppbVar17[0x1f1] = (byte *)fVar6;
          ppbVar17[0x1f2] = (byte *)fVar6;
        }
      }
      goto LAB_80147d6c;
    }
    *(undefined *)((int)ppbVar17 + 0xd) = 4;
    FUN_80139260(ppbVar17,4);
    *(undefined *)(ppbVar17 + 2) = 7;
    sVar2 = *(short *)(ppbVar17[9] + 0x46);
    if (sVar2 == 0x50f) {
      ppbVar17[0x1c9] = (byte *)FUN_802272c8;
      goto LAB_80147d6c;
    }
    if (sVar2 < 0x50f) {
      if (sVar2 == 0x194) {
LAB_80147b80:
        ppbVar17[0x1c9] = (byte *)0x0;
        goto LAB_80147d6c;
      }
      if (sVar2 < 0x194) {
        if (sVar2 == 0x102) goto LAB_80147b80;
        if (sVar2 < 0x102) {
          if (sVar2 == 0x3c) {
            ppbVar17[0x1c9] = &LAB_801da9cc;
            goto LAB_80147d6c;
          }
        }
        else if (sVar2 == 0x191) {
          ppbVar17[0x1c9] = &LAB_801b0784;
          goto LAB_80147d6c;
        }
      }
      else {
        if (sVar2 == 0x470) {
          ppbVar17[0x1c9] = &LAB_8021a42c;
          goto LAB_80147d6c;
        }
        if ((sVar2 < 0x470) && (sVar2 == 0x1c9)) {
          ppbVar17[0x1c9] = &LAB_801b17f4;
          goto LAB_80147d6c;
        }
      }
    }
    else {
      if (sVar2 == 0x551) {
        ppbVar17[0x1c9] = &LAB_801fd4a8;
        goto LAB_80147d6c;
      }
      if (sVar2 < 0x551) {
        if ((sVar2 == 0x54c) || ((sVar2 < 0x54c && (sVar2 == 0x542)))) goto LAB_80147b80;
      }
      else {
        if (sVar2 == 0x718) {
          ppbVar17[0x1c9] = &LAB_801b6d40;
          goto LAB_80147d6c;
        }
        if ((sVar2 < 0x718) && (sVar2 == 0x6f9)) goto LAB_80147b80;
      }
    }
    *(undefined *)(ppbVar17 + 2) = 1;
    *(undefined *)((int)ppbVar17 + 10) = 0;
    fVar6 = FLOAT_803e23dc;
    ppbVar17[0x1c7] = (byte *)FLOAT_803e23dc;
    ppbVar17[0x1c8] = (byte *)fVar6;
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xffffffef);
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffeffff);
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffdffff);
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffbffff);
    *(undefined *)((int)ppbVar17 + 0xd) = 0xff;
    FUN_80148b78(s_find_command_used_on_the_wrong_o_8031dbac);
    goto LAB_80147d6c;
  }
  if (iVar8 != 1) {
LAB_80147cd4:
    if ((((cVar13 == '\x01') && (*(char *)((int)ppbVar17 + 0xd) != '\0')) &&
        (((uint)pbVar10 & 0x20000) == 0)) &&
       (pbVar10 = (byte *)FUN_80138fa8((double)FLOAT_803e24d8,ppbVar17[1],0), pbVar10 != (byte *)0x0
       )) {
      ppbVar17[9] = pbVar10;
      if (ppbVar17[10] != pbVar10 + 0x18) {
        ppbVar17[10] = pbVar10 + 0x18;
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffffbff);
        *(undefined2 *)((int)ppbVar17 + 0xd2) = 0;
      }
      *(undefined *)(ppbVar17 + 2) = 0xd;
      *(undefined *)((int)ppbVar17 + 10) = 0;
      ppbVar17[0x1ca] = (byte *)0x0;
    }
    goto LAB_80147d6c;
  }
  *(undefined *)((int)ppbVar17 + 0xd) = 1;
  FUN_80139260(ppbVar17,1);
  iVar8 = *(int *)(psVar7 + 0x5c);
  if ((((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) && ((0x2f < psVar7[0x50] || (psVar7[0x50] < 0x29)))
      ) && (iVar11 = FUN_8000b578(psVar7,0x10), iVar11 == 0)) {
    FUN_800393f8(psVar7,iVar8 + 0x3a8,0x13c,0,0xffffffff,0);
  }
  sVar2 = *(short *)(ppbVar17[9] + 0x46);
  if (sVar2 == 0x1ca) {
    if (**ppbVar17 < 4) {
      cVar13 = FUN_8002e04c();
      if (cVar13 != '\0') {
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] | 4);
        *(undefined *)(ppbVar17 + 2) = 1;
        *(undefined *)((int)ppbVar17 + 10) = 0;
        fVar6 = FLOAT_803e23dc;
        ppbVar17[0x1c7] = (byte *)FLOAT_803e23dc;
        ppbVar17[0x1c8] = (byte *)fVar6;
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xffffffef);
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffeffff);
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffdffff);
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffbffff);
        *(undefined *)((int)ppbVar17 + 0xd) = 0xff;
        if (ppbVar17[0x1ee] == (byte *)0x0) {
          uVar9 = FUN_8002bdf4(0x20,0x17b);
          local_c0[0] = -1;
          local_c0[1] = -1;
          local_c0[2] = -1;
          if (ppbVar17[0x1ea] != (byte *)0x0) {
            local_c0[*(byte *)(ppbVar17 + 0x1ef) >> 6] = '\x01';
          }
          if (ppbVar17[0x1ec] != (byte *)0x0) {
            local_c0[*(byte *)(ppbVar17 + 0x1ef) >> 4 & 3] = '\x01';
          }
          if (ppbVar17[0x1ee] != (byte *)0x0) {
            local_c0[*(byte *)(ppbVar17 + 0x1ef) >> 2 & 3] = '\x01';
          }
          if (local_c0[0] == -1) {
            uVar15 = 0;
          }
          else if (local_c0[1] == -1) {
            uVar15 = 1;
          }
          else if (local_c0[2] == -1) {
            uVar15 = 2;
          }
          else if (local_c0[3] == -1) {
            uVar15 = 3;
          }
          else {
            uVar15 = 0xffffffff;
          }
          *(byte *)(ppbVar17 + 0x1ef) =
               (byte)((uVar15 & 0xff) << 2) & 0xc | *(byte *)(ppbVar17 + 0x1ef) & 0xf3;
          pbVar10 = (byte *)FUN_8002df90(uVar9,4,0xffffffff,0xffffffff,
                                         *(undefined4 *)(psVar7 + 0x18));
          ppbVar17[0x1ee] = pbVar10;
          FUN_80037d2c(psVar7,ppbVar17[0x1ee],*(byte *)(ppbVar17 + 0x1ef) >> 2 & 3);
          fVar6 = FLOAT_803e23dc;
          ppbVar17[0x1f0] = (byte *)FLOAT_803e23dc;
          ppbVar17[0x1f1] = (byte *)fVar6;
          ppbVar17[0x1f2] = (byte *)fVar6;
        }
      }
    }
    else {
      *(undefined *)(ppbVar17 + 2) = 2;
    }
    goto LAB_80147d6c;
  }
  if (sVar2 < 0x1ca) {
    if (sVar2 != 0x193) {
      if (sVar2 < 0x193) {
        if (sVar2 == 0x160) {
          if (**ppbVar17 < 4) {
            cVar13 = FUN_8002e04c();
            if (cVar13 != '\0') {
              ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] | 4);
              *(undefined *)(ppbVar17 + 2) = 1;
              *(undefined *)((int)ppbVar17 + 10) = 0;
              fVar6 = FLOAT_803e23dc;
              ppbVar17[0x1c7] = (byte *)FLOAT_803e23dc;
              ppbVar17[0x1c8] = (byte *)fVar6;
              ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xffffffef);
              ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffeffff);
              ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffdffff);
              ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffbffff);
              *(undefined *)((int)ppbVar17 + 0xd) = 0xff;
              if (ppbVar17[0x1ee] == (byte *)0x0) {
                uVar9 = FUN_8002bdf4(0x20,0x17b);
                local_c4[0] = -1;
                local_c4[1] = -1;
                local_c4[2] = -1;
                if (ppbVar17[0x1ea] != (byte *)0x0) {
                  local_c4[*(byte *)(ppbVar17 + 0x1ef) >> 6] = '\x01';
                }
                if (ppbVar17[0x1ec] != (byte *)0x0) {
                  local_c4[*(byte *)(ppbVar17 + 0x1ef) >> 4 & 3] = '\x01';
                }
                if (ppbVar17[0x1ee] != (byte *)0x0) {
                  local_c4[*(byte *)(ppbVar17 + 0x1ef) >> 2 & 3] = '\x01';
                }
                if (local_c4[0] == -1) {
                  uVar15 = 0;
                }
                else if (local_c4[1] == -1) {
                  uVar15 = 1;
                }
                else if (local_c4[2] == -1) {
                  uVar15 = 2;
                }
                else if (local_c4[3] == -1) {
                  uVar15 = 3;
                }
                else {
                  uVar15 = 0xffffffff;
                }
                *(byte *)(ppbVar17 + 0x1ef) =
                     (byte)((uVar15 & 0xff) << 2) & 0xc | *(byte *)(ppbVar17 + 0x1ef) & 0xf3;
                pbVar10 = (byte *)FUN_8002df90(uVar9,4,0xffffffff,0xffffffff,
                                               *(undefined4 *)(psVar7 + 0x18));
                ppbVar17[0x1ee] = pbVar10;
                FUN_80037d2c(psVar7,ppbVar17[0x1ee],*(byte *)(ppbVar17 + 0x1ef) >> 2 & 3);
                fVar6 = FLOAT_803e23dc;
                ppbVar17[0x1f0] = (byte *)FLOAT_803e23dc;
                ppbVar17[0x1f1] = (byte *)fVar6;
                ppbVar17[0x1f2] = (byte *)fVar6;
              }
            }
          }
          else {
            *(undefined *)(ppbVar17 + 2) = 3;
          }
          goto LAB_80147d6c;
        }
        if ((sVar2 < 0x160) && (sVar2 == 0x6a)) goto LAB_801472fc;
      }
      else if (sVar2 == 0x195) {
        if (**ppbVar17 < 2) {
          cVar13 = FUN_8002e04c();
          if (cVar13 != '\0') {
            ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] | 4);
            *(undefined *)(ppbVar17 + 2) = 1;
            *(undefined *)((int)ppbVar17 + 10) = 0;
            fVar6 = FLOAT_803e23dc;
            ppbVar17[0x1c7] = (byte *)FLOAT_803e23dc;
            ppbVar17[0x1c8] = (byte *)fVar6;
            ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xffffffef);
            ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffeffff);
            ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffdffff);
            ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffbffff);
            *(undefined *)((int)ppbVar17 + 0xd) = 0xff;
            if (ppbVar17[0x1ee] == (byte *)0x0) {
              uVar9 = FUN_8002bdf4(0x20,0x17b);
              local_c8[0] = -1;
              local_c8[1] = -1;
              local_c8[2] = -1;
              if (ppbVar17[0x1ea] != (byte *)0x0) {
                local_c8[*(byte *)(ppbVar17 + 0x1ef) >> 6] = '\x01';
              }
              if (ppbVar17[0x1ec] != (byte *)0x0) {
                local_c8[*(byte *)(ppbVar17 + 0x1ef) >> 4 & 3] = '\x01';
              }
              if (ppbVar17[0x1ee] != (byte *)0x0) {
                local_c8[*(byte *)(ppbVar17 + 0x1ef) >> 2 & 3] = '\x01';
              }
              if (local_c8[0] == -1) {
                uVar15 = 0;
              }
              else if (local_c8[1] == -1) {
                uVar15 = 1;
              }
              else if (local_c8[2] == -1) {
                uVar15 = 2;
              }
              else if (local_c8[3] == -1) {
                uVar15 = 3;
              }
              else {
                uVar15 = 0xffffffff;
              }
              *(byte *)(ppbVar17 + 0x1ef) =
                   (byte)((uVar15 & 0xff) << 2) & 0xc | *(byte *)(ppbVar17 + 0x1ef) & 0xf3;
              pbVar10 = (byte *)FUN_8002df90(uVar9,4,0xffffffff,0xffffffff,
                                             *(undefined4 *)(psVar7 + 0x18));
              ppbVar17[0x1ee] = pbVar10;
              FUN_80037d2c(psVar7,ppbVar17[0x1ee],*(byte *)(ppbVar17 + 0x1ef) >> 2 & 3);
              fVar6 = FLOAT_803e23dc;
              ppbVar17[0x1f0] = (byte *)FLOAT_803e23dc;
              ppbVar17[0x1f1] = (byte *)fVar6;
              ppbVar17[0x1f2] = (byte *)fVar6;
            }
          }
        }
        else {
          *(undefined *)(ppbVar17 + 2) = 0x10;
        }
        goto LAB_80147d6c;
      }
      goto LAB_801476dc;
    }
  }
  else if (sVar2 != 0x3fb) {
    if (sVar2 < 0x3fb) {
      if (sVar2 == 0x358) {
        *(undefined *)(ppbVar17 + 2) = 0xe;
        goto LAB_80147d6c;
      }
      if ((sVar2 < 0x358) && (sVar2 == 0x352)) {
        if (**ppbVar17 < 4) {
          cVar13 = FUN_8002e04c();
          if (cVar13 != '\0') {
            ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] | 4);
            *(undefined *)(ppbVar17 + 2) = 1;
            *(undefined *)((int)ppbVar17 + 10) = 0;
            fVar6 = FLOAT_803e23dc;
            ppbVar17[0x1c7] = (byte *)FLOAT_803e23dc;
            ppbVar17[0x1c8] = (byte *)fVar6;
            ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xffffffef);
            ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffeffff);
            ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffdffff);
            ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffbffff);
            *(undefined *)((int)ppbVar17 + 0xd) = 0xff;
            if (ppbVar17[0x1ee] == (byte *)0x0) {
              uVar9 = FUN_8002bdf4(0x20,0x17b);
              local_cc[0] = -1;
              local_cc[1] = -1;
              local_cc[2] = -1;
              if (ppbVar17[0x1ea] != (byte *)0x0) {
                local_cc[*(byte *)(ppbVar17 + 0x1ef) >> 6] = '\x01';
              }
              if (ppbVar17[0x1ec] != (byte *)0x0) {
                local_cc[*(byte *)(ppbVar17 + 0x1ef) >> 4 & 3] = '\x01';
              }
              if (ppbVar17[0x1ee] != (byte *)0x0) {
                local_cc[*(byte *)(ppbVar17 + 0x1ef) >> 2 & 3] = '\x01';
              }
              if (local_cc[0] == -1) {
                uVar15 = 0;
              }
              else if (local_cc[1] == -1) {
                uVar15 = 1;
              }
              else if (local_cc[2] == -1) {
                uVar15 = 2;
              }
              else if (local_cc[3] == -1) {
                uVar15 = 3;
              }
              else {
                uVar15 = 0xffffffff;
              }
              *(byte *)(ppbVar17 + 0x1ef) =
                   (byte)((uVar15 & 0xff) << 2) & 0xc | *(byte *)(ppbVar17 + 0x1ef) & 0xf3;
              pbVar10 = (byte *)FUN_8002df90(uVar9,4,0xffffffff,0xffffffff,
                                             *(undefined4 *)(psVar7 + 0x18));
              ppbVar17[0x1ee] = pbVar10;
              FUN_80037d2c(psVar7,ppbVar17[0x1ee],*(byte *)(ppbVar17 + 0x1ef) >> 2 & 3);
              fVar6 = FLOAT_803e23dc;
              ppbVar17[0x1f0] = (byte *)FLOAT_803e23dc;
              ppbVar17[0x1f1] = (byte *)fVar6;
              ppbVar17[0x1f2] = (byte *)fVar6;
            }
          }
        }
        else {
          *(undefined *)(ppbVar17 + 2) = 2;
        }
        goto LAB_80147d6c;
      }
    }
    else if (sVar2 == 0x658) goto LAB_801472fc;
LAB_801476dc:
    *(undefined *)(ppbVar17 + 2) = 1;
    *(undefined *)((int)ppbVar17 + 10) = 0;
    fVar6 = FLOAT_803e23dc;
    ppbVar17[0x1c7] = (byte *)FLOAT_803e23dc;
    ppbVar17[0x1c8] = (byte *)fVar6;
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xffffffef);
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffeffff);
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffdffff);
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffbffff);
    *(undefined *)((int)ppbVar17 + 0xd) = 0xff;
    FUN_80148b78(s_find_command_used_on_the_wrong_o_8031dbac);
    goto LAB_80147d6c;
  }
LAB_801472fc:
  *(undefined *)(ppbVar17 + 2) = 9;
LAB_80147d6c:
  pbVar10 = ppbVar17[0x15];
  if (((uint)pbVar10 & 0x10) == 0) {
    if (((uint)pbVar10 & 0x10000) == 0) {
      if (((uint)pbVar10 & 0x40000) != 0) {
        ppbVar17[9] = (byte *)psVar7;
        *(undefined *)(ppbVar17 + 2) = 0xf;
        uStack36 = FUN_800221a0(500,0x2ee);
        uStack36 = uStack36 ^ 0x80000000;
        local_28 = 0x43300000;
        ppbVar17[0x1d0] = (byte *)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e2460);
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffbffff);
        *(undefined *)((int)ppbVar17 + 0xd) = 3;
        if ((byte **)ppbVar17[10] != ppbVar17 + 0x1cb) {
          ppbVar17[10] = (byte *)(ppbVar17 + 0x1cb);
          ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffffbff);
          *(undefined2 *)((int)ppbVar17 + 0xd2) = 0;
        }
      }
    }
    else {
      if (((uint)pbVar10 & 0x20000) == 0) {
        *(undefined *)(ppbVar17 + 2) = 1;
        *(undefined *)((int)ppbVar17 + 10) = 0;
        fVar6 = FLOAT_803e23dc;
        ppbVar17[0x1c7] = (byte *)FLOAT_803e23dc;
        ppbVar17[0x1c8] = (byte *)fVar6;
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xffffffef);
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffeffff);
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffdffff);
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffbffff);
        *(undefined *)((int)ppbVar17 + 0xd) = 0xff;
      }
      else {
        *(undefined *)(ppbVar17 + 2) = 1;
        *(undefined *)((int)ppbVar17 + 10) = 0;
        fVar6 = FLOAT_803e23dc;
        ppbVar17[0x1c7] = (byte *)FLOAT_803e23dc;
        ppbVar17[0x1c8] = (byte *)fVar6;
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xffffffef);
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffeffff);
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffdffff);
        ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffbffff);
        *(undefined *)((int)ppbVar17 + 0xd) = 0xff;
        *(undefined *)((int)ppbVar17 + 0xd) = 0;
      }
      ppbVar17[0x1c7] = (byte *)FLOAT_803e2548;
    }
  }
  *(byte *)((int)psVar7 + 0xaf) = *(byte *)((int)psVar7 + 0xaf) | 8;
  *(undefined *)((int)ppbVar17 + 0x353) = 1;
  (*(code *)(&PTR_FUN_8031d30c)[*(byte *)(ppbVar17 + 2)])(psVar7,ppbVar17);
  ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffffffd);
  ppbVar17[6] = (byte *)((float)ppbVar17[6] + FLOAT_803db414);
  if ((FLOAT_803e247c < (float)ppbVar17[6]) &&
     (pbVar10 = ppbVar17[8], (byte *)(int)psVar7[0x50] != pbVar10)) {
    if ((((uint)ppbVar17[0x14] & 0x1000000) == 0) || (((uint)ppbVar17[0x15] & 0x1000000) == 0)) {
      FUN_80030334((double)FLOAT_803e23dc,psVar7,pbVar10,0);
    }
    else {
      FUN_80030334((double)*(float *)(psVar7 + 0x4c),psVar7,pbVar10,0);
    }
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xf9fffe1f);
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] | (uint)ppbVar17[0x14]);
    ppbVar17[6] = (byte *)FLOAT_803e23dc;
    ppbVar17[0xd] = ppbVar17[0xe];
  }
  if (((uint)ppbVar17[0x15] & 0x2000000) != 0) {
    *(float *)(psVar7 + 6) =
         FLOAT_803db414 * (float)ppbVar17[0xb] * (float)ppbVar17[5] + *(float *)(psVar7 + 6);
    *(float *)(psVar7 + 10) =
         FLOAT_803db414 * (float)ppbVar17[0xc] * (float)ppbVar17[5] + *(float *)(psVar7 + 10);
    FUN_8002f5d4((double)(float)ppbVar17[5],psVar7,ppbVar17 + 0xd);
  }
  if ((float)ppbVar17[0xd] == FLOAT_803e23dc) {
    FUN_80030304((double)(float)ppbVar17[0xf],psVar7);
  }
  iVar8 = FUN_8002fa48((double)(float)ppbVar17[0xd],(double)FLOAT_803db414,psVar7,ppbVar17 + 0x203);
  if (iVar8 == 0) {
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xf7ffffff);
  }
  else {
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] | 0x8000000);
  }
  if (((uint)ppbVar17[0x15] & 0x100) != 0) {
    iVar8 = (int)*(short *)((int)ppbVar17 + 0x5a) - ((int)*psVar7 & 0xffffU);
    if (0x8000 < iVar8) {
      iVar8 = iVar8 + -0xffff;
    }
    if (iVar8 < -0x8000) {
      iVar8 = iVar8 + 0xffff;
    }
    uStack36 = (int)*(short *)((int)ppbVar17 + 0x81a) ^ 0x80000000;
    local_28 = 0x43300000;
    iVar11 = (int)((float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e2460) *
                  (float)ppbVar17[0x13]);
    local_20 = (longlong)iVar11;
    iVar14 = iVar8;
    if (iVar8 < 0) {
      iVar14 = -iVar8;
    }
    sVar2 = (short)iVar8;
    if (iVar14 < 4) {
      *psVar7 = *psVar7 + sVar2;
    }
    else {
      sVar4 = (short)iVar11;
      if (((iVar11 < 1) || (iVar8 < 1)) && ((-1 < iVar11 || (-1 < iVar8)))) {
        *psVar7 = *psVar7 + sVar4;
      }
      else {
        if (iVar8 < 0) {
          iVar8 = -iVar8;
        }
        if (iVar11 < 0) {
          iVar11 = -iVar11;
        }
        if (iVar8 < iVar11) {
          *psVar7 = *psVar7 + sVar2;
        }
        else {
          *psVar7 = *psVar7 + sVar4;
        }
      }
    }
  }
  if (((uint)ppbVar17[0x15] & 0x40) != 0) {
    *(float *)(psVar7 + 6) =
         (float)ppbVar17[0x11] * (float)ppbVar17[0xb] * -(float)ppbVar17[0x205] +
         *(float *)(psVar7 + 6);
    *(float *)(psVar7 + 10) =
         (float)ppbVar17[0x11] * (float)ppbVar17[0xc] * -(float)ppbVar17[0x205] +
         *(float *)(psVar7 + 10);
  }
  if (((uint)ppbVar17[0x15] & 0x80) != 0) {
    *(float *)(psVar7 + 8) = (float)ppbVar17[0x204] * (float)ppbVar17[0x12] + *(float *)(psVar7 + 8)
    ;
  }
  if (((uint)ppbVar17[0x15] & 0x20) != 0) {
    *(float *)(psVar7 + 6) =
         (float)ppbVar17[0x10] * (float)ppbVar17[0xc] * (float)ppbVar17[0x203] +
         *(float *)(psVar7 + 6);
    *(float *)(psVar7 + 10) =
         (float)ppbVar17[0x10] * (float)ppbVar17[0xb] * -(float)ppbVar17[0x203] +
         *(float *)(psVar7 + 10);
  }
  if (ppbVar17[9] == (byte *)0x0) {
    *(undefined *)(ppbVar17 + 0xde) = 0;
  }
  else {
    *(undefined *)(ppbVar17 + 0xde) = 1;
    ppbVar17[0xdf] = *(byte **)(ppbVar17[9] + 0x18);
    ppbVar17[0xe0] = *(byte **)(ppbVar17[9] + 0x1c);
    ppbVar17[0xe1] = *(byte **)(ppbVar17[9] + 0x20);
  }
  if (psVar7[0x50] == 0x2a) {
    FUN_8003a168(psVar7,ppbVar17 + 0xde);
    FUN_8003b228(psVar7,ppbVar17 + 0xde);
  }
  else {
    FUN_8003a230((double)FLOAT_803e23dc,psVar7,ppbVar17 + 0xde);
    FUN_8003b310(psVar7,ppbVar17 + 0xde);
  }
  FUN_80038f38(psVar7,ppbVar17 + 0xea);
  iVar8 = *(int *)(psVar7 + 0x5c);
  puVar12 = *(undefined4 **)(iVar8 + 0x28);
  *(undefined4 **)(iVar8 + 0x6f0) = puVar12;
  if (*(int *)(iVar8 + 0x6f0) != 0) {
    *(undefined4 *)(iVar8 + 0x6f4) = *puVar12;
    *(undefined4 *)(iVar8 + 0x6f8) = puVar12[1];
    *(undefined4 *)(iVar8 + 0x6fc) = puVar12[2];
  }
  ppbVar17[4] = ppbVar17[5];
  iVar8 = *(byte *)(ppbVar17 + 0x1e6) - 1;
  ppbVar16 = ppbVar17 + iVar8 * 2;
  for (; -1 < iVar8; iVar8 = iVar8 + -1) {
    *(char *)((int)ppbVar16 + 0x74e) = *(char *)((int)ppbVar16 + 0x74e) + -1;
    if (*(char *)((int)ppbVar16 + 0x74e) == '\0') {
      FUN_8028f2cc(ppbVar16 + 0x1d2,ppbVar17 + (iVar8 + 1) * 2 + 0x1d2,
                   (((uint)*(byte *)(ppbVar17 + 0x1e6) - iVar8) + -1) * 8);
      *(char *)(ppbVar17 + 0x1e6) = *(char *)(ppbVar17 + 0x1e6) + -1;
    }
    ppbVar16 = ppbVar16 + -2;
  }
  dVar18 = (double)FUN_8002166c(psVar7 + 0xc,ppbVar17[1] + 0x18);
  if (((double)FLOAT_803e2538 <= dVar18) && (iVar8 = FUN_8001ffb4(0x4e4), iVar8 != 0)) {
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] | 0x10000);
  }
  ppbVar17[0x1e7] = (byte *)((float)ppbVar17[0x1e7] - FLOAT_803db414);
  if ((float)ppbVar17[0x1e7] < FLOAT_803e23dc) {
    ppbVar17[0x1e7] = (byte *)FLOAT_803e23dc;
  }
  if (((uint)ppbVar17[0x15] & 4) != 0) {
    iVar8 = *(int *)(psVar7 + 0x5c);
    if ((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) {
      if ((psVar7[0x50] < 0x30) && (0x28 < psVar7[0x50])) {
        bVar5 = false;
      }
      else {
        iVar11 = FUN_8000b578(psVar7,0x10);
        if (iVar11 == 0) {
          FUN_800393f8(psVar7,iVar8 + 0x3a8,0x298,0x500,0xffffffff,0);
          bVar5 = true;
        }
        else {
          bVar5 = false;
        }
      }
    }
    else {
      bVar5 = false;
    }
    if (bVar5) {
      ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0xfffffffb);
    }
  }
  ppbVar17[0x1e8] = (byte *)((float)ppbVar17[0x1e8] - FLOAT_803db414);
  if ((float)ppbVar17[0x1e8] < FLOAT_803e23dc) {
    ppbVar17[0x1e8] = (byte *)FLOAT_803e23dc;
  }
  if ((((FLOAT_803e23dc < (float)ppbVar17[0x1e8]) &&
       (iVar8 = *(int *)(psVar7 + 0x5c), (*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0)) &&
      ((0x2f < psVar7[0x50] || (psVar7[0x50] < 0x29)))) &&
     (iVar11 = FUN_8000b578(psVar7,0x10), iVar11 == 0)) {
    FUN_800393f8(psVar7,iVar8 + 0x3a8,0x29c,0x100,0xffffffff,0);
  }
  FUN_8013939c(psVar7);
  if ((((uint)ppbVar17[0x15] & 0x80000000) != 0) &&
     (ppbVar17[0x202] = (byte *)((float)ppbVar17[0x202] - FLOAT_803db414),
     (float)ppbVar17[0x202] <= FLOAT_803e23dc)) {
    ppbVar17[0x15] = (byte *)((uint)ppbVar17[0x15] & 0x7fffffff);
    iVar8 = FUN_800221a0(0,1);
    uVar3 = *(undefined2 *)((int)&local_bc + iVar8 * 2);
    iVar8 = *(int *)(psVar7 + 0x5c);
    if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
       (((0x2f < psVar7[0x50] || (psVar7[0x50] < 0x29)) &&
        (iVar11 = FUN_8000b578(psVar7,0x10), iVar11 == 0)))) {
      FUN_800393f8(psVar7,iVar8 + 0x3a8,uVar3,0x500,0xffffffff,0);
    }
  }
  FUN_80138d7c(psVar7,ppbVar17);
  FUN_80138b60(psVar7,ppbVar17);
  if ((double)FLOAT_803e254c < (double)(float)ppbVar17[5]) {
    FUN_8006ef38((double)(float)ppbVar17[5],(double)FLOAT_803e23e8,psVar7,ppbVar17 + 0x203,1,
                 ppbVar17 + 0x1f6,ppbVar17 + 0x3e);
  }
  if (FLOAT_803e23dc == (float)ppbVar17[0xab]) {
    bVar5 = false;
  }
  else if (FLOAT_803e2410 == (float)ppbVar17[0xac]) {
    bVar5 = true;
  }
  else if ((float)ppbVar17[0xad] - (float)ppbVar17[0xac] <= FLOAT_803e2414) {
    bVar5 = false;
  }
  else {
    bVar5 = true;
  }
  if (bVar5) {
    iVar14 = 0;
    iVar11 = 0;
    iVar8 = (int)*(char *)((int)ppbVar17 + 0x827);
    if (0 < iVar8) {
      do {
        cVar13 = *(char *)((int)ppbVar17 + iVar11 + 0x81f);
        if ((cVar13 < '\x03') && (-1 < cVar13)) {
          iVar14 = 0x433;
        }
        iVar11 = iVar11 + 1;
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
    }
    if (iVar14 != 0) {
      FUN_8000bb18(psVar7,iVar14);
    }
  }
  ppbVar17[0x23] = *(byte **)(psVar7 + 0x40);
  ppbVar17[0x24] = *(byte **)(psVar7 + 0x42);
  ppbVar17[0x25] = *(byte **)(psVar7 + 0x44);
  if (ppbVar17[0x1ee] != (byte *)0x0) {
    ppbVar17[0x1f0] = (byte *)((float)ppbVar17[0x1f0] + FLOAT_803db414);
    ppbVar17[0x1f1] = (byte *)((float)ppbVar17[0x1f1] + FLOAT_803db414);
    ppbVar17[0x1f2] = (byte *)((float)ppbVar17[0x1f2] + FLOAT_803db414);
    if (FLOAT_803e24c8 < (float)ppbVar17[0x1f2]) {
      ppbVar17[0x1f2] = (byte *)((float)ppbVar17[0x1f2] - FLOAT_803e24c8);
    }
    if ((float)ppbVar17[0x1f2] < FLOAT_803e2408) {
      *(ushort *)(ppbVar17[0x1ee] + 6) = *(ushort *)(ppbVar17[0x1ee] + 6) & 0xbfff;
    }
    else {
      *(ushort *)(ppbVar17[0x1ee] + 6) = *(ushort *)(ppbVar17[0x1ee] + 6) | 0x4000;
    }
    pbVar10 = ppbVar17[0x1f1];
    if (FLOAT_803e24d8 < (float)pbVar10) {
      if (FLOAT_803e2440 < (float)pbVar10) {
        ppbVar17[0x1f1] = (byte *)((float)pbVar10 - FLOAT_803e2440);
      }
      *(ushort *)(ppbVar17[0x1ee] + 6) = *(ushort *)(ppbVar17[0x1ee] + 6) | 0x4000;
    }
    if (FLOAT_803e2550 < (float)ppbVar17[0x1f0]) {
      iVar8 = FUN_8001ffb4(0xc1);
      if (iVar8 == 0) {
        iVar8 = *(int *)(psVar7 + 0x5c);
        if ((((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
            ((0x2f < psVar7[0x50] || (psVar7[0x50] < 0x29)))) &&
           (iVar11 = FUN_8000b578(psVar7,0x10), iVar11 == 0)) {
          FUN_800393f8(psVar7,iVar8 + 0x3a8,0x298,0x500,0xffffffff,0);
        }
      }
      else {
        iVar8 = *(int *)(psVar7 + 0x5c);
        if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < psVar7[0x50] || (psVar7[0x50] < 0x29)) &&
            (iVar11 = FUN_8000b578(psVar7,0x10), iVar11 == 0)))) {
          FUN_800393f8(psVar7,iVar8 + 0x3a8,0x392,0x500,0xffffffff,0);
        }
      }
      ppbVar17[0x1f0] = (byte *)((float)ppbVar17[0x1f0] - FLOAT_803e2550);
    }
    FUN_8002fa48((double)FLOAT_803e23ec,(double)FLOAT_803db414,ppbVar17[0x1ee],0);
  }
  if (ppbVar17[0x1ec] != (byte *)0x0) {
    FUN_8002fa48((double)FLOAT_803e23ec,(double)FLOAT_803db414,ppbVar17[0x1ec],0);
  }
  if (ppbVar17[0x1ea] != (byte *)0x0) {
    FUN_8002fa48((double)FLOAT_803e23ec,(double)FLOAT_803db414,ppbVar17[0x1ea],0);
  }
  FUN_80286124();
  return;
}

