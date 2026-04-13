// Function: FUN_8006f67c
// Entry: 8006f67c
// Size: 1104 bytes

/* WARNING: Removing unreachable block (ram,0x8006faac) */
/* WARNING: Removing unreachable block (ram,0x8006faa4) */
/* WARNING: Removing unreachable block (ram,0x8006f694) */
/* WARNING: Removing unreachable block (ram,0x8006f68c) */

void FUN_8006f67c(void)

{
  undefined uVar1;
  int iVar2;
  float *pfVar3;
  uint uVar4;
  undefined4 *puVar5;
  double dVar6;
  double dVar7;
  undefined4 local_f8;
  undefined4 local_f4;
  float afStack_f0 [12];
  float afStack_c0 [12];
  float afStack_90 [12];
  float afStack_60 [12];
  undefined4 local_30;
  uint uStack_2c;
  
  iVar2 = FUN_8002bac4();
  if (iVar2 != 0) {
    FUN_8000f9d4();
    FUN_8025d888(0);
    FUN_80257b5c();
    FUN_802570dc(9,1);
    FUN_802570dc(0xd,1);
    FUN_80258944(1);
    FUN_80258674(0,1,4,0x1e,0,0x7d);
    FUN_8025ca04(1);
    FUN_8025be54(0);
    FUN_8025a608(4,0,0,0,0,0,2);
    FUN_8025a608(5,0,0,0,0,0,2);
    FUN_8025a5bc(0);
    FUN_8025c828(0,0,0,0xff);
    FUN_8025be80(0);
    FUN_8025c1a4(0,0xf,0xf,0xf,0xf);
    FUN_8025c5f0(0,0x1c);
    FUN_8025c224(0,7,4,6,7);
    FUN_8025c2a8(0,0,0,0,1,0);
    FUN_8025c368(0,0,0,0,1,0);
    FUN_8025c65c(0,0,0);
    FUN_80259288(0);
    FUN_8025cce8(1,4,5,5);
    FUN_8004c460((&DAT_80392a30)[DAT_803ddc70],0);
    pfVar3 = (float *)FUN_8000f56c();
    FUN_80247a48(-(double)FLOAT_803dda58,(double)FLOAT_803dfaa0,-(double)FLOAT_803dda5c,afStack_60);
    FUN_80247618(pfVar3,afStack_60,afStack_90);
    FUN_8025d80c(afStack_90,0);
    FUN_8007048c(1,3,0);
    FUN_80070434(1);
    FUN_8025c754(7,0,0,7,0);
    iVar2 = 0;
    puVar5 = &DAT_80393a40;
    do {
      uVar4 = (uint)*(byte *)((int)puVar5 + 0x33);
      if (uVar4 != 0) {
        if (*(char *)((int)puVar5 + 0x32) == '\x01') {
          uVar1 = (undefined)((int)uVar4 >> 2);
        }
        else {
          uVar1 = (undefined)((int)uVar4 >> 1);
        }
        local_f4 = CONCAT31(local_f4._0_3_,uVar1);
        local_f8 = local_f4;
        FUN_8025c510(0,(byte *)&local_f8);
        if (*(char *)(puVar5 + 0xd) == '\0') {
          dVar7 = (double)FLOAT_803dfaa0;
          dVar6 = (double)FLOAT_803dfab8;
          uStack_2c = (uint)*(ushort *)(puVar5 + 0xc);
          local_30 = 0x43300000;
          FUN_8024782c((double)((FLOAT_803dfabc *
                                FLOAT_803dfac0 *
                                (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803dfab0)) /
                               FLOAT_803dfac4),afStack_c0,0x7a);
        }
        else {
          dVar7 = (double)FLOAT_803dfab8;
          dVar6 = (double)FLOAT_803dfaa0;
          uStack_2c = 0x8000 - *(ushort *)(puVar5 + 0xc) ^ 0x80000000;
          local_30 = 0x43300000;
          FUN_8024782c((double)((FLOAT_803dfabc *
                                FLOAT_803dfac0 *
                                (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803dfad0)) /
                               FLOAT_803dfac4),afStack_c0,0x7a);
        }
        FUN_80247a48((double)FLOAT_803dfac8,(double)FLOAT_803dfac8,(double)FLOAT_803dfaa0,afStack_f0
                    );
        FUN_80247618(afStack_c0,afStack_f0,afStack_c0);
        FUN_80247a48((double)FLOAT_803dfaa4,(double)FLOAT_803dfaa4,(double)FLOAT_803dfaa0,afStack_f0
                    );
        FUN_80247618(afStack_f0,afStack_c0,afStack_c0);
        FUN_8025d8c4(afStack_c0,0x1e,1);
        FUN_80259000(0x80,2,4);
        DAT_cc008000 = *puVar5;
        DAT_cc008000 = puVar5[1];
        DAT_cc008000 = puVar5[2];
        DAT_cc008000 = FLOAT_803dfaa0;
        DAT_cc008000 = (float)dVar7;
        DAT_cc008000 = puVar5[3];
        DAT_cc008000 = puVar5[4];
        DAT_cc008000 = puVar5[5];
        DAT_cc008000 = FLOAT_803dfab8;
        DAT_cc008000 = (float)dVar7;
        DAT_cc008000 = puVar5[6];
        DAT_cc008000 = puVar5[7];
        DAT_cc008000 = puVar5[8];
        DAT_cc008000 = FLOAT_803dfab8;
        DAT_cc008000 = (float)dVar6;
        DAT_cc008000 = puVar5[9];
        DAT_cc008000 = puVar5[10];
        DAT_cc008000 = puVar5[0xb];
        DAT_cc008000 = FLOAT_803dfaa0;
        DAT_cc008000 = (float)dVar6;
      }
      puVar5 = puVar5 + 0xe;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x100);
    FUN_8000f7a0();
  }
  return;
}

