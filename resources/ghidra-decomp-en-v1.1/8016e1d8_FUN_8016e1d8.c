// Function: FUN_8016e1d8
// Entry: 8016e1d8
// Size: 692 bytes

/* WARNING: Removing unreachable block (ram,0x8016e46c) */
/* WARNING: Removing unreachable block (ram,0x8016e464) */
/* WARNING: Removing unreachable block (ram,0x8016e45c) */
/* WARNING: Removing unreachable block (ram,0x8016e1f8) */
/* WARNING: Removing unreachable block (ram,0x8016e1f0) */
/* WARNING: Removing unreachable block (ram,0x8016e1e8) */

void FUN_8016e1d8(void)

{
  float *pfVar1;
  int *extraout_r4;
  uint uVar2;
  int iVar3;
  int *piVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  FUN_80286840();
  FUN_8004c460((&DAT_803de728)[*(char *)((int)extraout_r4 + 0xb9)],0);
  FUN_80079b3c();
  FUN_8007986c();
  FUN_80079980();
  FUN_8007048c(1,3,0);
  FUN_8025cce8(1,4,1,5);
  FUN_80070434(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80259288(0);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(0xb,1);
  FUN_802570dc(0xd,1);
  pfVar1 = (float *)FUN_8000f56c();
  FUN_8025d80c(pfVar1,0);
  FUN_8025d888(0);
  iVar3 = 0;
  piVar4 = extraout_r4;
  do {
    if (((*(byte *)(piVar4 + 5) & 2) != 0) && (3 < *(short *)((int)piVar4 + 0x12))) {
      uVar2 = (uint)*(ushort *)(piVar4 + 3);
      pfVar1 = (float *)(*piVar4 + uVar2 * 0x14);
      dVar5 = (double)FLOAT_803e3f2c;
      dVar6 = (double)FLOAT_803e3f4c;
      dVar7 = (double)FLOAT_803e3f20;
      for (; (int)uVar2 < (int)(*(ushort *)((int)piVar4 + 0xe) - 2); uVar2 = uVar2 + 2) {
        FUN_80259000(0x80,2,4);
        DAT_cc008000 = *pfVar1 - FLOAT_803dda58;
        DAT_cc008000 = pfVar1[1];
        DAT_cc008000 = pfVar1[2] - FLOAT_803dda5c;
        DAT_cc008000._0_1_ = 0xff;
        DAT_cc008000._0_1_ = 0xff;
        DAT_cc008000._0_1_ = 0xff;
        DAT_cc008000._0_1_ = (char)*(undefined2 *)(pfVar1 + 4);
        DAT_cc008000 = (float)dVar5;
        DAT_cc008000 = (float)dVar6;
        DAT_cc008000 = pfVar1[5] - FLOAT_803dda58;
        DAT_cc008000 = pfVar1[6];
        DAT_cc008000 = pfVar1[7] - FLOAT_803dda5c;
        DAT_cc008000._0_1_ = 0xff;
        DAT_cc008000._0_1_ = 0xff;
        DAT_cc008000._0_1_ = 0xff;
        DAT_cc008000._0_1_ = (char)*(undefined2 *)(pfVar1 + 9);
        DAT_cc008000 = (float)dVar5;
        DAT_cc008000 = (float)dVar7;
        DAT_cc008000 = pfVar1[0xf] - FLOAT_803dda58;
        DAT_cc008000 = pfVar1[0x10];
        DAT_cc008000 = pfVar1[0x11] - FLOAT_803dda5c;
        DAT_cc008000._0_1_ = 0xff;
        DAT_cc008000._0_1_ = 0xff;
        DAT_cc008000._0_1_ = 0xff;
        DAT_cc008000._0_1_ = (char)*(undefined2 *)(pfVar1 + 0x13);
        DAT_cc008000 = (float)dVar5;
        DAT_cc008000 = (float)dVar7;
        DAT_cc008000 = pfVar1[10] - FLOAT_803dda58;
        DAT_cc008000 = pfVar1[0xb];
        DAT_cc008000 = pfVar1[0xc] - FLOAT_803dda5c;
        DAT_cc008000._0_1_ = 0xff;
        DAT_cc008000._0_1_ = 0xff;
        DAT_cc008000._0_1_ = 0xff;
        DAT_cc008000._0_1_ = (char)*(undefined2 *)(pfVar1 + 0xe);
        DAT_cc008000 = (float)dVar5;
        DAT_cc008000 = (float)dVar6;
        pfVar1 = pfVar1 + 10;
      }
    }
    piVar4 = piVar4 + 6;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 3);
  FUN_8028688c();
  return;
}

