// Function: FUN_8016dd2c
// Entry: 8016dd2c
// Size: 692 bytes

/* WARNING: Removing unreachable block (ram,0x8016dfb8) */
/* WARNING: Removing unreachable block (ram,0x8016dfb0) */
/* WARNING: Removing unreachable block (ram,0x8016dfc0) */

void FUN_8016dd2c(void)

{
  undefined4 uVar1;
  int *extraout_r4;
  uint uVar2;
  float *pfVar3;
  int iVar4;
  int *piVar5;
  undefined4 uVar6;
  undefined8 in_f29;
  double dVar7;
  undefined8 in_f30;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  FUN_802860dc();
  FUN_8004c2e4((&DAT_803ddaa8)[*(char *)((int)extraout_r4 + 0xb9)],0);
  FUN_800799c0();
  FUN_800796f0();
  FUN_80079804();
  FUN_80070310(1,3,0);
  FUN_8025c584(1,4,1,5);
  FUN_800702b8(1);
  FUN_8025bff0(7,0,0,7,0);
  FUN_80258b24(0);
  FUN_802573f8();
  FUN_80256978(9,1);
  FUN_80256978(0xb,1);
  FUN_80256978(0xd,1);
  uVar1 = FUN_8000f54c();
  FUN_8025d0a8(uVar1,0);
  FUN_8025d124(0);
  iVar4 = 0;
  piVar5 = extraout_r4;
  do {
    if (((*(byte *)(piVar5 + 5) & 2) != 0) && (3 < *(short *)((int)piVar5 + 0x12))) {
      uVar2 = (uint)*(ushort *)(piVar5 + 3);
      pfVar3 = (float *)(*piVar5 + uVar2 * 0x14);
      dVar7 = (double)FLOAT_803e3294;
      dVar8 = (double)FLOAT_803e32b4;
      dVar9 = (double)FLOAT_803e3288;
      for (; (int)uVar2 < (int)(*(ushort *)((int)piVar5 + 0xe) - 2); uVar2 = uVar2 + 2) {
        FUN_8025889c(0x80,2,4);
        write_volatile_4(0xcc008000,*pfVar3 - FLOAT_803dcdd8);
        write_volatile_4(0xcc008000,pfVar3[1]);
        write_volatile_4(0xcc008000,pfVar3[2] - FLOAT_803dcddc);
        write_volatile_1(DAT_cc008000,0xff);
        write_volatile_1(DAT_cc008000,0xff);
        write_volatile_1(DAT_cc008000,0xff);
        write_volatile_1(DAT_cc008000,(char)*(undefined2 *)(pfVar3 + 4));
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,(float)dVar8);
        write_volatile_4(0xcc008000,pfVar3[5] - FLOAT_803dcdd8);
        write_volatile_4(0xcc008000,pfVar3[6]);
        write_volatile_4(0xcc008000,pfVar3[7] - FLOAT_803dcddc);
        write_volatile_1(DAT_cc008000,0xff);
        write_volatile_1(DAT_cc008000,0xff);
        write_volatile_1(DAT_cc008000,0xff);
        write_volatile_1(DAT_cc008000,(char)*(undefined2 *)(pfVar3 + 9));
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,(float)dVar9);
        write_volatile_4(0xcc008000,pfVar3[0xf] - FLOAT_803dcdd8);
        write_volatile_4(0xcc008000,pfVar3[0x10]);
        write_volatile_4(0xcc008000,pfVar3[0x11] - FLOAT_803dcddc);
        write_volatile_1(DAT_cc008000,0xff);
        write_volatile_1(DAT_cc008000,0xff);
        write_volatile_1(DAT_cc008000,0xff);
        write_volatile_1(DAT_cc008000,(char)*(undefined2 *)(pfVar3 + 0x13));
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,(float)dVar9);
        write_volatile_4(0xcc008000,pfVar3[10] - FLOAT_803dcdd8);
        write_volatile_4(0xcc008000,pfVar3[0xb]);
        write_volatile_4(0xcc008000,pfVar3[0xc] - FLOAT_803dcddc);
        write_volatile_1(DAT_cc008000,0xff);
        write_volatile_1(DAT_cc008000,0xff);
        write_volatile_1(DAT_cc008000,0xff);
        write_volatile_1(DAT_cc008000,(char)*(undefined2 *)(pfVar3 + 0xe));
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,(float)dVar8);
        pfVar3 = pfVar3 + 10;
      }
    }
    piVar5 = piVar5 + 6;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 3);
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  FUN_80286128();
  return;
}

