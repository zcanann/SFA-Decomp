// Function: FUN_801e991c
// Entry: 801e991c
// Size: 740 bytes

/* WARNING: Removing unreachable block (ram,0x801e9bd8) */
/* WARNING: Removing unreachable block (ram,0x801e9be0) */

void FUN_801e991c(void)

{
  undefined4 uVar1;
  int extraout_r4;
  int iVar2;
  int iVar3;
  int iVar4;
  float *pfVar5;
  undefined4 uVar6;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  undefined local_48;
  undefined local_47;
  undefined local_46 [2];
  undefined4 local_44;
  undefined4 local_40;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  FUN_802860dc();
  local_40 = DAT_803e5ae4;
  FUN_8004c2e4(DAT_803ddc60,0);
  FUN_800799c0();
  FUN_800796f0();
  FUN_80079804();
  local_44 = local_40;
  FUN_8025bcc4(2,&local_44);
  FUN_80070310(1,3,0);
  FUN_8025c584(1,4,5,5);
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
  FUN_800898c8(0,local_46,&local_47,&local_48);
  iVar3 = 0;
  iVar4 = extraout_r4;
  do {
    if (((*(byte *)(iVar4 + 0x4ce) & 1) != 0) && (3 < *(short *)(iVar4 + 0x4cc))) {
      pfVar5 = *(float **)(iVar4 + 0x4c8);
      dVar7 = (double)FLOAT_803e5ae8;
      dVar8 = (double)FLOAT_803e5aec;
      for (iVar2 = 0; iVar2 < *(short *)(iVar4 + 0x4cc) + -2; iVar2 = iVar2 + 2) {
        FUN_8025889c(0x80,2,4);
        write_volatile_4(0xcc008000,*pfVar5 - FLOAT_803dcdd8);
        write_volatile_4(0xcc008000,pfVar5[1]);
        write_volatile_4(0xcc008000,pfVar5[2] - FLOAT_803dcddc);
        write_volatile_1(DAT_cc008000,local_46[0]);
        write_volatile_1(DAT_cc008000,local_47);
        write_volatile_1(DAT_cc008000,local_48);
        write_volatile_1(DAT_cc008000,(char)*(undefined2 *)(pfVar5 + 3));
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,pfVar5[4] - FLOAT_803dcdd8);
        write_volatile_4(0xcc008000,pfVar5[5]);
        write_volatile_4(0xcc008000,pfVar5[6] - FLOAT_803dcddc);
        write_volatile_1(DAT_cc008000,local_46[0]);
        write_volatile_1(DAT_cc008000,local_47);
        write_volatile_1(DAT_cc008000,local_48);
        write_volatile_1(DAT_cc008000,(char)*(undefined2 *)(pfVar5 + 7));
        write_volatile_4(0xcc008000,(float)dVar8);
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,pfVar5[0xc] - FLOAT_803dcdd8);
        write_volatile_4(0xcc008000,pfVar5[0xd]);
        write_volatile_4(0xcc008000,pfVar5[0xe] - FLOAT_803dcddc);
        write_volatile_1(DAT_cc008000,local_46[0]);
        write_volatile_1(DAT_cc008000,local_47);
        write_volatile_1(DAT_cc008000,local_48);
        write_volatile_1(DAT_cc008000,(char)*(undefined2 *)(pfVar5 + 0xf));
        write_volatile_4(0xcc008000,(float)dVar8);
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,pfVar5[8] - FLOAT_803dcdd8);
        write_volatile_4(0xcc008000,pfVar5[9]);
        write_volatile_4(0xcc008000,pfVar5[10] - FLOAT_803dcddc);
        write_volatile_1(DAT_cc008000,local_46[0]);
        write_volatile_1(DAT_cc008000,local_47);
        write_volatile_1(DAT_cc008000,local_48);
        write_volatile_1(DAT_cc008000,(char)*(undefined2 *)(pfVar5 + 0xb));
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,(float)dVar7);
        pfVar5 = pfVar5 + 8;
      }
    }
    iVar4 = iVar4 + 8;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 9);
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  FUN_80286128();
  return;
}

