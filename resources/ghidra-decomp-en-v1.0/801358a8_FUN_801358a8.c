// Function: FUN_801358a8
// Entry: 801358a8
// Size: 488 bytes

/* WARNING: Removing unreachable block (ram,0x80135a68) */
/* WARNING: Removing unreachable block (ram,0x80135a58) */
/* WARNING: Removing unreachable block (ram,0x80135a60) */
/* WARNING: Removing unreachable block (ram,0x80135a70) */

void FUN_801358a8(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,short param_7,undefined2 param_8)

{
  short sVar3;
  int iVar1;
  int iVar2;
  undefined2 extraout_r4;
  undefined4 uVar4;
  double extraout_f1;
  undefined8 in_f28;
  double dVar5;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  sVar3 = FUN_802860dc();
  dVar5 = extraout_f1;
  FUN_8025d0a8(&DAT_803a9fe4,0);
  FUN_8025d124(0);
  FUN_8025cf48(&DAT_80396880,1);
  FUN_802573f8();
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
  FUN_80258b24(0);
  iVar1 = FUN_80285fb4((double)DAT_803aa000);
  iVar2 = FUN_80285fb4((double)DAT_803a9ff0);
  FUN_8025d324(iVar2 + 0x39,iVar1 + 0x4e,0x104,0x16);
  FUN_8025889c(0x80,1,4);
  write_volatile_2(0xcc008000,(sVar3 - (short)(DAT_803dd9bc << 2)) + 0x208);
  write_volatile_2(0xcc008000,extraout_r4);
  write_volatile_2(0xcc008000,0xffe0);
  write_volatile_4(0xcc008000,(float)dVar5);
  write_volatile_4(0xcc008000,(float)param_2);
  write_volatile_2(0xcc008000,(param_7 - (short)(DAT_803dd9bc << 2)) + 0x208);
  write_volatile_2(0xcc008000,extraout_r4);
  write_volatile_2(0xcc008000,0xffe0);
  write_volatile_4(0xcc008000,(float)param_3);
  write_volatile_4(0xcc008000,(float)param_2);
  write_volatile_2(0xcc008000,(param_7 - (short)(DAT_803dd9bc << 2)) + 0x208);
  write_volatile_2(0xcc008000,param_8);
  write_volatile_2(0xcc008000,0xffe0);
  write_volatile_4(0xcc008000,(float)param_3);
  write_volatile_4(0xcc008000,(float)param_4);
  write_volatile_2(0xcc008000,(sVar3 - (short)(DAT_803dd9bc << 2)) + 0x208);
  write_volatile_2(0xcc008000,param_8);
  write_volatile_2(0xcc008000,0xffe0);
  write_volatile_4(0xcc008000,(float)dVar5);
  write_volatile_4(0xcc008000,(float)param_4);
  FUN_8025d324(0,0,0x280,0x1e0);
  FUN_8000fb00();
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  __psq_l0(auStack56,uVar4);
  __psq_l1(auStack56,uVar4);
  FUN_80286128();
  return;
}

