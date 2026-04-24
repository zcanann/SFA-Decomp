// Function: FUN_80075684
// Entry: 80075684
// Size: 920 bytes

/* WARNING: Removing unreachable block (ram,0x800759f8) */
/* WARNING: Removing unreachable block (ram,0x800759e8) */
/* WARNING: Removing unreachable block (ram,0x800759d8) */
/* WARNING: Removing unreachable block (ram,0x800759c8) */
/* WARNING: Removing unreachable block (ram,0x800759d0) */
/* WARNING: Removing unreachable block (ram,0x800759e0) */
/* WARNING: Removing unreachable block (ram,0x800759f0) */
/* WARNING: Removing unreachable block (ram,0x80075a00) */

void FUN_80075684(double param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,double param_7,double param_8,undefined4 *param_9)

{
  undefined4 uVar1;
  double dVar2;
  undefined8 in_f24;
  double dVar3;
  undefined8 in_f25;
  double dVar4;
  undefined8 in_f26;
  double dVar5;
  undefined8 in_f27;
  double dVar6;
  undefined8 in_f28;
  double dVar7;
  undefined8 in_f29;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  undefined4 local_d8 [2];
  longlong local_d0;
  longlong local_c8;
  longlong local_c0;
  longlong local_b8;
  longlong local_b0;
  longlong local_a8;
  longlong local_a0;
  longlong local_98;
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  dVar2 = (double)FLOAT_803def2c;
  dVar3 = (double)(float)(dVar2 * param_1);
  dVar4 = (double)(float)(dVar2 * param_2);
  dVar5 = (double)(float)(dVar2 * param_3);
  dVar6 = (double)(float)(dVar2 * param_4);
  dVar7 = (double)(float)(dVar2 * param_5);
  dVar8 = (double)(float)(dVar2 * param_6);
  dVar9 = (double)(float)(dVar2 * param_7);
  dVar2 = (double)(float)(dVar2 * param_8);
  FUN_802573f8();
  FUN_80256978(0,1);
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
  FUN_80258b24(0);
  FUN_8025cf48(&DAT_80396880,1);
  if ((((DAT_803dd018 != '\0') || (DAT_803dd014 != 7)) || (DAT_803dd012 != '\0')) ||
     (DAT_803dd01a == '\0')) {
    FUN_8025c708(0,7,0);
    DAT_803dd018 = '\0';
    DAT_803dd014 = 7;
    DAT_803dd012 = '\0';
    DAT_803dd01a = '\x01';
  }
  FUN_8025c584(1,4,5,5);
  *(char *)((int)param_9 + 3) = (char)((uint)*(byte *)((int)param_9 + 3) * (uint)DAT_803db679 >> 8);
  local_d8[0] = *param_9;
  FUN_8025bdac(0,local_d8);
  FUN_8025be8c(0,0x1c);
  FUN_8025be20(0,0xc);
  FUN_8025c0c4(0,0xff,0xff,4);
  FUN_8025b71c(0);
  FUN_8025ba40(0,0xf,0xf,0xf,0xe);
  FUN_8025bac0(0,7,7,7,6);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_80259ea4(0,0,0,1,0,0,2);
  FUN_80259ea4(2,0,0,1,0,0,2);
  FUN_80259e58(1);
  FUN_8025b6f0(0);
  FUN_802581e0(0);
  FUN_8025c2a0(1);
  FUN_8025889c(0x80,1,4);
  write_volatile_1(DAT_cc008000,0x3c);
  local_d0 = (longlong)(int)dVar3;
  write_volatile_2(0xcc008000,(short)(int)dVar3);
  local_c8 = (longlong)(int)dVar4;
  write_volatile_2(0xcc008000,(short)(int)dVar4);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_1(DAT_cc008000,0x3c);
  local_c0 = (longlong)(int)dVar5;
  write_volatile_2(0xcc008000,(short)(int)dVar5);
  local_b8 = (longlong)(int)dVar6;
  write_volatile_2(0xcc008000,(short)(int)dVar6);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_1(DAT_cc008000,0x3c);
  local_b0 = (longlong)(int)dVar7;
  write_volatile_2(0xcc008000,(short)(int)dVar7);
  local_a8 = (longlong)(int)dVar8;
  write_volatile_2(0xcc008000,(short)(int)dVar8);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_1(DAT_cc008000,0x3c);
  local_a0 = (longlong)(int)dVar9;
  write_volatile_2(0xcc008000,(short)(int)dVar9);
  local_98 = (longlong)(int)dVar2;
  write_volatile_2(0xcc008000,(short)(int)dVar2);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  FUN_8000fb00();
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  __psq_l0(auStack24,uVar1);
  __psq_l1(auStack24,uVar1);
  __psq_l0(auStack40,uVar1);
  __psq_l1(auStack40,uVar1);
  __psq_l0(auStack56,uVar1);
  __psq_l1(auStack56,uVar1);
  __psq_l0(auStack72,uVar1);
  __psq_l1(auStack72,uVar1);
  __psq_l0(auStack88,uVar1);
  __psq_l1(auStack88,uVar1);
  __psq_l0(auStack104,uVar1);
  __psq_l1(auStack104,uVar1);
  __psq_l0(auStack120,uVar1);
  __psq_l1(auStack120,uVar1);
  return;
}

