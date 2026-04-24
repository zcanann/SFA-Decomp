// Function: FUN_80075fc8
// Entry: 80075fc8
// Size: 1352 bytes

/* WARNING: Removing unreachable block (ram,0x800764e8) */
/* WARNING: Removing unreachable block (ram,0x800764d8) */
/* WARNING: Removing unreachable block (ram,0x800764c8) */
/* WARNING: Removing unreachable block (ram,0x800764d0) */
/* WARNING: Removing unreachable block (ram,0x800764e0) */
/* WARNING: Removing unreachable block (ram,0x800764f0) */

void FUN_80075fc8(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7,int param_8,int param_9)

{
  undefined2 uVar1;
  undefined2 uVar2;
  undefined2 uVar3;
  int iVar4;
  undefined4 uVar5;
  double extraout_f1;
  undefined8 in_f26;
  double dVar6;
  undefined8 in_f27;
  double dVar7;
  undefined8 in_f28;
  double dVar8;
  undefined8 in_f29;
  double dVar9;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  undefined8 uVar12;
  uint local_118;
  uint local_114;
  undefined4 local_110;
  int iStack268;
  undefined4 local_108;
  uint uStack260;
  undefined4 local_100;
  int iStack252;
  undefined4 local_f8;
  uint uStack244;
  undefined4 local_f0;
  int iStack236;
  undefined4 local_e8;
  uint uStack228;
  undefined4 local_e0;
  int iStack220;
  undefined4 local_d8;
  uint uStack212;
  longlong local_d0;
  longlong local_c8;
  undefined4 local_c0;
  uint uStack188;
  longlong local_b8;
  longlong local_b0;
  longlong local_a8;
  undefined4 local_a0;
  uint uStack156;
  longlong local_98;
  longlong local_90;
  longlong local_88;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
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
  uVar12 = FUN_802860d4();
  iVar4 = (int)((ulonglong)uVar12 >> 0x20);
  local_114 = CONCAT31(0xffff00,(char)(((uint)uVar12 & 0xff) * (uint)DAT_803db679 >> 8)) | 0xff00;
  dVar6 = extraout_f1;
  FUN_802573f8();
  FUN_80256978(0,1);
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
  local_118 = local_114;
  FUN_8025bdac(0,&local_118);
  FUN_8025be8c(0,0x1c);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025b71c(0);
  FUN_8025ba40(0,0xf,0xf,0xf,8);
  FUN_8025bac0(0,7,4,6,7);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  if (*(int *)(iVar4 + 0x50) == 0) {
    FUN_8025c2a0(1);
  }
  else {
    FUN_8025be8c(1,0x1c);
    FUN_8025c0c4(1,0,1,0xff);
    FUN_8025b71c(1);
    FUN_8025ba40(1,0xf,0xf,0xf,0);
    FUN_8025bac0(1,7,4,6,7);
    FUN_8025bef8(1,0,0);
    FUN_8025bb44(1,0,0,0,1,0);
    FUN_8025bc04(1,0,0,0,1,0);
    FUN_8025c2a0(2);
  }
  FUN_8025b6f0(0);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  FUN_802581e0(1);
  FUN_80257f10(0,1,4,0x3c,0,0x7d);
  FUN_8004c264(iVar4,0);
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
  uStack188 = param_6 * 4 * (param_5 & 0xffff) >> 8;
  dVar7 = (double)(float)((double)FLOAT_803def2c * dVar6);
  dVar8 = (double)(float)((double)FLOAT_803def2c * param_2);
  local_110 = 0x43300000;
  uStack260 = (uint)*(ushort *)(iVar4 + 10);
  local_108 = 0x43300000;
  dVar10 = (double)((float)((double)CONCAT44(0x43300000,param_8) - DOUBLE_803def00) /
                   (float)((double)CONCAT44(0x43300000,uStack260) - DOUBLE_803def00));
  local_100 = 0x43300000;
  uStack244 = (uint)*(ushort *)(iVar4 + 0xc);
  local_f8 = 0x43300000;
  dVar9 = (double)((float)((double)CONCAT44(0x43300000,param_9) - DOUBLE_803def00) /
                  (float)((double)CONCAT44(0x43300000,uStack244) - DOUBLE_803def00));
  iStack236 = param_6 + param_8;
  local_f0 = 0x43300000;
  local_e8 = 0x43300000;
  dVar11 = (double)((float)((double)CONCAT44(0x43300000,iStack236) - DOUBLE_803def00) /
                   (float)((double)CONCAT44(0x43300000,uStack260) - DOUBLE_803def00));
  iStack220 = param_7 + param_9;
  local_e0 = 0x43300000;
  local_d8 = 0x43300000;
  dVar6 = (double)((float)((double)CONCAT44(0x43300000,iStack220) - DOUBLE_803def00) /
                  (float)((double)CONCAT44(0x43300000,uStack244) - DOUBLE_803def00));
  iStack268 = param_8;
  iStack252 = param_9;
  uStack228 = uStack260;
  uStack212 = uStack244;
  FUN_8025889c(0x80,1,4);
  write_volatile_1(DAT_cc008000,0x3c);
  local_d0 = (longlong)(int)dVar7;
  uVar1 = (undefined2)(int)dVar7;
  write_volatile_2(0xcc008000,uVar1);
  local_c8 = (longlong)(int)dVar8;
  uVar2 = (undefined2)(int)dVar8;
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,(float)dVar10);
  write_volatile_4(0xcc008000,(float)dVar9);
  write_volatile_1(DAT_cc008000,0x3c);
  local_c0 = 0x43300000;
  iVar4 = (int)(dVar7 + (double)(float)((double)CONCAT44(0x43300000,uStack188) - DOUBLE_803def00));
  local_b8 = (longlong)iVar4;
  uVar3 = (undefined2)iVar4;
  write_volatile_2(0xcc008000,uVar3);
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,(float)dVar11);
  write_volatile_4(0xcc008000,(float)dVar9);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,uVar3);
  uStack156 = param_7 * 4 * (param_5 & 0xffff) >> 8;
  local_a0 = 0x43300000;
  iVar4 = (int)(dVar8 + (double)(float)((double)CONCAT44(0x43300000,uStack156) - DOUBLE_803def00));
  local_98 = (longlong)iVar4;
  uVar2 = (undefined2)iVar4;
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,(float)dVar11);
  write_volatile_4(0xcc008000,(float)dVar6);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,(float)dVar10);
  write_volatile_4(0xcc008000,(float)dVar6);
  local_b0 = local_c8;
  local_a8 = local_b8;
  local_90 = local_d0;
  local_88 = local_98;
  FUN_8000fb00();
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  __psq_l0(auStack40,uVar5);
  __psq_l1(auStack40,uVar5);
  __psq_l0(auStack56,uVar5);
  __psq_l1(auStack56,uVar5);
  __psq_l0(auStack72,uVar5);
  __psq_l1(auStack72,uVar5);
  __psq_l0(auStack88,uVar5);
  __psq_l1(auStack88,uVar5);
  FUN_80286120();
  return;
}

