// Function: FUN_8007681c
// Entry: 8007681c
// Size: 1372 bytes

/* WARNING: Removing unreachable block (ram,0x80076d50) */
/* WARNING: Removing unreachable block (ram,0x80076d40) */
/* WARNING: Removing unreachable block (ram,0x80076d30) */
/* WARNING: Removing unreachable block (ram,0x80076d38) */
/* WARNING: Removing unreachable block (ram,0x80076d48) */
/* WARNING: Removing unreachable block (ram,0x80076d58) */

void FUN_8007681c(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7,uint param_8)

{
  uint uVar1;
  undefined2 uVar2;
  undefined2 uVar3;
  undefined2 uVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  double extraout_f1;
  double dVar8;
  undefined8 in_f26;
  undefined8 in_f27;
  double dVar9;
  undefined8 in_f28;
  double dVar10;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  undefined8 uVar14;
  uint local_d8;
  uint local_d4;
  double local_d0;
  undefined4 local_c8;
  uint uStack196;
  double local_c0;
  double local_b8;
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
  
  uVar6 = 0;
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
  uVar14 = FUN_802860d8();
  iVar5 = (int)((ulonglong)uVar14 >> 0x20);
  local_d4 = CONCAT31(0xffff00,(char)(((uint)uVar14 & 0xff) * (uint)DAT_803db679 >> 8)) | 0xff00;
  dVar7 = extraout_f1;
  FUN_802573f8();
  FUN_80256978(0,1);
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
  local_d8 = local_d4;
  FUN_8025bdac(0,&local_d8);
  FUN_8025be8c(0,0x1c);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025b71c(0);
  FUN_8025ba40(0,0xf,0xf,0xf,8);
  FUN_8025bac0(0,7,4,6,7);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  if (*(int *)(iVar5 + 0x50) == 0) {
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
  FUN_8004c264(iVar5,0);
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
  if ((param_8 & 4) == 0) {
    FUN_8025c584(1,4,5,5);
  }
  else {
    FUN_8025c584(1,4,1,5);
  }
  uVar1 = param_6 * 4 * (param_5 & 0xffff) >> 8;
  uStack156 = param_7 * 4 * (param_5 & 0xffff) >> 8;
  dVar12 = (double)(float)((double)FLOAT_803def2c * dVar7);
  dVar13 = (double)(float)((double)FLOAT_803def2c * param_2);
  local_d0 = (double)CONCAT44(0x43300000,param_6);
  uStack196 = (uint)*(ushort *)(iVar5 + 10);
  local_c8 = 0x43300000;
  dVar8 = (double)((float)(local_d0 - DOUBLE_803def00) /
                  (float)((double)CONCAT44(0x43300000,uStack196) - DOUBLE_803def00));
  local_c0 = (double)CONCAT44(0x43300000,param_7);
  local_b8 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar5 + 0xc));
  dVar7 = (double)((float)(local_c0 - DOUBLE_803def00) / (float)(local_b8 - DOUBLE_803def00));
  if ((param_8 & 1) == 0) {
    dVar11 = (double)FLOAT_803deedc;
    dVar10 = dVar8;
  }
  else {
    dVar10 = (double)FLOAT_803deedc;
    dVar11 = dVar8;
  }
  if ((param_8 & 2) == 0) {
    dVar9 = (double)FLOAT_803deedc;
    dVar8 = dVar7;
  }
  else {
    dVar8 = (double)FLOAT_803deedc;
    dVar9 = dVar7;
  }
  FUN_8025889c(0x80,1,4);
  write_volatile_1(DAT_cc008000,0x3c);
  local_b8 = (double)(longlong)(int)dVar12;
  uVar2 = (undefined2)(int)dVar12;
  write_volatile_2(0xcc008000,uVar2);
  local_c0 = (double)(longlong)(int)dVar13;
  uVar3 = (undefined2)(int)dVar13;
  write_volatile_2(0xcc008000,uVar3);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,(float)dVar11);
  write_volatile_4(0xcc008000,(float)dVar9);
  write_volatile_1(DAT_cc008000,0x3c);
  local_c8 = 0x43300000;
  iVar5 = (int)(dVar12 + (double)(float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803def00));
  local_d0 = (double)(longlong)iVar5;
  uVar4 = (undefined2)iVar5;
  write_volatile_2(0xcc008000,uVar4);
  write_volatile_2(0xcc008000,uVar3);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,(float)dVar10);
  write_volatile_4(0xcc008000,(float)dVar9);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,uVar4);
  local_a0 = 0x43300000;
  iVar5 = (int)(dVar13 + (double)(float)((double)CONCAT44(0x43300000,uStack156) - DOUBLE_803def00));
  local_98 = (longlong)iVar5;
  uVar3 = (undefined2)iVar5;
  write_volatile_2(0xcc008000,uVar3);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,(float)dVar10);
  write_volatile_4(0xcc008000,(float)dVar8);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,uVar3);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,(float)dVar11);
  write_volatile_4(0xcc008000,(float)dVar8);
  uStack196 = uVar1;
  local_b0 = (longlong)local_c0;
  local_a8 = (longlong)local_d0;
  local_90 = (longlong)local_b8;
  local_88 = local_98;
  FUN_8000fb00();
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  __psq_l0(auStack56,uVar6);
  __psq_l1(auStack56,uVar6);
  __psq_l0(auStack72,uVar6);
  __psq_l1(auStack72,uVar6);
  __psq_l0(auStack88,uVar6);
  __psq_l1(auStack88,uVar6);
  FUN_80286124();
  return;
}

