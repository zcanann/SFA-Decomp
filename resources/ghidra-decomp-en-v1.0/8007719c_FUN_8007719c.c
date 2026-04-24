// Function: FUN_8007719c
// Entry: 8007719c
// Size: 1128 bytes

/* WARNING: Removing unreachable block (ram,0x800775dc) */
/* WARNING: Removing unreachable block (ram,0x800775e4) */

void FUN_8007719c(double param_1,double param_2,int param_3,uint param_4,uint param_5)

{
  int iVar1;
  uint uVar2;
  undefined2 uVar3;
  undefined2 uVar4;
  undefined2 uVar5;
  undefined4 uVar6;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  uint local_88;
  uint local_84;
  longlong local_80;
  longlong local_78;
  undefined4 local_70;
  int iStack108;
  longlong local_68;
  longlong local_60;
  longlong local_58;
  undefined4 local_50;
  int iStack76;
  longlong local_48;
  longlong local_40;
  longlong local_38;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  local_84 = CONCAT31(0xffff00,(char)((param_4 & 0xff) * (uint)DAT_803db679 >> 8)) | 0xff00;
  FUN_802573f8();
  FUN_80256978(0,1);
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
  local_88 = local_84;
  FUN_8025bdac(0,&local_88);
  FUN_8025be8c(0,0x1c);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025b71c(0);
  FUN_8025ba40(0,0xf,0xf,0xf,8);
  FUN_8025bac0(0,7,4,6,7);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  if (*(int *)(param_3 + 0x50) == 0) {
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
  FUN_8004c264(param_3,0);
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
  uVar2 = (uint)*(ushort *)(param_3 + 10) * 4 * (param_5 & 0xffff);
  iStack108 = ((int)uVar2 >> 8) + (uint)((int)uVar2 < 0 && (uVar2 & 0xff) != 0);
  uVar2 = (uint)*(ushort *)(param_3 + 0xc) * 4 * (param_5 & 0xffff);
  iStack76 = ((int)uVar2 >> 8) + (uint)((int)uVar2 < 0 && (uVar2 & 0xff) != 0);
  dVar7 = (double)(float)((double)FLOAT_803def2c * param_1);
  dVar8 = (double)(float)((double)FLOAT_803def2c * param_2);
  FUN_8025889c(0x80,1,4);
  write_volatile_1(DAT_cc008000,0x3c);
  local_80 = (longlong)(int)dVar7;
  uVar3 = (undefined2)(int)dVar7;
  write_volatile_2(0xcc008000,uVar3);
  local_78 = (longlong)(int)dVar8;
  uVar4 = (undefined2)(int)dVar8;
  write_volatile_2(0xcc008000,uVar4);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_1(DAT_cc008000,0x3c);
  local_70 = 0x43300000;
  iVar1 = (int)(dVar7 + (double)(float)((double)CONCAT44(0x43300000,iStack108) - DOUBLE_803def00));
  local_68 = (longlong)iVar1;
  uVar5 = (undefined2)iVar1;
  write_volatile_2(0xcc008000,uVar5);
  write_volatile_2(0xcc008000,uVar4);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deee4);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,uVar5);
  local_50 = 0x43300000;
  iVar1 = (int)(dVar8 + (double)(float)((double)CONCAT44(0x43300000,iStack76) - DOUBLE_803def00));
  local_48 = (longlong)iVar1;
  uVar4 = (undefined2)iVar1;
  write_volatile_2(0xcc008000,uVar4);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deee4);
  write_volatile_4(0xcc008000,FLOAT_803deee4);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,uVar3);
  write_volatile_2(0xcc008000,uVar4);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_4(0xcc008000,FLOAT_803deee4);
  local_60 = local_78;
  local_58 = local_68;
  local_40 = local_80;
  local_38 = local_48;
  FUN_8000fb00();
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return;
}

