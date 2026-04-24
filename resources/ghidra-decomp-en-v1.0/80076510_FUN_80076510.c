// Function: FUN_80076510
// Entry: 80076510
// Size: 780 bytes

/* WARNING: Removing unreachable block (ram,0x800767f4) */
/* WARNING: Removing unreachable block (ram,0x800767fc) */

void FUN_80076510(double param_1,double param_2,int param_3,int param_4)

{
  undefined2 uVar1;
  undefined4 uVar2;
  undefined8 in_f30;
  double dVar3;
  undefined8 in_f31;
  double dVar4;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  FUN_802573f8();
  FUN_80256978(9,1);
  FUN_8025c688(0);
  FUN_8025c0c4(0,0xff,0xff,4);
  FUN_8025b71c(0);
  FUN_8025ba40(0,0xf,0xf,0xf,0xc);
  FUN_8025bac0(0,7,7,7,7);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_80259ea4(0,0,0,1,0,0,2);
  FUN_80259ea4(2,0,0,1,0,0,2);
  FUN_80259e58(1);
  FUN_8025b6f0(0);
  FUN_802581e0(0);
  FUN_8025c2a0(1);
  FUN_80258b24(0);
  FUN_8025cf48(&DAT_80396880,1);
  if ((((DAT_803dd018 != '\x01') || (DAT_803dd014 != 7)) || (DAT_803dd012 != '\x01')) ||
     (DAT_803dd01a == '\0')) {
    FUN_8025c708(1,7,1);
    DAT_803dd018 = '\x01';
    DAT_803dd014 = 7;
    DAT_803dd012 = '\x01';
    DAT_803dd01a = '\x01';
  }
  if ((DAT_803dd011 != '\0') || (DAT_803dd019 == '\0')) {
    FUN_8025c780(0);
    DAT_803dd011 = '\0';
    DAT_803dd019 = '\x01';
  }
  FUN_8025c584(0,1,0,5);
  FUN_8025d124(0x3c);
  dVar3 = (double)(float)((double)FLOAT_803def2c * param_1);
  dVar4 = (double)(float)((double)FLOAT_803def2c * param_2);
  FUN_8025889c(0x80,1,4);
  write_volatile_2(0xcc008000,(short)(int)dVar3);
  write_volatile_2(0xcc008000,(short)(int)dVar4);
  write_volatile_2(0xcc008000,0xfe74);
  uVar1 = (undefined2)
          (int)(dVar3 + (double)(float)((double)CONCAT44(0x43300000,param_3 << 2) - DOUBLE_803def00)
               );
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_2(0xcc008000,(short)(int)dVar4);
  write_volatile_2(0xcc008000,0xfe74);
  write_volatile_2(0xcc008000,uVar1);
  uVar1 = (undefined2)
          (int)(dVar4 + (double)(float)((double)CONCAT44(0x43300000,param_4 << 2) - DOUBLE_803def00)
               );
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_2(0xcc008000,0xfe74);
  write_volatile_2(0xcc008000,(short)(int)dVar3);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_2(0xcc008000,0xfe74);
  FUN_8000fb00();
  FUN_8025c688(1);
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  return;
}

