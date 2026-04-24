// Function: FUN_8011e690
// Entry: 8011e690
// Size: 584 bytes

/* WARNING: Removing unreachable block (ram,0x8011e8a8) */
/* WARNING: Removing unreachable block (ram,0x8011e898) */
/* WARNING: Removing unreachable block (ram,0x8011e8a0) */
/* WARNING: Removing unreachable block (ram,0x8011e8b0) */

void FUN_8011e690(double param_1,double param_2,double param_3,double param_4,int param_5,
                 int param_6,int param_7,int param_8)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  short sVar5;
  short sVar6;
  short sVar7;
  undefined4 uVar8;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  FUN_8025d0a8(&DAT_803a8830,0);
  FUN_8025d0e4(&DAT_803a8830,0);
  FUN_8025d124(0);
  FUN_802573f8();
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
  FUN_80258b24(0);
  fVar1 = (float)((double)CONCAT44(0x43300000,param_5 - 0x500U ^ 0x80000000) - DOUBLE_803e1e78) *
          FLOAT_803dba8c;
  fVar2 = (float)((double)CONCAT44(0x43300000,param_6 - 0x3c0U ^ 0x80000000) - DOUBLE_803e1e78) *
          FLOAT_803dba8c;
  fVar3 = (float)((double)CONCAT44(0x43300000,param_7 - 0x500U ^ 0x80000000) - DOUBLE_803e1e78) *
          FLOAT_803dba8c;
  fVar4 = (float)((double)CONCAT44(0x43300000,param_8 - 0x3c0U ^ 0x80000000) - DOUBLE_803e1e78) *
          FLOAT_803dba8c;
  FUN_8025889c(0x80,1,4);
  sVar5 = (short)(int)fVar1 + 0x500;
  write_volatile_2(0xcc008000,sVar5);
  sVar6 = (short)(int)fVar2 + 0x3c0;
  write_volatile_2(0xcc008000,sVar6);
  write_volatile_2(0xcc008000,(short)((int)DAT_803dba8a << 2));
  write_volatile_4(0xcc008000,(float)param_1);
  write_volatile_4(0xcc008000,(float)param_2);
  sVar7 = (short)(int)fVar3 + 0x500;
  write_volatile_2(0xcc008000,sVar7);
  write_volatile_2(0xcc008000,sVar6);
  write_volatile_2(0xcc008000,(short)((int)DAT_803dba8a << 2));
  write_volatile_4(0xcc008000,(float)param_3);
  write_volatile_4(0xcc008000,(float)param_2);
  write_volatile_2(0xcc008000,sVar7);
  sVar6 = (short)(int)fVar4 + 0x3c0;
  write_volatile_2(0xcc008000,sVar6);
  write_volatile_2(0xcc008000,(short)((int)DAT_803dba8a << 2));
  write_volatile_4(0xcc008000,(float)param_3);
  write_volatile_4(0xcc008000,(float)param_4);
  write_volatile_2(0xcc008000,sVar5);
  write_volatile_2(0xcc008000,sVar6);
  write_volatile_2(0xcc008000,(short)((int)DAT_803dba8a << 2));
  write_volatile_4(0xcc008000,(float)param_1);
  write_volatile_4(0xcc008000,(float)param_4);
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  return;
}

