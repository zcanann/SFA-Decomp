// Function: FUN_8011eda4
// Entry: 8011eda4
// Size: 428 bytes

/* WARNING: Removing unreachable block (ram,0x8011ef20) */
/* WARNING: Removing unreachable block (ram,0x8011ef28) */

void FUN_8011eda4(double param_1,double param_2,int param_3,int param_4,undefined4 param_5,
                 uint param_6,uint param_7)

{
  undefined2 uVar1;
  uint uVar2;
  uint uVar3;
  undefined2 uVar4;
  undefined4 uVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  FUN_8011de20(param_3,param_5,(int)(short)param_4,param_7 & 4);
  uVar2 = (uint)*(ushort *)(param_3 + 10) * 4 * (param_6 & 0xffff);
  uVar3 = (uint)*(ushort *)(param_3 + 0xc) * 4 * (param_6 & 0xffff);
  dVar6 = (double)(float)((double)FLOAT_803e1e80 * param_1);
  dVar7 = (double)(float)((double)FLOAT_803e1e80 * param_2);
  FUN_8025889c(0x80,1,4);
  write_volatile_2(0xcc008000,(short)(int)dVar6);
  write_volatile_2(0xcc008000,(short)(int)dVar7);
  uVar1 = (undefined2)(param_4 << 2);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_4(0xcc008000,FLOAT_803e1e3c);
  write_volatile_4(0xcc008000,FLOAT_803e1e3c);
  uVar4 = (undefined2)
          (int)(dVar6 + (double)(float)((double)CONCAT44(0x43300000,
                                                         ((int)uVar2 >> 8) +
                                                         (uint)((int)uVar2 < 0 &&
                                                               (uVar2 & 0xff) != 0)) -
                                       DOUBLE_803e1e88));
  write_volatile_2(0xcc008000,uVar4);
  write_volatile_2(0xcc008000,(short)(int)dVar7);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_4(0xcc008000,FLOAT_803e1e68);
  write_volatile_4(0xcc008000,FLOAT_803e1e3c);
  write_volatile_2(0xcc008000,uVar4);
  uVar4 = (undefined2)
          (int)(dVar7 + (double)(float)((double)CONCAT44(0x43300000,
                                                         ((int)uVar3 >> 8) +
                                                         (uint)((int)uVar3 < 0 &&
                                                               (uVar3 & 0xff) != 0)) -
                                       DOUBLE_803e1e88));
  write_volatile_2(0xcc008000,uVar4);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_4(0xcc008000,FLOAT_803e1e68);
  write_volatile_4(0xcc008000,FLOAT_803e1e68);
  write_volatile_2(0xcc008000,(short)(int)dVar6);
  write_volatile_2(0xcc008000,uVar4);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_4(0xcc008000,FLOAT_803e1e3c);
  write_volatile_4(0xcc008000,FLOAT_803e1e68);
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  return;
}

