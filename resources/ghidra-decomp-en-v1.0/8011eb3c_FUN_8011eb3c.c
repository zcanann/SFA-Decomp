// Function: FUN_8011eb3c
// Entry: 8011eb3c
// Size: 616 bytes

/* WARNING: Removing unreachable block (ram,0x8011ed7c) */
/* WARNING: Removing unreachable block (ram,0x8011ed6c) */
/* WARNING: Removing unreachable block (ram,0x8011ed5c) */
/* WARNING: Removing unreachable block (ram,0x8011ed64) */
/* WARNING: Removing unreachable block (ram,0x8011ed74) */
/* WARNING: Removing unreachable block (ram,0x8011ed84) */

void FUN_8011eb3c(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6,int param_7,int param_8,uint param_9)

{
  undefined2 uVar1;
  undefined2 uVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  double extraout_f1;
  double dVar6;
  undefined8 in_f26;
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
  double local_d8;
  double local_c8;
  double local_c0;
  undefined auStack88 [16];
  undefined auStack72 [16];
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
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  uVar12 = FUN_802860d4();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  dVar5 = extraout_f1;
  FUN_8011de20(iVar3,param_5,(int)(short)uVar12,param_9 & 4);
  dVar10 = (double)(float)((double)FLOAT_803e1e80 * dVar5);
  dVar11 = (double)(float)((double)FLOAT_803e1e80 * param_2);
  local_d8 = (double)CONCAT44(0x43300000,param_7);
  dVar6 = (double)((float)(local_d8 - DOUBLE_803e1e88) /
                  (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 10)) -
                         DOUBLE_803e1e88));
  local_c8 = (double)CONCAT44(0x43300000,param_8);
  local_c0 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0xc));
  dVar5 = (double)((float)(local_c8 - DOUBLE_803e1e88) / (float)(local_c0 - DOUBLE_803e1e88));
  if ((param_9 & 1) == 0) {
    dVar9 = (double)FLOAT_803e1e3c;
    dVar8 = dVar6;
  }
  else {
    dVar8 = (double)FLOAT_803e1e3c;
    dVar9 = dVar6;
  }
  if ((param_9 & 2) == 0) {
    dVar7 = (double)FLOAT_803e1e3c;
    dVar6 = dVar5;
  }
  else {
    dVar6 = (double)FLOAT_803e1e3c;
    dVar7 = dVar5;
  }
  FUN_8025889c(0x80,1,4);
  write_volatile_2(0xcc008000,(short)(int)dVar10);
  write_volatile_2(0xcc008000,(short)(int)dVar11);
  uVar1 = (undefined2)((int)uVar12 << 2);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_4(0xcc008000,(float)dVar9);
  write_volatile_4(0xcc008000,(float)dVar7);
  uVar2 = (undefined2)
          (int)(dVar10 + (double)(float)((double)CONCAT44(0x43300000,
                                                          param_7 * 4 * (param_6 & 0xffff) >> 8) -
                                        DOUBLE_803e1e88));
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,(short)(int)dVar11);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_4(0xcc008000,(float)dVar8);
  write_volatile_4(0xcc008000,(float)dVar7);
  write_volatile_2(0xcc008000,uVar2);
  uVar2 = (undefined2)
          (int)(dVar11 + (double)(float)((double)CONCAT44(0x43300000,
                                                          param_8 * 4 * (param_6 & 0xffff) >> 8) -
                                        DOUBLE_803e1e88));
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_4(0xcc008000,(float)dVar8);
  write_volatile_4(0xcc008000,(float)dVar6);
  write_volatile_2(0xcc008000,(short)(int)dVar10);
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_4(0xcc008000,(float)dVar9);
  write_volatile_4(0xcc008000,(float)dVar6);
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  __psq_l0(auStack56,uVar4);
  __psq_l1(auStack56,uVar4);
  __psq_l0(auStack72,uVar4);
  __psq_l1(auStack72,uVar4);
  __psq_l0(auStack88,uVar4);
  __psq_l1(auStack88,uVar4);
  FUN_80286120();
  return;
}

