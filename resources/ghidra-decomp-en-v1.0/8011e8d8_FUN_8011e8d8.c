// Function: FUN_8011e8d8
// Entry: 8011e8d8
// Size: 612 bytes

/* WARNING: Removing unreachable block (ram,0x8011eb14) */
/* WARNING: Removing unreachable block (ram,0x8011eb04) */
/* WARNING: Removing unreachable block (ram,0x8011eaf4) */
/* WARNING: Removing unreachable block (ram,0x8011eafc) */
/* WARNING: Removing unreachable block (ram,0x8011eb0c) */
/* WARNING: Removing unreachable block (ram,0x8011eb1c) */

void FUN_8011e8d8(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,int param_7,int param_8,int param_9)

{
  undefined2 uVar1;
  undefined2 uVar2;
  int iVar3;
  undefined4 uVar4;
  double extraout_f1;
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
  double dVar10;
  undefined8 uVar11;
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
  uVar11 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar11 >> 0x20);
  dVar5 = extraout_f1;
  FUN_8011de20(iVar3,param_5,(int)(short)uVar11,0);
  dVar6 = (double)(float)((double)FLOAT_803e1e80 * dVar5);
  dVar7 = (double)(float)((double)FLOAT_803e1e80 * param_2);
  dVar9 = (double)((float)((double)CONCAT44(0x43300000,param_8) - DOUBLE_803e1e88) /
                  (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 10)) -
                         DOUBLE_803e1e88));
  dVar8 = (double)((float)((double)CONCAT44(0x43300000,param_9) - DOUBLE_803e1e88) /
                  (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0xc)) -
                         DOUBLE_803e1e88));
  dVar10 = (double)((float)((double)CONCAT44(0x43300000,param_6 + param_8) - DOUBLE_803e1e88) /
                   (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 10)) -
                          DOUBLE_803e1e88));
  dVar5 = (double)((float)((double)CONCAT44(0x43300000,param_7 + param_9) - DOUBLE_803e1e88) /
                  (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0xc)) -
                         DOUBLE_803e1e88));
  FUN_8025889c(0x80,1,4);
  write_volatile_2(0xcc008000,(short)(int)dVar6);
  write_volatile_2(0xcc008000,(short)(int)dVar7);
  uVar1 = (undefined2)((int)uVar11 << 2);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_4(0xcc008000,(float)dVar9);
  write_volatile_4(0xcc008000,(float)dVar8);
  uVar2 = (undefined2)
          (int)(dVar6 + (double)(float)((double)CONCAT44(0x43300000,param_6 << 2) - DOUBLE_803e1e88)
               );
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,(short)(int)dVar7);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_4(0xcc008000,(float)dVar10);
  write_volatile_4(0xcc008000,(float)dVar8);
  write_volatile_2(0xcc008000,uVar2);
  uVar2 = (undefined2)
          (int)(dVar7 + (double)(float)((double)CONCAT44(0x43300000,param_7 << 2) - DOUBLE_803e1e88)
               );
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_4(0xcc008000,(float)dVar10);
  write_volatile_4(0xcc008000,(float)dVar5);
  write_volatile_2(0xcc008000,(short)(int)dVar6);
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_4(0xcc008000,(float)dVar9);
  write_volatile_4(0xcc008000,(float)dVar5);
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
  FUN_80286124();
  return;
}

