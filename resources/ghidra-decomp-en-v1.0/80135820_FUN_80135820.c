// Function: FUN_80135820
// Entry: 80135820
// Size: 136 bytes

/* WARNING: Removing unreachable block (ram,0x80135888) */
/* WARNING: Removing unreachable block (ram,0x80135890) */

void FUN_80135820(double param_1,double param_2)

{
  undefined4 uVar1;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  FUN_802472e4(param_1,param_2,(double)FLOAT_803e22f8,&DAT_803a9fe4);
  FLOAT_803dd9c8 = (float)((double)FLOAT_803e2344 - param_2) / FLOAT_803e2348;
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  __psq_l0(auStack24,uVar1);
  __psq_l1(auStack24,uVar1);
  FLOAT_803dd9b0 = FLOAT_803e2318 - FLOAT_803dd9c8;
  FLOAT_803dd9b4 = (float)(param_1 - (double)FLOAT_803e234c) / FLOAT_803e2350;
  return;
}

