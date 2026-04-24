// Function: FUN_80129cbc
// Entry: 80129cbc
// Size: 248 bytes

/* WARNING: Removing unreachable block (ram,0x80129d94) */
/* WARNING: Removing unreachable block (ram,0x80129d8c) */
/* WARNING: Removing unreachable block (ram,0x80129d9c) */

void FUN_80129cbc(undefined8 param_1,double param_2,double param_3)

{
  undefined4 uVar1;
  double dVar2;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
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
  dVar2 = (double)FUN_8000fc34();
  FLOAT_803dbaa4 = (float)dVar2;
  FUN_8000fc3c(param_1);
  FUN_8000f458(1);
  DAT_803dd7e0 = FUN_8000fac4();
  FUN_8000facc();
  dVar2 = (double)FLOAT_803e1e3c;
  FUN_8000f510(dVar2,dVar2,dVar2);
  FUN_8000f4e0(0x8000,0,0);
  FUN_8000f564();
  FUN_8000fb00();
  FUN_8025d300((double)(float)(param_2 - (double)FLOAT_803e1f34),
               (double)(float)(param_3 - (double)FLOAT_803e2024),
               (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 4)) -
                              DOUBLE_803e1e88),
               (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 8)) -
                              DOUBLE_803e1e88),(double)FLOAT_803e1e3c,(double)FLOAT_803e1e68);
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  __psq_l0(auStack24,uVar1);
  __psq_l1(auStack24,uVar1);
  __psq_l0(auStack40,uVar1);
  __psq_l1(auStack40,uVar1);
  return;
}

