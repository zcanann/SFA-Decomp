// Function: FUN_80129ff8
// Entry: 80129ff8
// Size: 248 bytes

/* WARNING: Removing unreachable block (ram,0x8012a0d8) */
/* WARNING: Removing unreachable block (ram,0x8012a0d0) */
/* WARNING: Removing unreachable block (ram,0x8012a0c8) */
/* WARNING: Removing unreachable block (ram,0x8012a018) */
/* WARNING: Removing unreachable block (ram,0x8012a010) */
/* WARNING: Removing unreachable block (ram,0x8012a008) */

void FUN_80129ff8(double param_1,double param_2,double param_3)

{
  double dVar1;
  
  dVar1 = FUN_8000fc54();
  FLOAT_803dc70c = (float)dVar1;
  FUN_8000fc5c(param_1);
  FUN_8000f478(1);
  DAT_803de460 = FUN_8000fae4();
  FUN_8000faec();
  dVar1 = (double)FLOAT_803e2abc;
  FUN_8000f530(dVar1,dVar1,dVar1);
  FUN_8000f500(0x8000,0,0);
  FUN_8000f584();
  FUN_8000fb20();
  FUN_8025da64((double)(float)(param_2 - (double)FLOAT_803e2bb4),
               (double)(float)(param_3 - (double)FLOAT_803e2ca4),
               (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 4)) -
                              DOUBLE_803e2b08),
               (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 6)) -
                              DOUBLE_803e2b08),(double)FLOAT_803e2abc,(double)FLOAT_803e2ae8);
  return;
}

