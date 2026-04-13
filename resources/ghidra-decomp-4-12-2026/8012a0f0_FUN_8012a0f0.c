// Function: FUN_8012a0f0
// Entry: 8012a0f0
// Size: 300 bytes

/* WARNING: Removing unreachable block (ram,0x8012a204) */
/* WARNING: Removing unreachable block (ram,0x8012a100) */

void FUN_8012a0f0(void)

{
  double dVar1;
  double dVar2;
  
  if (DAT_803de400 != '\0') {
    FUN_8000f478(1);
    dVar1 = (double)FLOAT_803e2abc;
    FUN_8000f530(dVar1,dVar1,dVar1);
    FUN_8000f500(0x8000,0,0);
    dVar1 = FUN_8000fc54();
    FUN_8000fc5c((double)FLOAT_803e2cc4);
    FUN_8000fb20();
    FUN_8000f584();
    dVar2 = (double)FLOAT_803e2abc;
    FUN_8025da64(dVar2,dVar2,
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 4)) -
                                DOUBLE_803e2b08),
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 6)) -
                                DOUBLE_803e2b08),dVar2,(double)FLOAT_803e2ae8);
    FUN_8006b6d4((ushort *)(&DAT_803aa070)[DAT_803dc6cc]);
    if (0x90000000 < *(uint *)((&DAT_803aa070)[DAT_803dc6cc] + 0x4c)) {
      *(undefined4 *)((&DAT_803aa070)[DAT_803dc6cc] + 0x4c) = 0;
    }
    FUN_8000f478(0);
    FUN_8000fc5c(dVar1);
    FUN_8000fb20();
    FUN_8000f584();
    FUN_8000f7a0();
  }
  return;
}

