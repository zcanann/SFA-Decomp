// Function: FUN_80129db4
// Entry: 80129db4
// Size: 300 bytes

/* WARNING: Removing unreachable block (ram,0x80129ec8) */

void FUN_80129db4(void)

{
  undefined4 uVar1;
  double dVar2;
  undefined8 uVar3;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (DAT_803dd780 != '\0') {
    FUN_8000f458(1);
    dVar2 = (double)FLOAT_803e1e3c;
    FUN_8000f510(dVar2,dVar2,dVar2);
    FUN_8000f4e0(0x8000,0,0);
    uVar3 = FUN_8000fc34();
    FUN_8000fc3c((double)FLOAT_803e2044);
    FUN_8000fb00();
    FUN_8000f564();
    dVar2 = (double)FLOAT_803e1e3c;
    FUN_8025d300(dVar2,dVar2,
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 4)) -
                                DOUBLE_803e1e88),
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 8)) -
                                DOUBLE_803e1e88),dVar2,(double)FLOAT_803e1e68);
    FUN_8006b558((&DAT_803a9410)[DAT_803dba64]);
    if (0x90000000 < *(uint *)((&DAT_803a9410)[DAT_803dba64] + 0x4c)) {
      *(undefined4 *)((&DAT_803a9410)[DAT_803dba64] + 0x4c) = 0;
    }
    FUN_8000f458(0);
    FUN_8000fc3c(uVar3);
    FUN_8000fb00();
    FUN_8000f564();
    FUN_8000f780();
  }
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  return;
}

