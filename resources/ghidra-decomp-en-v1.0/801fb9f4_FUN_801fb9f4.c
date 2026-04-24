// Function: FUN_801fb9f4
// Entry: 801fb9f4
// Size: 152 bytes

/* WARNING: Removing unreachable block (ram,0x801fba70) */

void FUN_801fb9f4(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  double dVar3;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar1 = FUN_8002b9ec();
  dVar3 = (double)FUN_80021704(iVar1 + 0x18,param_1 + 0x18);
  iVar1 = FUN_8000b578(param_1,0x40);
  if (iVar1 == 0) {
    if ((double)FLOAT_803e6100 <= dVar3) {
      FUN_8000b7bc(param_1,0x40);
    }
  }
  else if (dVar3 < (double)FLOAT_803e6100) {
    FUN_8000bb18(param_1,0x110);
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

