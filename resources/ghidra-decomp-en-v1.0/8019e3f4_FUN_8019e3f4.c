// Function: FUN_8019e3f4
// Entry: 8019e3f4
// Size: 372 bytes

/* WARNING: Removing unreachable block (ram,0x8019e548) */

undefined4 FUN_8019e3f4(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  double dVar3;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar1 = *(int *)(param_1 + 0xb8);
  if ((*(short *)(param_1 + 0xa0) != 5) && (*(short *)(param_1 + 0xa0) != 0xd)) {
    FUN_80030334((double)*(float *)(param_1 + 0x98),param_1,0xd,0);
  }
  if ((*(short *)(param_1 + 0xa0) == 5) && (FLOAT_803e422c < *(float *)(param_1 + 0x28))) {
    FUN_80030334((double)*(float *)(param_1 + 0x98),param_1,0xd,0);
  }
  if ((*(short *)(param_1 + 0xa0) == 0xd) && (*(float *)(param_1 + 0x28) < FLOAT_803e4218)) {
    FUN_80030334((double)*(float *)(param_1 + 0x98),param_1,5,0);
  }
  dVar3 = (double)((*(float *)(param_1 + 0x28) * FLOAT_803dbe4c + FLOAT_803e4230) * FLOAT_803e4234);
  if (dVar3 < (double)FLOAT_803e4218) {
    dVar3 = (double)FLOAT_803e4218;
  }
  if ((double)FLOAT_803e4234 < dVar3) {
    dVar3 = (double)FLOAT_803e4234;
  }
  if (*(short *)(param_1 + 0xa0) == 0xd) {
    if (*(float *)(param_1 + 0x98) <= FLOAT_803e4234) {
      *(byte *)(iVar1 + 0x244) = *(byte *)(iVar1 + 0x244) & 0xbf;
    }
    else if ((*(byte *)(iVar1 + 0x244) >> 6 & 1) == 0) {
      FUN_8000bb18(param_1,0x334);
      *(byte *)(iVar1 + 0x244) = *(byte *)(iVar1 + 0x244) & 0xbf | 0x40;
    }
  }
  FUN_8002fa48(dVar3,(double)FLOAT_803db414,param_1,0);
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return 1;
}

