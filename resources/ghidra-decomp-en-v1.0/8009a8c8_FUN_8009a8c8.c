// Function: FUN_8009a8c8
// Entry: 8009a8c8
// Size: 164 bytes

/* WARNING: Removing unreachable block (ram,0x8009a950) */

void FUN_8009a8c8(double param_1,int param_2)

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
  if (((iVar1 != 0) && ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)) &&
     (dVar3 = (double)FUN_8000f480((double)*(float *)(param_2 + 0x18),
                                   (double)*(float *)(param_2 + 0x1c),
                                   (double)*(float *)(param_2 + 0x20)), dVar3 <= param_1)) {
    dVar3 = (double)(FLOAT_803df354 - (float)(dVar3 / param_1));
    FUN_8000e650((double)(float)((double)FLOAT_803df3a0 * dVar3),
                 (double)(float)((double)FLOAT_803df384 * dVar3),(double)FLOAT_803df3a4);
    FUN_80014aa0((double)(float)((double)FLOAT_803df3a8 * dVar3));
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

