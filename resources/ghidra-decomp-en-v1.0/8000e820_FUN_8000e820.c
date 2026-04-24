// Function: FUN_8000e820
// Entry: 8000e820
// Size: 292 bytes

/* WARNING: Removing unreachable block (ram,0x8000e920) */

void FUN_8000e820(double param_1,undefined4 param_2,undefined4 param_3,int param_4,
                 undefined *param_5)

{
  undefined *puVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  puVar1 = param_5;
  if (param_5 == (undefined *)0x0) {
    puVar1 = &DAT_80338190;
  }
  *(float *)(param_4 + 0xc) = *(float *)(param_4 + 0xc) - FLOAT_803dcdd8;
  *(float *)(param_4 + 0x14) = *(float *)(param_4 + 0x14) - FLOAT_803dcddc;
  FUN_80021ee8(puVar1,param_4);
  if ((double)FLOAT_803de5f0 != param_1) {
    FUN_80021ec0(param_1,puVar1);
  }
  if (param_5 == (undefined *)0x0) {
    FUN_80021608(puVar1,&DAT_803967c0);
  }
  else {
    FUN_80021608(param_5,&DAT_803967c0);
  }
  FUN_80246eb4(&DAT_803386d0,&DAT_803967c0,&DAT_803967c0);
  FUN_8025d0a8(&DAT_803967c0,0);
  *(float *)(param_4 + 0xc) = *(float *)(param_4 + 0xc) + FLOAT_803dcdd8;
  *(float *)(param_4 + 0x14) = *(float *)(param_4 + 0x14) + FLOAT_803dcddc;
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

