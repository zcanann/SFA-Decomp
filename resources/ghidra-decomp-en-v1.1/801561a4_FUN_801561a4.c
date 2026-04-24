// Function: FUN_801561a4
// Entry: 801561a4
// Size: 280 bytes

void FUN_801561a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  bool bVar1;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float local_18 [4];
  
  (**(code **)(*DAT_803dd6d8 + 0x14))(local_18);
  if ((local_18[0] < FLOAT_803e3708) || (FLOAT_803e370c < local_18[0])) {
    bVar1 = false;
  }
  else {
    bVar1 = true;
  }
  if ((bVar1) && (*(char *)(param_10 + 0x33a) == '\0')) {
    *(undefined *)(param_10 + 0x33a) = 1;
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
    FUN_8014d504((double)FLOAT_803e3710,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,1,0,0,in_r8,in_r9,in_r10);
  }
  else if ((!bVar1) && (*(char *)(param_10 + 0x33a) == '\x02')) {
    *(undefined *)(param_10 + 0x33a) = 1;
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
    FUN_8014d504((double)FLOAT_803e3710,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,3,0,0,in_r8,in_r9,in_r10);
  }
  return;
}

