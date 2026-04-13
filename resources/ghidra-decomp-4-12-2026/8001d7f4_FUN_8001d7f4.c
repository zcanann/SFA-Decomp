// Function: FUN_8001d7f4
// Entry: 8001d7f4
// Size: 200 bytes

/* WARNING: Removing unreachable block (ram,0x8001d89c) */
/* WARNING: Removing unreachable block (ram,0x8001d804) */

void FUN_8001d7f4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  double extraout_f1;
  double dVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  iVar2 = (int)uVar4;
  dVar3 = extraout_f1;
  if (iVar2 == 0) {
    iVar2 = FUN_80054ed0(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x605,0
                         ,param_11,param_12,param_13,param_14,param_15,param_16);
    *(int *)(iVar1 + 0x2e8) = iVar2;
    if (iVar2 != 0) {
      *(undefined *)(iVar1 + 0x2f8) = 2;
    }
  }
  else {
    iVar2 = FUN_80054ed0(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,
                         iVar2,param_11,param_12,param_13,param_14,param_15,param_16);
    *(int *)(iVar1 + 0x2e8) = iVar2;
    if (iVar2 != 0) {
      *(undefined *)(iVar1 + 0x2f8) = 2;
    }
  }
  *(char *)(iVar1 + 0x2ec) = (char)param_11;
  *(char *)(iVar1 + 0x2ed) = (char)param_12;
  *(char *)(iVar1 + 0x2ee) = (char)param_13;
  *(char *)(iVar1 + 0x2ef) = (char)param_14;
  *(float *)(iVar1 + 0x2f0) = (float)dVar3;
  *(undefined *)(iVar1 + 0x2f9) = 0;
  *(undefined *)(iVar1 + 0x2fa) = 0;
  *(float *)(iVar1 + 0x2f4) = FLOAT_803df408 * *(float *)(iVar1 + 0x2f0);
  FUN_8028688c();
  return;
}

