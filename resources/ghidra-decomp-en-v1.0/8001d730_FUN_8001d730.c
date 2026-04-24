// Function: FUN_8001d730
// Entry: 8001d730
// Size: 200 bytes

/* WARNING: Removing unreachable block (ram,0x8001d7d8) */

void FUN_8001d730(undefined4 param_1,undefined4 param_2,undefined param_3,undefined param_4,
                 undefined param_5,undefined param_6)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  double extraout_f1;
  undefined8 in_f31;
  double dVar4;
  undefined8 uVar5;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar5 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar5 >> 0x20);
  dVar4 = extraout_f1;
  if ((int)uVar5 == 0) {
    iVar2 = FUN_80054d54(0x605);
    *(int *)(iVar1 + 0x2e8) = iVar2;
    if (iVar2 != 0) {
      *(undefined *)(iVar1 + 0x2f8) = 2;
    }
  }
  else {
    iVar2 = FUN_80054d54((int)uVar5);
    *(int *)(iVar1 + 0x2e8) = iVar2;
    if (iVar2 != 0) {
      *(undefined *)(iVar1 + 0x2f8) = 2;
    }
  }
  *(undefined *)(iVar1 + 0x2ec) = param_3;
  *(undefined *)(iVar1 + 0x2ed) = param_4;
  *(undefined *)(iVar1 + 0x2ee) = param_5;
  *(undefined *)(iVar1 + 0x2ef) = param_6;
  *(float *)(iVar1 + 0x2f0) = (float)dVar4;
  *(undefined *)(iVar1 + 0x2f9) = 0;
  *(undefined *)(iVar1 + 0x2fa) = 0;
  *(float *)(iVar1 + 0x2f4) = FLOAT_803de788 * *(float *)(iVar1 + 0x2f0);
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  FUN_80286128();
  return;
}

