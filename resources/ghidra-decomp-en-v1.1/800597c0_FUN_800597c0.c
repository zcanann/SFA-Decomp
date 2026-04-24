// Function: FUN_800597c0
// Entry: 800597c0
// Size: 232 bytes

void FUN_800597c0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  
  uVar6 = FUN_80286840();
  uVar1 = DAT_803ddb48;
  uVar2 = FUN_8005a05c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  iVar4 = 0x50;
  piVar3 = &DAT_80387208;
  iVar5 = 0x28;
  do {
    if (*piVar3 == 0) {
      (&DAT_803870c8)[iVar4] = uVar2;
      break;
    }
    piVar3 = piVar3 + 1;
    iVar4 = iVar4 + 1;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  *(char *)((int)uVar6 + 0x34) = (char)iVar4;
  (**(code **)(*DAT_803dd72c + 0x48))((int)((ulonglong)uVar6 >> 0x20),iVar4);
  FUN_800598a8();
  (**(code **)(*DAT_803dd72c + 0x58))(iVar4);
  DAT_803ddb48 = uVar1;
  FUN_8028688c();
  return;
}

