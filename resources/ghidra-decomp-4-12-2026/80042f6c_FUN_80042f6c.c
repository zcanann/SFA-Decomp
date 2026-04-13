// Function: FUN_80042f6c
// Entry: 80042f6c
// Size: 260 bytes

void FUN_80042f6c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  undefined8 extraout_f1;
  undefined8 uVar2;
  
  if (*(short *)(&DAT_802cc9d4 + param_9 * 2) != -1) {
    iVar1 = (**(code **)(*DAT_803dd72c + 0x90))();
    *(char *)(iVar1 + 0xe) = (char)param_9;
    param_1 = extraout_f1;
  }
  uVar2 = FUN_80044548(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar2 = FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_80044548(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

