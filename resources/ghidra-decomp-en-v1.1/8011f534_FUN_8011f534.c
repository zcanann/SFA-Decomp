// Function: FUN_8011f534
// Entry: 8011f534
// Size: 244 bytes

void FUN_8011f534(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int *piVar1;
  int iVar2;
  undefined8 uVar3;
  
  DAT_803de413 = 0;
  DAT_803dc6d8 = 0xffff;
  DAT_803de550 = 0;
  DAT_803de428 = 0;
  uVar3 = FUN_8011fa10();
  DAT_803de400 = 0;
  DAT_803de3f8 = 0;
  DAT_803de3b0 = 0;
  DAT_803de3f0 = 0;
  FLOAT_803de3e0 = FLOAT_803e2abc;
  iVar2 = 0;
  piVar1 = &DAT_803aa070;
  do {
    if (*piVar1 != 0) {
      *(undefined4 *)(*(int *)(*piVar1 + 100) + 4) = 0;
      *(undefined4 *)(*(int *)(*piVar1 + 100) + 8) = 0;
      if (0x90000000 < *(uint *)(*piVar1 + 0x4c)) {
        *(undefined4 *)(*piVar1 + 0x4c) = 0;
      }
      uVar3 = FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar1);
      *piVar1 = 0;
    }
    piVar1 = piVar1 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  DAT_803de3da = 0;
  DAT_803de3db = 0;
  DAT_803de3f2 = 0;
  DAT_803de408 = 0x3c;
  DAT_803de412 = 0;
  return;
}

