// Function: FUN_801d550c
// Entry: 801d550c
// Size: 440 bytes

void FUN_801d550c(undefined4 param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  *(undefined **)(param_2 + 0x62c) = &DAT_803dc008;
  switch(*(undefined *)(param_2 + 0x626)) {
  case 1:
    *(undefined **)(param_2 + 0x62c) = &DAT_803dc010;
    break;
  case 2:
    iVar2 = FUN_8001ffb4(0xc2);
    if (iVar2 != 6) {
      *(undefined **)(param_2 + 0x62c) = &DAT_803dc014;
    }
    break;
  case 3:
    iVar2 = FUN_8001ffb4(0x193);
    if (iVar2 == 0) {
      *(undefined **)(param_2 + 0x62c) = &DAT_803dc018;
    }
    break;
  case 4:
    *(undefined **)(param_2 + 0x62c) = &DAT_803dc01c;
    break;
  case 5:
    iVar2 = FUN_8001ffb4(0x23c);
    if (iVar2 == 0) {
      iVar2 = FUN_8001ffb4(0x5bd);
      if (iVar2 == 0) {
        iVar2 = FUN_8001ffb4(0x23d);
        if (iVar2 == 0) {
          *(undefined **)(param_2 + 0x62c) = &DAT_803dc020;
          *(undefined *)(param_2 + 0x624) = 0x10;
          return;
        }
        if (*(char *)(param_2 + 0x624) == '\x10') {
          *(undefined *)(param_2 + 0x624) = 0;
          uVar1 = FUN_800221a0(1000,2000);
          *(float *)(param_2 + 0x630) =
               (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e5428);
        }
        *(undefined **)(param_2 + 0x62c) = &DAT_803dc024;
      }
      else {
        (**(code **)(*DAT_803dcaac + 0x44))(0x1d,3);
        *(undefined **)(param_2 + 0x62c) = &DAT_803dc028;
      }
    }
    break;
  case 6:
    iVar2 = FUN_8001ffb4(0x13f);
    if (iVar2 == 0) {
      *(undefined **)(param_2 + 0x62c) = &DAT_803dc02c;
    }
    break;
  case 7:
    iVar2 = FUN_8001ffb4(0x199);
    if (iVar2 == 0) {
      *(undefined **)(param_2 + 0x62c) = &DAT_803dc030;
    }
    break;
  case 8:
    *(undefined **)(param_2 + 0x62c) = &DAT_803dc034;
  }
  FUN_801d5174(param_1,param_2);
  return;
}

