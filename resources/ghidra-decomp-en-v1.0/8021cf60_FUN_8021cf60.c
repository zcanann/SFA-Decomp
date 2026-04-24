// Function: FUN_8021cf60
// Entry: 8021cf60
// Size: 312 bytes

undefined4 FUN_8021cf60(int param_1,uint *param_2)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    *(undefined *)(iVar3 + 0xc4b) = 3;
    *param_2 = *param_2 | 0x1000000;
  }
  iVar1 = FUN_8001ffb4(0x1c3);
  if (iVar1 == 0) {
    *(undefined *)(iVar3 + 0xc4b) = 3;
  }
  else {
    iVar1 = FUN_8001ffb4(0xee);
    if (iVar1 == 2) {
      *(undefined *)(iVar3 + 0xc4b) = 7;
    }
    else {
      *(undefined *)(iVar3 + 0xc4b) = 9;
    }
  }
  iVar3 = FUN_8002b9ec();
  dVar4 = (double)FUN_80021704(iVar3 + 0x18,param_1 + 0x18);
  if (((double)FLOAT_803e6aa4 < dVar4) && (iVar3 = FUN_80080100(500), iVar3 != 0)) {
    iVar1 = FUN_800221a0(0,100);
    iVar3 = 0;
    for (piVar2 = &DAT_8032ab3c; *piVar2 < iVar1; piVar2 = piVar2 + 1) {
      iVar1 = iVar1 - (&DAT_8032ab3c)[iVar3];
      iVar3 = iVar3 + 1;
    }
    (**(code **)(*DAT_803dca54 + 0x48))((&DAT_8032ab30)[iVar3],param_1,0xffffffff);
  }
  return 0;
}

