// Function: FUN_80026c00
// Entry: 80026c00
// Size: 244 bytes

void FUN_80026c00(undefined4 param_1,undefined4 param_2,int *param_3,undefined *param_4)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_8028683c();
  piVar1 = (int *)((ulonglong)uVar6 >> 0x20);
  iVar3 = (int)uVar6;
  if (*(char *)((int)param_3 + 0x1a) != '\0') {
    iVar5 = 0;
    for (iVar4 = 0; iVar4 < param_3[1]; iVar4 = iVar4 + 1) {
      if (*(char *)((int)param_3 + 0x19) == '\0') {
        FUN_800269ec(piVar1,iVar3,(int *)(*param_3 + iVar5));
      }
      iVar2 = FUN_80020800();
      if (iVar2 == 0) {
        FUN_80026854((int)piVar1,iVar3,(int)param_3,(int *)(*param_3 + iVar5));
        FUN_800263cc(piVar1,iVar3,(int)param_3,(int *)(*param_3 + iVar5),param_4,iVar4);
      }
      else {
        FUN_80025ffc();
      }
      iVar5 = iVar5 + 0xc;
    }
    *(undefined *)(param_3 + 6) = 1;
    *(undefined *)((int)param_3 + 0x19) = 1;
  }
  FUN_80286888();
  return;
}

