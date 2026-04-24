// Function: FUN_80210cc0
// Entry: 80210cc0
// Size: 372 bytes

void FUN_80210cc0(short *param_1)

{
  int iVar1;
  int iVar2;
  char *pcVar3;
  double dVar4;
  
  pcVar3 = *(char **)(param_1 + 0x5c);
  iVar2 = *(int *)(param_1 + 0x26);
  if (*pcVar3 == '\x02') {
    param_1[1] = 0;
    *param_1 = *param_1 + 0x100;
    param_1[2] = 0;
  }
  iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x1e));
  if (iVar1 == 0) {
    iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x20));
    if (iVar1 != 0) {
      param_1[3] = param_1[3] | 0x4000;
      FUN_8002ce88(param_1);
    }
    if (*pcVar3 == '\x02') {
      iVar1 = FUN_8002b9ec();
      dVar4 = (double)FUN_80021704(param_1 + 0xc,iVar1 + 0x18);
      if (dVar4 < (double)FLOAT_803e6758) {
        FUN_800200e8((int)*(short *)(iVar2 + 0x1e),1);
      }
    }
    if (*pcVar3 == '\0') {
      FUN_80035f00(param_1);
      if (*(int *)(param_1 + 0x62) != 0) {
        *(undefined4 *)(param_1 + 6) = *(undefined4 *)(*(int *)(param_1 + 0x62) + 0xc);
        *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*(int *)(param_1 + 0x62) + 0x10);
        *(undefined4 *)(param_1 + 10) = *(undefined4 *)(*(int *)(param_1 + 0x62) + 0x14);
      }
    }
    else {
      FUN_80035f20(param_1);
    }
  }
  else {
    FUN_800200e8((int)*(short *)(&DAT_803dc228 + *(char *)(iVar2 + 0x19) * 2),1);
    param_1[3] = param_1[3] | 0x4000;
    FUN_8002ce88(param_1);
    (**(code **)(*DAT_803dcaac + 0x44))(0x1d,2);
  }
  return;
}

