// Function: FUN_80211338
// Entry: 80211338
// Size: 372 bytes

void FUN_80211338(short *param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  double dVar5;
  
  pcVar4 = *(char **)(param_1 + 0x5c);
  iVar3 = *(int *)(param_1 + 0x26);
  if (*pcVar4 == '\x02') {
    param_1[1] = 0;
    *param_1 = *param_1 + 0x100;
    param_1[2] = 0;
  }
  uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x1e));
  if (uVar1 == 0) {
    uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x20));
    if (uVar1 != 0) {
      param_1[3] = param_1[3] | 0x4000;
      FUN_8002cf80((int)param_1);
    }
    if (*pcVar4 == '\x02') {
      iVar2 = FUN_8002bac4();
      dVar5 = (double)FUN_800217c8((float *)(param_1 + 0xc),(float *)(iVar2 + 0x18));
      if (dVar5 < (double)FLOAT_803e73f0) {
        FUN_800201ac((int)*(short *)(iVar3 + 0x1e),1);
      }
    }
    if (*pcVar4 == '\0') {
      FUN_80035ff8((int)param_1);
      if (*(int *)(param_1 + 0x62) != 0) {
        *(undefined4 *)(param_1 + 6) = *(undefined4 *)(*(int *)(param_1 + 0x62) + 0xc);
        *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*(int *)(param_1 + 0x62) + 0x10);
        *(undefined4 *)(param_1 + 10) = *(undefined4 *)(*(int *)(param_1 + 0x62) + 0x14);
      }
    }
    else {
      FUN_80036018((int)param_1);
    }
  }
  else {
    FUN_800201ac((int)*(short *)(&DAT_803dce90 + *(char *)(iVar3 + 0x19) * 2),1);
    param_1[3] = param_1[3] | 0x4000;
    FUN_8002cf80((int)param_1);
    (**(code **)(*DAT_803dd72c + 0x44))(0x1d,2);
  }
  return;
}

