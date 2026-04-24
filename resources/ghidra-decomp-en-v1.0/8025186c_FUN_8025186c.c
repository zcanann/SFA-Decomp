// Function: FUN_8025186c
// Entry: 8025186c
// Size: 160 bytes

void FUN_8025186c(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803de078;
  if (DAT_803de078 == 0) {
    DAT_803de074 = param_1;
    DAT_803de078 = param_1;
    DAT_803de07c = param_1;
    *(undefined4 *)(param_1 + 0x3c) = 0;
    *(undefined4 *)(param_1 + 0x38) = 0;
    return;
  }
  do {
    iVar1 = DAT_803de078;
    if (iVar2 == 0) {
LAB_802518e4:
      DAT_803de078 = iVar1;
      if (iVar2 == 0) {
        *(int *)(DAT_803de074 + 0x38) = param_1;
        *(undefined4 *)(param_1 + 0x38) = 0;
        *(int *)(param_1 + 0x3c) = DAT_803de074;
        DAT_803de074 = param_1;
        return;
      }
      return;
    }
    if (*(uint *)(param_1 + 4) < *(uint *)(iVar2 + 4)) {
      *(undefined4 *)(param_1 + 0x3c) = *(undefined4 *)(iVar2 + 0x3c);
      *(int *)(iVar2 + 0x3c) = param_1;
      *(int *)(param_1 + 0x38) = iVar2;
      iVar1 = param_1;
      if (*(int *)(param_1 + 0x3c) != 0) {
        *(int *)(*(int *)(param_1 + 0x3c) + 0x38) = param_1;
        iVar1 = DAT_803de078;
      }
      goto LAB_802518e4;
    }
    iVar2 = *(int *)(iVar2 + 0x38);
  } while( true );
}

