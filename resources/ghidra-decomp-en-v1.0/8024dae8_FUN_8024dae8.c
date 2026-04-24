// Function: FUN_8024dae8
// Entry: 8024dae8
// Size: 264 bytes

void FUN_8024dae8(int param_1)

{
  int iVar1;
  
  iVar1 = 0;
  do {
    if (*(char *)(param_1 + 10) == '\0') {
      FUN_8024d9b8(param_1 + 2,param_1 + 3,uRam803dc583,uRam803dc584,uRam803dc582);
      FUN_8024d9b8(param_1 + 4,param_1 + 5,uRam803dc586,uRam803dc587,uRam803dc585);
      if (DAT_803dc580 < *(byte *)(param_1 + 6)) {
        if (bRam803dc581 < *(byte *)(param_1 + 6)) {
          *(byte *)(param_1 + 6) = bRam803dc581;
        }
        *(byte *)(param_1 + 6) = *(char *)(param_1 + 6) - DAT_803dc580;
      }
      else {
        *(undefined *)(param_1 + 6) = 0;
      }
      if (DAT_803dc580 < *(byte *)(param_1 + 7)) {
        if (bRam803dc581 < *(byte *)(param_1 + 7)) {
          *(byte *)(param_1 + 7) = bRam803dc581;
        }
        *(byte *)(param_1 + 7) = *(char *)(param_1 + 7) - DAT_803dc580;
      }
      else {
        *(undefined *)(param_1 + 7) = 0;
      }
    }
    iVar1 = iVar1 + 1;
    param_1 = param_1 + 0xc;
  } while (iVar1 < 4);
  return;
}

