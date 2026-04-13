// Function: FUN_8024e24c
// Entry: 8024e24c
// Size: 264 bytes

void FUN_8024e24c(int param_1)

{
  int iVar1;
  
  iVar1 = 0;
  do {
    if (*(char *)(param_1 + 10) == '\0') {
      FUN_8024e11c((char *)(param_1 + 2),(char *)(param_1 + 3),cRam803dd1eb,cRam803dd1ec,
                   cRam803dd1ea);
      FUN_8024e11c((char *)(param_1 + 4),(char *)(param_1 + 5),cRam803dd1ee,cRam803dd1ef,
                   cRam803dd1ed);
      if (DAT_803dd1e8 < *(byte *)(param_1 + 6)) {
        if (bRam803dd1e9 < *(byte *)(param_1 + 6)) {
          *(byte *)(param_1 + 6) = bRam803dd1e9;
        }
        *(byte *)(param_1 + 6) = *(char *)(param_1 + 6) - DAT_803dd1e8;
      }
      else {
        *(undefined *)(param_1 + 6) = 0;
      }
      if (DAT_803dd1e8 < *(byte *)(param_1 + 7)) {
        if (bRam803dd1e9 < *(byte *)(param_1 + 7)) {
          *(byte *)(param_1 + 7) = bRam803dd1e9;
        }
        *(byte *)(param_1 + 7) = *(char *)(param_1 + 7) - DAT_803dd1e8;
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

