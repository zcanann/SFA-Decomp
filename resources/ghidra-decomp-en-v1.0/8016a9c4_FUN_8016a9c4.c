// Function: FUN_8016a9c4
// Entry: 8016a9c4
// Size: 332 bytes

void FUN_8016a9c4(int param_1)

{
  int iVar1;
  int iVar2;
  undefined auStack24 [16];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_80080150(iVar2 + 0x20);
  if (iVar1 == 0) {
    iVar1 = FUN_8003687c(param_1,auStack24,0,0);
    if ((iVar1 == 0xe) || (iVar1 == 0xf)) {
      if (*(short *)(*(int *)(iVar2 + 0x1c) + 4) != -1) {
        FUN_8009ab70((double)FLOAT_803e315c,param_1,0,1,0,1,0,1,0);
        FUN_8000b4d0(param_1,*(undefined2 *)(*(int *)(iVar2 + 0x1c) + 4),3);
      }
      FUN_80035f00(param_1);
      FUN_80080178(iVar2 + 0x20,0x78);
    }
    if (*(char *)(*(int *)(param_1 + 0x54) + 0xad) != '\0') {
      FUN_80035f00(param_1);
      *(float *)(iVar2 + 8) = FLOAT_803e3160;
      if (*(short *)(*(int *)(iVar2 + 0x1c) + 4) != -1) {
        FUN_8009ab70((double)FLOAT_803e315c,param_1,0,1,0,1,0,1,0);
        FUN_8000b4d0(param_1,*(undefined2 *)(*(int *)(iVar2 + 0x1c) + 4),3);
      }
      FUN_80080178(iVar2 + 0x20,0x78);
    }
  }
  return;
}

