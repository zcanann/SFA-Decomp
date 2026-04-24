// Function: FUN_801f1f64
// Entry: 801f1f64
// Size: 264 bytes

void FUN_801f1f64(int param_1)

{
  int iVar1;
  short *psVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  psVar2 = *(short **)(param_1 + 0xb8);
  iVar1 = FUN_8003687c(param_1,0,0,0);
  if (iVar1 != 0) {
    *(undefined *)(psVar2 + 1) = 1;
    *psVar2 = *(short *)(iVar3 + 0x1a);
  }
  if ((*psVar2 < 1) && (*(char *)(psVar2 + 1) != '\0')) {
    iVar1 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x1e));
    if (iVar1 == 0) {
      FUN_8002b884(param_1,1);
      FUN_800200e8((int)*(short *)(iVar3 + 0x1e),1);
      FUN_800200e8((int)*(short *)(iVar3 + 0x20),1);
    }
    else {
      FUN_8002b884(param_1,0);
      FUN_800200e8((int)*(short *)(iVar3 + 0x1e),0);
      FUN_800200e8((int)*(short *)(iVar3 + 0x20),0);
    }
    *(undefined *)(psVar2 + 1) = 0;
    *psVar2 = *(short *)(iVar3 + 0x1a);
  }
  else if (0 < *psVar2) {
    *psVar2 = *psVar2 - (ushort)DAT_803db410;
  }
  return;
}

