// Function: FUN_801f259c
// Entry: 801f259c
// Size: 264 bytes

void FUN_801f259c(int param_1)

{
  int iVar1;
  uint uVar2;
  short *psVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  psVar3 = *(short **)(param_1 + 0xb8);
  iVar1 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
  if (iVar1 != 0) {
    *(undefined *)(psVar3 + 1) = 1;
    *psVar3 = *(short *)(iVar4 + 0x1a);
  }
  if ((*psVar3 < 1) && (*(char *)(psVar3 + 1) != '\0')) {
    uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x1e));
    if (uVar2 == 0) {
      FUN_8002b95c(param_1,1);
      FUN_800201ac((int)*(short *)(iVar4 + 0x1e),1);
      FUN_800201ac((int)*(short *)(iVar4 + 0x20),1);
    }
    else {
      FUN_8002b95c(param_1,0);
      FUN_800201ac((int)*(short *)(iVar4 + 0x1e),0);
      FUN_800201ac((int)*(short *)(iVar4 + 0x20),0);
    }
    *(undefined *)(psVar3 + 1) = 0;
    *psVar3 = *(short *)(iVar4 + 0x1a);
  }
  else if (0 < *psVar3) {
    *psVar3 = *psVar3 - (ushort)DAT_803dc070;
  }
  return;
}

