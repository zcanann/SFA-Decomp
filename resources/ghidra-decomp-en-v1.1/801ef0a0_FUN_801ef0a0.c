// Function: FUN_801ef0a0
// Entry: 801ef0a0
// Size: 232 bytes

void FUN_801ef0a0(undefined4 param_1,undefined4 param_2,int param_3)

{
  short *psVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  
  psVar1 = (short *)FUN_8028683c();
  iVar4 = *(int *)(psVar1 + 0x5c);
  psVar2 = (short *)FUN_8002bac4();
  *(undefined **)(param_3 + 0xe8) = &LAB_801ee6c0;
  *(undefined4 *)(iVar4 + 0x4c) = *(undefined4 *)(psVar1 + 6);
  *(undefined4 *)(iVar4 + 0x50) = *(undefined4 *)(psVar1 + 8);
  *(undefined4 *)(iVar4 + 0x54) = *(undefined4 *)(psVar1 + 10);
  *(short *)(iVar4 + 0x2c) = *psVar1 + -0x4000;
  *(short *)(iVar4 + 0x2e) = psVar1[2];
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    if (*(char *)(param_3 + iVar3 + 0x81) == '\x01') {
      FUN_80063000(psVar2,*(short **)(iVar4 + 0x10),0);
      FUN_80296078((double)FLOAT_803e6908,(int)psVar2,5);
      *(undefined *)(iVar4 + 0x6e) = 1;
    }
  }
  *(undefined *)(param_3 + 0x56) = 0;
  psVar1[3] = psVar1[3] & 0xbfff;
  FUN_80286888();
  return;
}

