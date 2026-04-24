// Function: FUN_801eea68
// Entry: 801eea68
// Size: 232 bytes

void FUN_801eea68(undefined4 param_1,undefined4 param_2,int param_3)

{
  short *psVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  psVar1 = (short *)FUN_802860d8();
  iVar4 = *(int *)(psVar1 + 0x5c);
  uVar2 = FUN_8002b9ec();
  *(undefined **)(param_3 + 0xe8) = &LAB_801ee088;
  *(undefined4 *)(iVar4 + 0x4c) = *(undefined4 *)(psVar1 + 6);
  *(undefined4 *)(iVar4 + 0x50) = *(undefined4 *)(psVar1 + 8);
  *(undefined4 *)(iVar4 + 0x54) = *(undefined4 *)(psVar1 + 10);
  *(short *)(iVar4 + 0x2c) = *psVar1 + -0x4000;
  *(short *)(iVar4 + 0x2e) = psVar1[2];
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    if (*(char *)(param_3 + iVar3 + 0x81) == '\x01') {
      FUN_80062e84(uVar2,*(undefined4 *)(iVar4 + 0x10),0);
      FUN_80295918((double)FLOAT_803e5c70,uVar2,5);
      *(undefined *)(iVar4 + 0x6e) = 1;
    }
  }
  *(undefined *)(param_3 + 0x56) = 0;
  psVar1[3] = psVar1[3] & 0xbfff;
  FUN_80286124(0);
  return;
}

