// Function: FUN_801a8f88
// Entry: 801a8f88
// Size: 264 bytes

undefined4 FUN_801a8f88(int param_1,int param_2)

{
  byte bVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_2 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_2 + iVar3 + 0x81);
    if (bVar1 == 2) {
      iVar4 = *(int *)(param_1 + 200);
      if (iVar4 != 0) {
        FUN_80037cb0(param_1,iVar4);
        FUN_8002cbc4(iVar4);
      }
      *(undefined4 *)(param_1 + 0xf8) = 0xffffffff;
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      *(undefined4 *)(param_1 + 0xf8) = 0x30b;
      iVar4 = *(int *)(param_1 + 200);
      if (iVar4 != 0) {
        FUN_80037cb0(param_1,iVar4);
        FUN_8002cbc4(iVar4);
      }
      uVar2 = FUN_8002bdf4(0x20,*(undefined4 *)(param_1 + 0xf8));
      uVar2 = FUN_8002df90(uVar2,4,(int)*(char *)(param_1 + 0xac),0xffffffff,
                           *(undefined4 *)(param_1 + 0x30));
      FUN_80037d2c(param_1,uVar2,0);
    }
  }
  return 0;
}

