// Function: FUN_80207b34
// Entry: 80207b34
// Size: 240 bytes

undefined4 FUN_80207b34(int param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar2 + 8) = *(byte *)(iVar2 + 8) & 0x7f | 0x80;
  FUN_8001467c();
  for (uVar1 = 0; (int)uVar1 < (int)(uint)*(byte *)(param_3 + 0x8b); uVar1 = uVar1 + 1) {
    if (*(char *)(param_3 + uVar1 + 0x81) == '\x01') {
      *(byte *)(iVar2 + 8) = *(byte *)(iVar2 + 8) & 0xef | 0x10;
      *(undefined *)(iVar2 + 7) = 0;
      FUN_800200e8((int)*(short *)(iVar2 + 2),0);
      FUN_800200e8(0xedf,1);
      uVar1 = 0;
      do {
        FUN_80207948(param_1,uVar1 & 0xff);
        uVar1 = uVar1 + 1;
      } while ((int)uVar1 < 4);
      *(byte *)(iVar2 + 8) = *(byte *)(iVar2 + 8) & 0xbf | 0x40;
    }
  }
  FUN_8020768c(param_1);
  return 0;
}

