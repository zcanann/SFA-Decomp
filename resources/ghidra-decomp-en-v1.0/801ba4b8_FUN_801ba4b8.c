// Function: FUN_801ba4b8
// Entry: 801ba4b8
// Size: 216 bytes

undefined4 FUN_801ba4b8(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  FUN_8002b9ec();
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27b) != '\0') {
    *(undefined4 *)(param_2 + 0x2d0) = 0;
    *(undefined *)(param_2 + 0x25f) = 0;
    *(undefined *)(param_2 + 0x349) = 0;
    FUN_80035f00(param_1);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0x7f;
    uVar1 = FUN_8002b9ec();
    FUN_800378c4(uVar1,0xe0000,param_1,0);
    FUN_800200e8((int)*(short *)(iVar2 + 0x3f4),0);
    FUN_800200e8((int)*(short *)(iVar2 + 0x3f2),1);
    if (*(int *)(param_1 + 0x4c) == 0) {
      FUN_8002cbc4(param_1);
    }
  }
  return 0;
}

