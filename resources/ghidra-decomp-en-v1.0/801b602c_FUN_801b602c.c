// Function: FUN_801b602c
// Entry: 801b602c
// Size: 312 bytes

undefined4 FUN_801b602c(int param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined *)(param_3 + 0x56) = 0;
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffbf;
  FUN_801b5f1c(param_1,iVar4);
  if (*(char *)(param_3 + 0x80) == '\x01') {
    *(undefined *)(param_3 + 0x80) = 0;
    *(undefined *)(iVar4 + 0x5f) = 1;
  }
  if (*(char *)(iVar4 + 0x5f) != '\0') {
    *(ushort *)(iVar4 + 100) = *(short *)(iVar4 + 100) - (ushort)DAT_803db410;
    if (*(short *)(iVar4 + 100) < 1) {
      *(undefined2 *)(iVar4 + 100) = 0x10;
      for (iVar2 = 1;
          (*(char *)(iVar4 + iVar2 + 0x40) != '\0' && (iVar2 < (int)(uint)*(byte *)(iVar4 + 0x4f)));
          iVar2 = iVar2 + 1) {
      }
      *(undefined *)(iVar4 + iVar2 + 0x40) = 1;
    }
    for (iVar2 = 1; iVar2 < (int)(uint)*(byte *)(iVar4 + 0x4f); iVar2 = iVar2 + 1) {
      iVar3 = iVar4 + iVar2;
      if (*(char *)(iVar3 + 0x40) != '\0') {
        uVar1 = (uint)*(byte *)(iVar3 + 0x50) + (uint)DAT_803db410;
        if (0xff < uVar1) {
          uVar1 = 0xff;
        }
        *(char *)(iVar3 + 0x50) = (char)uVar1;
      }
    }
  }
  FUN_801b5d48(param_1,iVar4);
  return 0;
}

