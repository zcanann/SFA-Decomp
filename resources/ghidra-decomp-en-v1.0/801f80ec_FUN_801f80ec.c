// Function: FUN_801f80ec
// Entry: 801f80ec
// Size: 144 bytes

void FUN_801f80ec(int param_1)

{
  byte bVar1;
  char in_r8;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if ((*(ushort *)(iVar2 + 0x294) & 0x40) != 0) {
    bVar1 = *(byte *)(param_1 + 0x36);
    if (bVar1 < 0xff) {
      if ((int)(0xff - (uint)DAT_803db410) < (int)(uint)bVar1) {
        *(undefined *)(param_1 + 0x36) = 0xff;
        *(ushort *)(iVar2 + 0x294) = *(ushort *)(iVar2 + 0x294) & 0xffbf;
      }
      else {
        *(byte *)(param_1 + 0x36) = bVar1 + DAT_803db410;
      }
    }
  }
  if ((in_r8 != '\0') && (*(short *)(iVar2 + 0x28c) == 0)) {
    FUN_8003b8f4((double)FLOAT_803e5fb4);
  }
  return;
}

