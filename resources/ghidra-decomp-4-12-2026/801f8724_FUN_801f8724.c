// Function: FUN_801f8724
// Entry: 801f8724
// Size: 144 bytes

void FUN_801f8724(int param_1)

{
  byte bVar1;
  char in_r8;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if ((*(ushort *)(iVar2 + 0x294) & 0x40) != 0) {
    bVar1 = *(byte *)(param_1 + 0x36);
    if (bVar1 < 0xff) {
      if ((int)(0xff - (uint)DAT_803dc070) < (int)(uint)bVar1) {
        *(undefined *)(param_1 + 0x36) = 0xff;
        *(ushort *)(iVar2 + 0x294) = *(ushort *)(iVar2 + 0x294) & 0xffbf;
      }
      else {
        *(byte *)(param_1 + 0x36) = bVar1 + DAT_803dc070;
      }
    }
  }
  if ((in_r8 != '\0') && (*(short *)(iVar2 + 0x28c) == 0)) {
    FUN_8003b9ec(param_1);
  }
  return;
}

