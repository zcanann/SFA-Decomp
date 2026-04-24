// Function: FUN_8023267c
// Entry: 8023267c
// Size: 376 bytes

void FUN_8023267c(undefined4 param_1,int param_2,int param_3)

{
  int iVar1;
  
  if ((*(byte *)(param_2 + 0x160) >> 5 & 1) == 0) {
    iVar1 = FUN_800801a8(param_2 + 0x124);
    if (iVar1 != 0) {
      *(byte *)(param_2 + 0x160) = *(byte *)(param_2 + 0x160) & 0xdf | 0x20;
      FUN_8008016c(param_2 + 0x128);
      FUN_80080178(param_2 + 0x128,*(undefined *)(param_3 + 0x2d));
      *(undefined *)(param_2 + 0x155) = *(undefined *)(param_3 + 0x2e);
      *(short *)(param_2 + 0x14e) = -*(short *)(param_3 + 0x2a);
    }
  }
  else {
    iVar1 = FUN_800801a8(param_2 + 0x128);
    if (iVar1 != 0) {
      FUN_80232278(param_1,0,(int)*(short *)(param_2 + 0x14e),
                   (int)*(char *)(param_2 + 0x155) == (uint)*(byte *)(param_3 + 0x2e));
      if (1 < *(byte *)(param_2 + 0x15b)) {
        FUN_80232278(param_1,1,(int)*(short *)(param_2 + 0x14e),0);
      }
      *(char *)(param_2 + 0x155) = *(char *)(param_2 + 0x155) + -1;
      FUN_8008016c(param_2 + 0x128);
      FUN_80080178(param_2 + 0x128,*(undefined *)(param_3 + 0x2d));
      *(short *)(param_2 + 0x14e) =
           *(short *)(param_2 + 0x14e) +
           (short)(((uint)*(ushort *)(param_3 + 0x2a) << 1) / (uint)*(byte *)(param_3 + 0x2e));
      if (*(char *)(param_2 + 0x155) < '\x01') {
        *(byte *)(param_2 + 0x160) = *(byte *)(param_2 + 0x160) & 0xdf;
        FUN_8008016c(param_2 + 0x124);
        FUN_80080178(param_2 + 0x124,*(undefined *)(param_3 + 0x2c));
      }
    }
  }
  return;
}

