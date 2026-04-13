// Function: FUN_802b79f8
// Entry: 802b79f8
// Size: 196 bytes

undefined4 FUN_802b79f8(int param_1,int param_2)

{
  if (*(int *)(param_2 + 0x2d0) != 0) {
    if (*(ushort *)(*(int *)(*(int *)(param_1 + 0xb8) + 0x40c) + 0x22) <
        *(ushort *)(*(int *)(param_1 + 0xb8) + 0x3fe)) {
      if (((*(char *)(param_2 + 0x27b) != '\0') || (*(char *)(param_2 + 0x346) != '\0')) ||
         (*(short *)(param_2 + 0x274) == 0)) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,4);
      }
    }
    else if ((*(char *)(param_2 + 0x27b) != '\0') || (*(char *)(param_2 + 0x346) != '\0')) {
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
    }
  }
  return 0;
}

