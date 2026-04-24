// Function: FUN_801603e8
// Entry: 801603e8
// Size: 84 bytes

undefined4 FUN_801603e8(int param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dcab8 + 0x4c))
              (param_1,(int)*(short *)(*(int *)(param_1 + 0xb8) + 0x3f0),0xffffffff,0);
  }
  return 0;
}

