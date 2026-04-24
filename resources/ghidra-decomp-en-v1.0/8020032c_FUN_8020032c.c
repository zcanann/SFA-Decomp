// Function: FUN_8020032c
// Entry: 8020032c
// Size: 84 bytes

undefined4 FUN_8020032c(int param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dcab8 + 0x4c))
              (param_1,(int)*(short *)(*(int *)(param_1 + 0xb8) + 0x3f0),0xffffffff,0);
  }
  return 0;
}

