// Function: FUN_80200964
// Entry: 80200964
// Size: 84 bytes

undefined4 FUN_80200964(int param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd738 + 0x4c))
              (param_1,(int)*(short *)(*(int *)(param_1 + 0xb8) + 0x3f0),0xffffffff,0);
  }
  return 0;
}

