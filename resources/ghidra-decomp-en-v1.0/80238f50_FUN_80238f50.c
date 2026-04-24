// Function: FUN_80238f50
// Entry: 80238f50
// Size: 84 bytes

undefined4 FUN_80238f50(int param_1,undefined4 param_2,int param_3)

{
  if (*(char *)(param_3 + 0x8b) != '\0') {
    (**(code **)(*DAT_803dca68 + 0x38))
              ((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1a),0x14,0x8c,0);
  }
  return 0;
}

