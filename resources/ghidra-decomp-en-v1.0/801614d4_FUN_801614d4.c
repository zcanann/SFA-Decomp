// Function: FUN_801614d4
// Entry: 801614d4
// Size: 244 bytes

undefined4 FUN_801614d4(undefined4 param_1,int param_2)

{
  undefined auStack24 [2];
  undefined auStack22 [2];
  ushort local_14 [2];
  undefined4 local_10;
  uint uStack12;
  
  if ((*(int *)(param_2 + 0x2d0) != 0) && (*(short *)(param_2 + 0x274) != 2)) {
    uStack12 = (int)*(short *)(param_2 + 0x32e) ^ 0x80000000;
    local_10 = 0x43300000;
    if (FLOAT_803e2ed0 * FLOAT_803db414 <
        (float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e2ed8)) {
      (**(code **)(*DAT_803dcab8 + 0x14))
                (param_1,*(int *)(param_2 + 0x2d0),0x10,local_14,auStack22,auStack24);
      if ((local_14[0] < 4) || (0xb < local_14[0])) {
        return 3;
      }
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,2);
      *(float *)(param_2 + 0x2a0) = FLOAT_803e2ed4;
      *(undefined *)(param_2 + 0x346) = 0;
    }
  }
  return 0;
}

