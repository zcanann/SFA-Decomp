// Function: FUN_80161980
// Entry: 80161980
// Size: 244 bytes

undefined4 FUN_80161980(undefined4 param_1,int param_2)

{
  undefined auStack_18 [2];
  undefined auStack_16 [2];
  ushort local_14 [2];
  undefined4 local_10;
  uint uStack_c;
  
  if ((*(int *)(param_2 + 0x2d0) != 0) && (*(short *)(param_2 + 0x274) != 2)) {
    uStack_c = (int)*(short *)(param_2 + 0x32e) ^ 0x80000000;
    local_10 = 0x43300000;
    if (FLOAT_803e3b68 * FLOAT_803dc074 <
        (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e3b70)) {
      (**(code **)(*DAT_803dd738 + 0x14))
                (param_1,*(int *)(param_2 + 0x2d0),0x10,local_14,auStack_16,auStack_18);
      if ((local_14[0] < 4) || (0xb < local_14[0])) {
        return 3;
      }
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,2);
      *(float *)(param_2 + 0x2a0) = FLOAT_803e3b6c;
      *(undefined *)(param_2 + 0x346) = 0;
    }
  }
  return 0;
}

