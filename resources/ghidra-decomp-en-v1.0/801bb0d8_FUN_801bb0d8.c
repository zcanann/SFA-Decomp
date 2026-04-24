// Function: FUN_801bb0d8
// Entry: 801bb0d8
// Size: 276 bytes

/* WARNING: Removing unreachable block (ram,0x801bb1cc) */

undefined4 FUN_801bb0d8(undefined8 param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  undefined8 in_f31;
  undefined auStack40 [2];
  undefined auStack38 [2];
  ushort local_24 [6];
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  *(float *)(param_3 + 0x280) = FLOAT_803e4bd8;
  if (((*(char *)(param_3 + 0x346) != '\0') || (*(char *)(param_3 + 0x27a) != '\0')) ||
     (*(short *)(param_2 + 0xa0) == 1)) {
    (**(code **)(*DAT_803dcab8 + 0x14))
              (param_2,*(undefined4 *)(param_3 + 0x2d0),0x10,local_24,auStack38,auStack40);
    FUN_80030334((double)FLOAT_803e4bd8,param_2,
                 *(undefined4 *)(&DAT_80325960 + (uint)local_24[0] * 4),0);
    *(undefined4 *)(param_3 + 0x2a0) = *(undefined4 *)(&DAT_803259a0 + (uint)local_24[0] * 4);
    *(undefined *)(param_3 + 0x346) = 0;
  }
  (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,8);
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  return 0;
}

