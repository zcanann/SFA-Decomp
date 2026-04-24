// Function: FUN_801706d4
// Entry: 801706d4
// Size: 164 bytes

void FUN_801706d4(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_800803f8((undefined4 *)(iVar1 + 4));
  *(float *)(iVar1 + 8) =
       ((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
               DOUBLE_803e4030) / FLOAT_803e4038) * FLOAT_803dc9c8;
  *(float *)(param_1 + 0x28) = FLOAT_803e4024;
  *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  *(undefined4 *)(iVar1 + 0x10) = 1;
  FUN_80035ff8(param_1);
  return;
}

