// Function: FUN_80231a58
// Entry: 80231a58
// Size: 48 bytes

void FUN_80231a58(int param_1,int param_2)

{
  **(float **)(param_1 + 0xb8) =
       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x18)) - DOUBLE_803e7158);
  return;
}

