// Function: FUN_8023211c
// Entry: 8023211c
// Size: 48 bytes

void FUN_8023211c(int param_1,int param_2)

{
  **(float **)(param_1 + 0xb8) =
       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x18)) - DOUBLE_803e7df0);
  return;
}

