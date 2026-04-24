// Function: FUN_801ccfe4
// Entry: 801ccfe4
// Size: 276 bytes

void FUN_801ccfe4(int param_1)

{
  int iVar1;
  int iVar2;
  undefined auStack_28 [8];
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  undefined4 local_10;
  uint uStack_c;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  local_1c = FLOAT_803e5e50;
  local_18 = FLOAT_803e5e50;
  local_14 = FLOAT_803e5e50;
  uStack_c = (int)*(char *)(*(int *)(param_1 + 0x4c) + 0x19) ^ 0x80000000;
  local_10 = 0x43300000;
  local_20 = (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e5e58);
  iVar1 = *(int *)(*(int *)(param_1 + 0x54) + 0x50);
  if ((iVar1 != 0) && (*(short *)(iVar1 + 0x46) != 0x248)) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x2a0,auStack_28,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x2a0,auStack_28,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x2a0,auStack_28,1,0xffffffff,0);
    *(undefined2 *)(iVar2 + 0x32) = 0x32;
  }
  return;
}

