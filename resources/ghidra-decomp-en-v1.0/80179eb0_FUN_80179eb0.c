// Function: FUN_80179eb0
// Entry: 80179eb0
// Size: 348 bytes

void FUN_80179eb0(int param_1)

{
  int iVar1;
  undefined local_18 [8];
  undefined4 local_10;
  uint uStack12;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  local_18[0] = 5;
  FUN_800033a8(iVar1,0,0x2cc);
  FUN_8002b9ec();
  *(undefined *)(iVar1 + 0x274) = 0;
  *(float *)(iVar1 + 0x26c) = FLOAT_803e369c;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  uStack12 = (int)*(short *)(*(int *)(param_1 + 0x54) + 0x5a) ^ 0x80000000;
  local_10 = 0x43300000;
  *(float *)(iVar1 + 0x268) = (float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e36d8);
  (**(code **)(*DAT_803dcaa8 + 4))(iVar1,0,0x40007,1);
  (**(code **)(*DAT_803dcaa8 + 8))(iVar1,1,&DAT_80320f30,iVar1 + 0x268,1);
  (**(code **)(*DAT_803dcaa8 + 0xc))(iVar1,1,&DAT_80320f30,iVar1 + 0x268,local_18);
  (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,iVar1);
  FUN_80035f00(param_1);
  *(undefined *)(iVar1 + 0x25b) = 0;
  FUN_80037964(param_1,1);
  FUN_800200e8(0x3f8,0);
  return;
}

