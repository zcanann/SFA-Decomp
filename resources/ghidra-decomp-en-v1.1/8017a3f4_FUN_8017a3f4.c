// Function: FUN_8017a3f4
// Entry: 8017a3f4
// Size: 348 bytes

void FUN_8017a3f4(int param_1)

{
  int iVar1;
  undefined local_18 [8];
  undefined4 local_10;
  uint uStack_c;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  local_18[0] = 5;
  FUN_800033a8(iVar1,0,0x2cc);
  FUN_8002bac4();
  *(undefined *)(iVar1 + 0x274) = 0;
  *(float *)(iVar1 + 0x26c) = FLOAT_803e4334;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  uStack_c = (int)*(short *)(*(int *)(param_1 + 0x54) + 0x5a) ^ 0x80000000;
  local_10 = 0x43300000;
  *(float *)(iVar1 + 0x268) = (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e4370);
  (**(code **)(*DAT_803dd728 + 4))(iVar1,0,0x40007,1);
  (**(code **)(*DAT_803dd728 + 8))(iVar1,1,&DAT_80321b80,iVar1 + 0x268,1);
  (**(code **)(*DAT_803dd728 + 0xc))(iVar1,1,&DAT_80321b80,iVar1 + 0x268,local_18);
  (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar1);
  FUN_80035ff8(param_1);
  *(undefined *)(iVar1 + 0x25b) = 0;
  FUN_80037a5c(param_1,1);
  FUN_800201ac(0x3f8,0);
  return;
}

