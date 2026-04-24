// Function: FUN_80164f2c
// Entry: 80164f2c
// Size: 420 bytes

void FUN_80164f2c(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined4 *)(iVar2 + 0x288) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(iVar2 + 0x28c) = *(undefined4 *)(param_1 + 0x14);
  *(short *)(iVar2 + 0x26a) = (short)(int)(FLOAT_803e2fcc * *(float *)(param_2 + 0x1c));
  *(undefined *)(iVar2 + 0x279) = *(undefined *)(param_2 + 0x1b);
  *(undefined4 *)(iVar2 + 0x26c) = *(undefined4 *)(param_1 + 8);
  uVar1 = FUN_800221a0(200,500);
  *(float *)(iVar2 + 0x270) =
       *(float *)(iVar2 + 0x26c) /
       (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e2f70);
  *(undefined4 *)(iVar2 + 0x284) = 0;
  *(float *)(param_1 + 8) = FLOAT_803e2fd0;
  (**(code **)(*DAT_803dcaa8 + 4))(iVar2,0,0x40000,1);
  (**(code **)(*DAT_803dcaa8 + 8))(iVar2,1,&DAT_80320288,&DAT_803dbd40,8);
  (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,iVar2);
  *(undefined *)(iVar2 + 0x278) = 0;
  uVar1 = FUN_800221a0(0xfffffed4,300);
  *(float *)(iVar2 + 0x2a0) =
       FLOAT_803e2fb4 + (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e2f70);
  FUN_80037200(param_1,3);
  FUN_80037200(param_1,0x31);
  FUN_80035f00(param_1);
  FUN_80037964(param_1,1);
  if (*(short *)(param_1 + 0x46) == 0x4ba) {
    *(byte *)(iVar2 + 0x27a) = *(byte *)(iVar2 + 0x27a) | 0x10;
  }
  return;
}

