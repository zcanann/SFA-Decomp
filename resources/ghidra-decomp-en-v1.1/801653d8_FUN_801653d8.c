// Function: FUN_801653d8
// Entry: 801653d8
// Size: 420 bytes

void FUN_801653d8(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined4 *)(iVar2 + 0x288) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(iVar2 + 0x28c) = *(undefined4 *)(param_1 + 0x14);
  *(short *)(iVar2 + 0x26a) = (short)(int)(FLOAT_803e3c64 * *(float *)(param_2 + 0x1c));
  *(undefined *)(iVar2 + 0x279) = *(undefined *)(param_2 + 0x1b);
  *(undefined4 *)(iVar2 + 0x26c) = *(undefined4 *)(param_1 + 8);
  uVar1 = FUN_80022264(200,500);
  *(float *)(iVar2 + 0x270) =
       *(float *)(iVar2 + 0x26c) /
       (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e3c08);
  *(undefined4 *)(iVar2 + 0x284) = 0;
  *(float *)(param_1 + 8) = FLOAT_803e3c68;
  (**(code **)(*DAT_803dd728 + 4))(iVar2,0,0x40000,1);
  (**(code **)(*DAT_803dd728 + 8))(iVar2,1,&DAT_80320ed8,&DAT_803dc9a8,8);
  (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar2);
  *(undefined *)(iVar2 + 0x278) = 0;
  uVar1 = FUN_80022264(0xfffffed4,300);
  *(float *)(iVar2 + 0x2a0) =
       FLOAT_803e3c4c + (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e3c08);
  FUN_800372f8(param_1,3);
  FUN_800372f8(param_1,0x31);
  FUN_80035ff8(param_1);
  FUN_80037a5c(param_1,1);
  if (*(short *)(param_1 + 0x46) == 0x4ba) {
    *(byte *)(iVar2 + 0x27a) = *(byte *)(iVar2 + 0x27a) | 0x10;
  }
  return;
}

