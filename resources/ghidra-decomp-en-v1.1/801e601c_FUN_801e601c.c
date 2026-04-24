// Function: FUN_801e601c
// Entry: 801e601c
// Size: 296 bytes

undefined4 FUN_801e601c(int param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  undefined auStack_28 [6];
  undefined2 local_22;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  uVar1 = FUN_80022264(0,1);
  if (uVar1 == 0) {
    *(undefined *)(param_3 + 0x90) = 8;
  }
  else {
    *(undefined *)(param_3 + 0x90) = 4;
  }
  *(undefined *)(param_3 + 0x56) = 0;
  *(undefined2 *)(param_3 + 0x6e) = 0xffff;
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffdf;
  iVar2 = FUN_8002bac4();
  if ((iVar2 != 0) && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    local_20 = FLOAT_803e6614;
    local_22 = 0xc0d;
    local_1c = local_1c - *(float *)(param_1 + 0x18);
    local_18 = local_18 - *(float *)(param_1 + 0x1c);
    local_14 = local_14 - *(float *)(param_1 + 0x20);
    for (iVar2 = 0; iVar2 < (int)(uint)DAT_803dc070; iVar2 = iVar2 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7a8,auStack_28,6,0xffffffff,0);
    }
  }
  return 0;
}

