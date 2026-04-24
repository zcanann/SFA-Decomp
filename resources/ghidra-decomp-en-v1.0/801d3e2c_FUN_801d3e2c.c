// Function: FUN_801d3e2c
// Entry: 801d3e2c
// Size: 456 bytes

void FUN_801d3e2c(int param_1)

{
  undefined2 uVar2;
  int iVar1;
  int iVar3;
  undefined local_28 [8];
  undefined4 local_20;
  uint uStack28;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  local_28[0] = 5;
  *(float *)(iVar3 + 0x274) = FLOAT_803e53f0;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  *(float *)(param_1 + 0x28) = FLOAT_803e53f4;
  FUN_80035f00();
  uVar2 = FUN_800221a0(0,0xffff);
  *(undefined2 *)(iVar3 + 0x2ac) = uVar2;
  uStack28 = FUN_800221a0(0,1000);
  uStack28 = uStack28 ^ 0x80000000;
  local_20 = 0x43300000;
  *(float *)(iVar3 + 0x280) =
       (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e53a0) / FLOAT_803e5390;
  (**(code **)(*DAT_803dcaa8 + 4))(iVar3 + 8,0,0x40002,1);
  (**(code **)(*DAT_803dcaa8 + 0xc))(iVar3 + 8,1,&DAT_80326d98,&DAT_803dbfc0,local_28);
  (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,iVar3 + 8);
  (**(code **)(*DAT_803dca88 + 8))(param_1,0x3f1,0,4,0xffffffff,0);
  iVar1 = FUN_8001f4c8(param_1,1);
  if (iVar1 != 0) {
    FUN_8001db2c(iVar1,2);
    FUN_8001daf0(iVar1,0xff,0,0xff,0);
    FUN_8001db14(iVar1,1);
    FUN_8001dc38((double)FLOAT_803e5388,(double)FLOAT_803e538c,iVar1);
  }
  *(int *)(iVar3 + 0x270) = iVar1;
  FUN_80037964(param_1,2);
  uVar2 = FUN_800221a0(0xfffffe00,0x200);
  *(undefined2 *)(iVar3 + 0x2ae) = uVar2;
  return;
}

