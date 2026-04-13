// Function: FUN_80233ebc
// Entry: 80233ebc
// Size: 240 bytes

void FUN_80233ebc(undefined2 *param_1,int param_2,int param_3)

{
  uint uVar1;
  undefined2 *puVar2;
  
  puVar2 = *(undefined2 **)(param_1 + 0x5c);
  uVar1 = FUN_80022264(100,300);
  *puVar2 = (short)uVar1;
  *(undefined *)((int)puVar2 + 0x15) = *(undefined *)(param_2 + 0x31);
  if (param_3 == 0) {
    uVar1 = FUN_80022264(0,0xffff);
    param_1[1] = (short)uVar1;
    uVar1 = FUN_80022264(0,0xffff);
    param_1[2] = (short)uVar1;
    uVar1 = FUN_80022264(0,0xffff);
    *param_1 = (short)uVar1;
    param_1[3] = param_1[3] | 0x4000;
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  FUN_800803f8((undefined4 *)(puVar2 + 6));
  FUN_800803f8((undefined4 *)(puVar2 + 8));
  FUN_80035ff8((int)param_1);
  FUN_80035f84((int)param_1);
  return;
}

