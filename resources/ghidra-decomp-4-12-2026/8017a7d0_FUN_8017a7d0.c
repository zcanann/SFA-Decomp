// Function: FUN_8017a7d0
// Entry: 8017a7d0
// Size: 188 bytes

void FUN_8017a7d0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  ushort *puVar1;
  uint uVar2;
  undefined4 *puVar3;
  
  puVar3 = *(undefined4 **)(param_9 + 0xb8);
  *(code **)(param_9 + 0xbc) = FUN_8017a58c;
  puVar1 = FUN_800195a8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                        *(uint *)(param_10 + 0x1c));
  puVar3[1] = **(undefined4 **)(puVar1 + 4);
  puVar3[2] = 100;
  *puVar3 = puVar1;
  *(undefined *)(puVar3 + 3) = *(undefined *)(param_10 + 0x20);
  *(undefined2 *)((int)puVar3 + 0xe) = *(undefined2 *)(param_10 + 0x18);
  *(undefined *)(puVar3 + 5) = 0;
  *(undefined2 *)((int)puVar3 + 0x12) = 0;
  *(undefined2 *)(puVar3 + 4) = 0;
  if (((int)*(short *)((int)puVar3 + 0xe) != 0xffffffff) &&
     (uVar2 = FUN_80020078((int)*(short *)((int)puVar3 + 0xe)), uVar2 != 0)) {
    *(undefined *)(puVar3 + 5) = 4;
  }
  *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x2000;
  return;
}

