// Function: FUN_801d6cd0
// Entry: 801d6cd0
// Size: 564 bytes

/* WARNING: Removing unreachable block (ram,0x801d6d28) */

void FUN_801d6cd0(short *param_1,int param_2)

{
  byte bVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  puVar4 = *(undefined4 **)(param_1 + 0x5c);
  local_28[0] = DAT_803e60a8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x19) << 8;
  bVar1 = *(byte *)(param_2 + 0x18);
  if (bVar1 == 2) {
    *(undefined *)(puVar4 + 0x189) = 0;
    uVar2 = FUN_80022264(1000,2000);
    puVar4[0x18c] = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e60c0);
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      *(undefined *)(puVar4 + 0x189) = 0;
      uVar2 = FUN_80022264(1000,2000);
      puVar4[0x18c] = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e60c0);
    }
    else {
      *(undefined *)((int)puVar4 + 0x627) = 2;
      *(undefined *)(puVar4 + 0x189) = 0xc;
    }
  }
  else if (bVar1 < 4) {
    *(undefined *)(puVar4 + 0x189) = 0;
    uVar2 = FUN_80022264(1000,2000);
    puVar4[0x18c] = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e60c0);
  }
  uStack_1c = (uint)*(ushort *)(param_2 + 0x1c);
  local_20 = 0x43300000;
  *(float *)(param_1 + 4) =
       *(float *)(*(int *)(param_1 + 0x28) + 4) *
       ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e60d8) / FLOAT_803e60f4);
  FUN_8002b660((int)param_1);
  FUN_8002cfb8();
  puVar3 = puVar4 + 0x191;
  (**(code **)(*DAT_803dd728 + 4))(puVar3,3,0xa3,0);
  (**(code **)(*DAT_803dd728 + 0xc))(puVar3,4,&DAT_80327b38,&DAT_80327b68,local_28);
  (**(code **)(*DAT_803dd728 + 0x20))(param_1,puVar3);
  *(code **)(param_1 + 0x5e) = FUN_801d6338;
  FUN_80115200((int)param_1,puVar4,0xdc72,0x2aaa,3);
  FUN_80115318((int)puVar4,400,0x78);
  FUN_800372f8((int)param_1,0x4d);
  return;
}

