// Function: FUN_801e93b4
// Entry: 801e93b4
// Size: 288 bytes

void FUN_801e93b4(short *param_1,int param_2)

{
  short sVar1;
  int iVar2;
  
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(code **)(param_1 + 0x5e) = FUN_801e8ce4;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x18);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x1b) << 8;
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  sVar1 = param_1[0x23];
  if (sVar1 == 0x467) {
    FUN_801f5260((int)param_1,*(int *)(param_1 + 0x5c));
  }
  else if (sVar1 < 0x467) {
    if (sVar1 == 0x462) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x3f1,0,4,0xffffffff,0);
    }
  }
  else if (sVar1 < 0x469) {
    iVar2 = FUN_8002b660((int)param_1);
    FUN_800285f0(iVar2,FUN_801e891c);
    FUN_800372f8((int)param_1,0x4f);
  }
  return;
}

