// Function: FUN_8017cc04
// Entry: 8017cc04
// Size: 248 bytes

void FUN_8017cc04(short *param_1,int param_2)

{
  uint uVar1;
  byte *pbVar2;
  
  pbVar2 = *(byte **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1c) << 8;
  *(code **)(param_1 + 0x5e) = FUN_8017c82c;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x1f);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  FUN_800372f8((int)param_1,0xf);
  *pbVar2 = 0;
  if ((((int)*(short *)(param_2 + 0x18) != 0xffffffff) &&
      (uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x18)), uVar1 != 0)) &&
     (*pbVar2 = *pbVar2 | 1, *(short *)(param_2 + 0x20) != 0)) {
    *pbVar2 = *pbVar2 | 2;
  }
  pbVar2[1] = 0;
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

