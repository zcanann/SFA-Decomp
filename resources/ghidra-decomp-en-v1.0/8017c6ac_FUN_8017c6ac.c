// Function: FUN_8017c6ac
// Entry: 8017c6ac
// Size: 248 bytes

void FUN_8017c6ac(short *param_1,int param_2)

{
  int iVar1;
  byte *pbVar2;
  
  pbVar2 = *(byte **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1c) << 8;
  *(code **)(param_1 + 0x5e) = FUN_8017c2d4;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x1f);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  FUN_80037200(param_1,0xf);
  *pbVar2 = 0;
  if (((*(short *)(param_2 + 0x18) != -1) && (iVar1 = FUN_8001ffb4(), iVar1 != 0)) &&
     (*pbVar2 = *pbVar2 | 1, *(short *)(param_2 + 0x20) != 0)) {
    *pbVar2 = *pbVar2 | 2;
  }
  pbVar2[1] = 0;
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

