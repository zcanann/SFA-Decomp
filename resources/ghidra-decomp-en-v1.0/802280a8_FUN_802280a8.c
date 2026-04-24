// Function: FUN_802280a8
// Entry: 802280a8
// Size: 284 bytes

void FUN_802280a8(short *param_1,int param_2)

{
  int iVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[0x58] = param_1[0x58] | 0x6000;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x19);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1a));
  if (iVar1 != 0) {
    *(float *)(param_1 + 8) =
         *(float *)(param_2 + 0xc) -
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1c)) - DOUBLE_803e6e08);
    *puVar2 = 0x1e;
    puVar2[1] = 2;
  }
  FUN_80037200(param_1,0x31);
  *(undefined4 *)(puVar2 + 4) = 0;
  *(undefined4 *)(puVar2 + 8) = 0;
  *(undefined4 *)(puVar2 + 0xc) = 0;
  *(undefined4 *)(puVar2 + 0x10) = 0;
  *(undefined4 *)(puVar2 + 0x14) = 0;
  *(undefined4 *)(puVar2 + 0x18) = 0;
  *(undefined4 *)(puVar2 + 0x1c) = 0;
  *(undefined4 *)(puVar2 + 0x20) = 0;
  *(undefined4 *)(puVar2 + 0x24) = 0;
  *(undefined4 *)(puVar2 + 0x28) = 0;
  *(code **)(param_1 + 0x5e) = FUN_80227bb8;
  return;
}

