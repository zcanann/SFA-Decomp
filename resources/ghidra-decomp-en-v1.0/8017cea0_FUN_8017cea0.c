// Function: FUN_8017cea0
// Entry: 8017cea0
// Size: 232 bytes

void FUN_8017cea0(short *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  
  puVar4 = *(undefined **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x28) << 8;
  *(code **)(param_1 + 0x5e) = FUN_8017cbdc;
  param_1[0x58] = param_1[0x58] | 0x6000;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x2a);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  FUN_80037200(param_1,0xf);
  iVar2 = 0;
  iVar3 = param_2;
  do {
    uVar1 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x18));
    if (((int)(uint)*(byte *)(param_2 + 0x30) >> (iVar2 + 4U & 0x3f) & 1U) == uVar1) break;
    iVar3 = iVar3 + 2;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  *puVar4 = (char)iVar2;
  return;
}

