// Function: FUN_802290cc
// Entry: 802290cc
// Size: 296 bytes

void FUN_802290cc(short *param_1,int param_2)

{
  uint uVar1;
  char cVar3;
  undefined4 *puVar2;
  char *pcVar4;
  
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  param_1[2] = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  *(code **)(param_1 + 0x5e) = FUN_80228b20;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x21);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  pcVar4 = *(char **)(param_1 + 0x5c);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1c));
  *pcVar4 = (char)uVar1;
  cVar3 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0x56));
  pcVar4[1] = cVar3;
  if (((*(byte *)(param_2 + 0x1b) & 1) != 0) && (*pcVar4 != '\0')) {
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  if ((*pcVar4 != '\0') &&
     (puVar2 = (undefined4 *)FUN_800395a4((int)param_1,0), puVar2 != (undefined4 *)0x0)) {
    *puVar2 = 0x100;
  }
  return;
}

