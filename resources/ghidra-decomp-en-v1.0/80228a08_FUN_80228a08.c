// Function: FUN_80228a08
// Entry: 80228a08
// Size: 296 bytes

void FUN_80228a08(short *param_1,int param_2)

{
  char cVar2;
  undefined4 *puVar1;
  char *pcVar3;
  
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  param_1[2] = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  *(code **)(param_1 + 0x5e) = FUN_80228478;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x21);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  pcVar3 = *(char **)(param_1 + 0x5c);
  cVar2 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1c));
  *pcVar3 = cVar2;
  cVar2 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0x56));
  pcVar3[1] = cVar2;
  if (((*(byte *)(param_2 + 0x1b) & 1) != 0) && (*pcVar3 != '\0')) {
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  if ((*pcVar3 != '\0') &&
     (puVar1 = (undefined4 *)FUN_800394ac(param_1,0,0), puVar1 != (undefined4 *)0x0)) {
    *puVar1 = 0x100;
  }
  return;
}

