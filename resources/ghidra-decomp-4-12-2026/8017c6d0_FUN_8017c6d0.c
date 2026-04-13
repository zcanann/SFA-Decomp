// Function: FUN_8017c6d0
// Entry: 8017c6d0
// Size: 284 bytes

void FUN_8017c6d0(short *param_1,int param_2)

{
  uint uVar1;
  char *pcVar2;
  
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  param_1[2] = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  *(code **)(param_1 + 0x5e) = FUN_8017c250;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x21);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  pcVar2 = *(char **)(param_1 + 0x5c);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1c));
  *pcVar2 = (char)uVar1;
  FUN_800372f8((int)param_1,0xf);
  if ((*(byte *)(param_2 + 0x1b) & 1) == 0) {
    if ((*(ushort *)(param_2 + 0x26) & 1) != 0) {
      if (*pcVar2 == '\0') {
        param_1[0x7c] = 0;
        param_1[0x7d] = 1;
      }
      else {
        param_1[0x7c] = 0;
        param_1[0x7d] = 0;
      }
    }
  }
  else if (*pcVar2 != '\0') {
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  return;
}

