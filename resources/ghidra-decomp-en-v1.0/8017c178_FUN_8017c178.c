// Function: FUN_8017c178
// Entry: 8017c178
// Size: 284 bytes

void FUN_8017c178(short *param_1,int param_2)

{
  char cVar1;
  char *pcVar2;
  
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  param_1[2] = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  *(code **)(param_1 + 0x5e) = FUN_8017bcf8;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x21);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  pcVar2 = *(char **)(param_1 + 0x5c);
  cVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1c));
  *pcVar2 = cVar1;
  FUN_80037200(param_1,0xf);
  if ((*(byte *)(param_2 + 0x1b) & 1) == 0) {
    if ((*(ushort *)(param_2 + 0x26) & 1) != 0) {
      if (*pcVar2 == '\0') {
        *(undefined4 *)(param_1 + 0x7c) = 1;
      }
      else {
        *(undefined4 *)(param_1 + 0x7c) = 0;
      }
    }
  }
  else if (*pcVar2 != '\0') {
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  return;
}

