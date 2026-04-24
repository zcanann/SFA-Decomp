// Function: FUN_8022dfcc
// Entry: 8022dfcc
// Size: 212 bytes

void FUN_8022dfcc(ushort *param_1)

{
  int iVar1;
  float local_58;
  float local_54;
  float local_50;
  float afStack_4c [17];
  
  iVar1 = *(int *)(param_1 + 0x5c);
  if (((param_1[0x58] & 0x1000) != 0) && (*(char *)(iVar1 + 0x47f) != '\0')) {
    FUN_8002b554(param_1,afStack_4c,'\0');
    FUN_80247bf8(afStack_4c,(float *)(iVar1 + 0x484),&local_58);
    local_58 = local_58 + FLOAT_803dda58;
    local_50 = local_50 + FLOAT_803dda5c;
    FUN_80080498((double)local_58,(double)local_54,(double)local_50,(double)FLOAT_803e7c90,
                 (-0x8000 - *param_1) + *(short *)(iVar1 + 0x490),
                 param_1[1] + *(short *)(iVar1 + 0x492),param_1[2] + *(short *)(iVar1 + 0x494));
  }
  return;
}

