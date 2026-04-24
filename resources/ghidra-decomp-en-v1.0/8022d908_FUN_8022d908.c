// Function: FUN_8022d908
// Entry: 8022d908
// Size: 212 bytes

void FUN_8022d908(short *param_1)

{
  int iVar1;
  float local_58;
  float local_54;
  float local_50;
  undefined auStack76 [68];
  
  iVar1 = *(int *)(param_1 + 0x5c);
  if (((param_1[0x58] & 0x1000U) != 0) && (*(char *)(iVar1 + 0x47f) != '\0')) {
    FUN_8002b47c(param_1,auStack76,0);
    FUN_80247494(auStack76,iVar1 + 0x484,&local_58);
    local_58 = local_58 + FLOAT_803dcdd8;
    local_50 = local_50 + FLOAT_803dcddc;
    FUN_8008020c((double)local_58,(double)local_54,(double)local_50,(double)FLOAT_803e6ff8,
                 (int)(short)((-0x8000 - *param_1) + *(short *)(iVar1 + 0x490)),
                 (int)(short)(param_1[1] + *(short *)(iVar1 + 0x492)),
                 (int)(short)(param_1[2] + *(short *)(iVar1 + 0x494)));
  }
  return;
}

