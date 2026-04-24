// Function: FUN_8020c71c
// Entry: 8020c71c
// Size: 460 bytes

void FUN_8020c71c(int param_1,int param_2)

{
  short sVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar3 = *(undefined4 **)(param_1 + 0xb8);
  *puVar3 = 0;
  FUN_80035a58(param_1,4);
  *(short *)(param_1 + 2) = (short)((int)*(char *)(param_2 + 0x18) << 8);
  if (*(int *)(param_2 + 0x14) == -1) {
    *(byte *)((int)puVar3 + 0x79) = *(byte *)((int)puVar3 + 0x79) & 0x7f | 0x80;
  }
  FUN_800803f8(puVar3 + 3);
  FUN_800803f8(puVar3 + 4);
  puVar3[2] = 0;
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x727) {
    puVar3[0x1b] = &DAT_803dce10;
    FUN_80035a6c(param_1,*(undefined2 *)(param_2 + 0x1c));
    puVar3[0x1d] = (int)*(short *)(param_2 + 0x1c);
    puVar3[0x1c] = FLOAT_803e7258;
    *(float *)(param_1 + 8) =
         (*(float *)(*(int *)(param_1 + 0x50) + 4) *
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
                DOUBLE_803e7238)) / FLOAT_803e7228;
  }
  else if ((sVar1 < 0x727) && (sVar1 == 0x709)) {
    puVar3[0x1b] = &DAT_803dce08;
    *(float *)(param_1 + 8) =
         (*(float *)(*(int *)(param_1 + 0x50) + 4) *
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
                DOUBLE_803e7238)) / FLOAT_803e725c;
    iVar2 = (int)*(short *)(param_2 + 0x1c) / 7 + ((int)*(short *)(param_2 + 0x1c) >> 0x1f);
    FUN_80035a6c(param_1,(short)iVar2 - (short)(iVar2 >> 0x1f));
    FUN_80080404((float *)(puVar3 + 4),(short)(int)FLOAT_803dce18);
    puVar3[0x1c] = FLOAT_803e7260;
    iVar2 = (int)*(short *)(param_2 + 0x1c) / 5 + ((int)*(short *)(param_2 + 0x1c) >> 0x1f);
    puVar3[0x1d] = iVar2 - (iVar2 >> 0x1f);
    puVar3[0x1a] = FLOAT_803e722c;
  }
  return;
}

