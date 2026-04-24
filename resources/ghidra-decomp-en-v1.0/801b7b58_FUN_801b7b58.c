// Function: FUN_801b7b58
// Entry: 801b7b58
// Size: 488 bytes

void FUN_801b7b58(undefined2 *param_1,int param_2)

{
  float fVar1;
  undefined uVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  puVar5 = *(undefined4 **)(param_1 + 0x5c);
  uVar4 = *(undefined4 *)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4);
  FUN_800279cc((double)FLOAT_803e4a88,uVar4,0,0xffffffff,0,0);
  FUN_80027980((double)FLOAT_803e4a78,uVar4,0);
  *(undefined2 *)(puVar5 + 6) = *(undefined2 *)(param_2 + 0x1a);
  if (*(short *)(puVar5 + 6) < 0xf) {
    *(undefined2 *)(puVar5 + 6) = 0xf;
  }
  *(undefined2 *)((int)puVar5 + 0x1a) = *(undefined2 *)(param_2 + 0x1c);
  if (*(short *)((int)puVar5 + 0x1a) < 0xf) {
    *(undefined2 *)((int)puVar5 + 0x1a) = 0xf;
  }
  fVar1 = FLOAT_803e4a88;
  puVar5[2] = FLOAT_803e4a88 * *(float *)(param_1 + 4);
  puVar5[2] = (float)puVar5[2] * (float)puVar5[2];
  puVar5[3] = fVar1 * *(float *)(param_1 + 4);
  puVar5[3] = (float)puVar5[3] * (float)puVar5[3];
  iVar3 = FUN_8001ffb4(0x1f0);
  if (iVar3 == 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = 2;
  }
  *(undefined *)((int)puVar5 + 0x1d) = uVar2;
  for (iVar3 = 0; iVar3 < 4; iVar3 = iVar3 + 1) {
    if ((&DAT_803dbf20)[iVar3] == '\0') {
      (&DAT_803dbf20)[iVar3] = 1;
      *(char *)((int)puVar5 + 0x1f) = (char)iVar3;
      iVar3 = 4;
    }
  }
  uVar4 = FUN_80023cc8(0x28,0x12,0);
  *puVar5 = uVar4;
  FUN_8001f71c(*puVar5,0xc,
               *(short *)(&DAT_803dbf18 + (uint)*(byte *)((int)puVar5 + 0x1f) * 2) * 0x28,0x28);
  uVar4 = FUN_80023cc8(0x28,0x12,0);
  puVar5[1] = uVar4;
  FUN_8001f71c(puVar5[1],0xc,
               (*(short *)(&DAT_803dbf18 + (uint)*(byte *)((int)puVar5 + 0x1f) * 2) + 1) * 0x28,0x28
              );
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

