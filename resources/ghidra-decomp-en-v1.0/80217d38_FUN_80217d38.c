// Function: FUN_80217d38
// Entry: 80217d38
// Size: 484 bytes

void FUN_80217d38(undefined2 *param_1,int param_2)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  
  puVar4 = *(undefined4 **)(param_1 + 0x5c);
  *(undefined *)((int)puVar4 + 0x1a6) = 4;
  FUN_80035f20();
  iVar2 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar2 != 0) {
    param_1[3] = param_1[3] | 0x4000;
    FUN_8002ce88(param_1);
    FUN_80035f00(param_1);
  }
  FUN_80037200(param_1,3);
  *puVar4 = 0;
  *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0xef;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  puVar4[0x4a] = 600;
  puVar4[0x49] = FLOAT_803e6920;
  iVar2 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar2 == 0) {
    *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0xf7;
  }
  else {
    *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0x7f | 0x80;
    *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0xf7 | 8;
  }
  *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0xfb;
  fVar1 = FLOAT_803e690c;
  *(float *)(param_1 + 0x12) = FLOAT_803e690c;
  *(float *)(param_1 + 0x14) = fVar1;
  *(float *)(param_1 + 0x16) = fVar1;
  iVar2 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar2 == 0) {
    uVar3 = FUN_801702d4((double)FLOAT_803e6938,param_1);
    puVar4[100] = uVar3;
    if (puVar4[100] != 0) {
      FUN_80170380(puVar4[100],4);
    }
    *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0xfd | 2;
  }
  else {
    *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0xfd;
    puVar4[100] = 0;
  }
  FUN_8008016c(puVar4 + 0x4b);
  FUN_80080178(puVar4 + 0x4b,(int)(short)((short)((int)*(char *)(param_2 + 0x19) << 2) + 1));
  *(undefined *)((int)puVar4 + 0x1a7) = 0;
  *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0xfe | 1;
  puVar4[0x67] = 0x429;
  if (*(char *)(param_1 + 0x56) == '\x02') {
    *(undefined2 *)(puVar4 + 0x69) = 0xe90;
  }
  else {
    *(undefined2 *)(puVar4 + 0x69) = 0xffff;
  }
  return;
}

