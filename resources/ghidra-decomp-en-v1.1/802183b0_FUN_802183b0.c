// Function: FUN_802183b0
// Entry: 802183b0
// Size: 484 bytes

void FUN_802183b0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  
  puVar4 = *(undefined4 **)(param_9 + 0x5c);
  *(undefined *)((int)puVar4 + 0x1a6) = 4;
  FUN_80036018((int)param_9);
  uVar2 = FUN_80020078((int)*(short *)(param_10 + 0x1e));
  if (uVar2 != 0) {
    param_9[3] = param_9[3] | 0x4000;
    FUN_8002cf80((int)param_9);
    FUN_80035ff8((int)param_9);
  }
  FUN_800372f8((int)param_9,3);
  *puVar4 = 0;
  *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0xef;
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  puVar4[0x4a] = 600;
  puVar4[0x49] = FLOAT_803e75b8;
  uVar2 = FUN_80020078((int)*(short *)(param_10 + 0x1e));
  if (uVar2 == 0) {
    *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0xf7;
  }
  else {
    *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0x7f | 0x80;
    *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0xf7 | 8;
  }
  *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0xfb;
  fVar1 = FLOAT_803e75a4;
  *(float *)(param_9 + 0x12) = FLOAT_803e75a4;
  *(float *)(param_9 + 0x14) = fVar1;
  *(float *)(param_9 + 0x16) = fVar1;
  uVar2 = FUN_80020078((int)*(short *)(param_10 + 0x1e));
  if (uVar2 == 0) {
    iVar3 = FUN_80170780((double)FLOAT_803e75d0,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,(int)param_9);
    puVar4[100] = iVar3;
    if (puVar4[100] != 0) {
      FUN_8017082c();
    }
    *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0xfd | 2;
  }
  else {
    *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0xfd;
    puVar4[100] = 0;
  }
  FUN_800803f8(puVar4 + 0x4b);
  FUN_80080404((float *)(puVar4 + 0x4b),(short)((int)*(char *)(param_10 + 0x19) << 2) + 1);
  *(undefined *)((int)puVar4 + 0x1a7) = 0;
  *(byte *)(puVar4 + 0x6a) = *(byte *)(puVar4 + 0x6a) & 0xfe | 1;
  puVar4[0x67] = 0x429;
  if (*(char *)(param_9 + 0x56) == '\x02') {
    *(undefined2 *)(puVar4 + 0x69) = 0xe90;
  }
  else {
    *(undefined2 *)(puVar4 + 0x69) = 0xffff;
  }
  return;
}

