// Function: FUN_801c8680
// Entry: 801c8680
// Size: 428 bytes

void FUN_801c8680(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)

{
  uint uVar1;
  short *psVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar3;
  double dVar4;
  
  pfVar3 = *(float **)(param_9 + 0x5c);
  uVar1 = FUN_80020078(0x5af);
  if (uVar1 != 0) {
    *(undefined4 *)(param_9 + 0x7c) = 0;
    *(byte *)((int)pfVar3 + 5) = *(byte *)((int)pfVar3 + 5) & 0x7f;
    *(undefined *)((int)param_9 + 0x37) = 0xff;
    *(undefined *)(param_9 + 0x1b) = 0xff;
  }
  if (-1 < *(char *)((int)pfVar3 + 5)) {
    if ((*(int *)(param_9 + 0x7c) == 0) && (uVar1 = FUN_80020078(0x148), uVar1 != 0)) {
      *pfVar3 = FLOAT_803e5ce4;
      *(undefined4 *)(param_9 + 0x7c) = 1;
    }
    uVar1 = FUN_8002e144();
    if (((uVar1 & 0xff) != 0) && (*pfVar3 != FLOAT_803e5ce8)) {
      *pfVar3 = *pfVar3 - FLOAT_803dc074;
      FUN_800972fc(param_9,2,1,1,0);
      dVar4 = (double)*pfVar3;
      if (dVar4 <= (double)FLOAT_803e5ce8) {
        FUN_8000b4f0(0,0x167,1);
        psVar2 = FUN_8002becc(0x24,*(byte *)(pfVar3 + 1) + 500);
        *(byte *)((int)pfVar3 + 5) = *(byte *)((int)pfVar3 + 5) & 0x7f | 0x80;
        *(undefined *)((int)psVar2 + 7) = 0xff;
        *(undefined *)(psVar2 + 2) = 0x20;
        *(undefined *)((int)psVar2 + 5) = 2;
        *(undefined4 *)(psVar2 + 4) = *(undefined4 *)(param_9 + 6);
        *(undefined4 *)(psVar2 + 6) = *(undefined4 *)(param_9 + 8);
        *(undefined4 *)(psVar2 + 8) = *(undefined4 *)(param_9 + 10);
        *psVar2 = *(byte *)(pfVar3 + 1) + 500;
        *(char *)(psVar2 + 0xc) = (char)((ushort)*param_9 >> 8);
        psVar2[0xd] = u___00___80326ff8[*(byte *)(pfVar3 + 1)];
        FUN_8002e088(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar2,5,
                     *(undefined *)(param_9 + 0x56),0xffffffff,*(uint **)(param_9 + 0x18),in_r8,
                     in_r9,in_r10);
      }
    }
  }
  return;
}

