// Function: FUN_8021f754
// Entry: 8021f754
// Size: 368 bytes

void FUN_8021f754(undefined2 *param_1,int param_2)

{
  float fVar1;
  short sVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 *puVar5;
  
  puVar5 = *(undefined4 **)(param_1 + 0x5c);
  if (param_1[0x23] == 0x72e) {
    *(code **)(param_1 + 0x5e) = FUN_8021f34c;
    puVar3 = (undefined4 *)FUN_800394ac(param_1,0,0);
    if (puVar3 != (undefined4 *)0x0) {
      *puVar3 = 0x100;
    }
  }
  *(undefined *)((int)puVar5 + 0x19a) = 2;
  FUN_80035f20(param_1);
  iVar4 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar4 != 0) {
    param_1[3] = param_1[3] | 0x4000;
    FUN_8002ce88(param_1);
    FUN_80035f00(param_1);
  }
  FUN_80037200(param_1,3);
  *puVar5 = 0;
  *(byte *)((int)puVar5 + 0x19b) = *(byte *)((int)puVar5 + 0x19b) & 0xef | 0x10;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  sVar2 = *(short *)(param_2 + 0x1a);
  if (sVar2 == 0) {
    sVar2 = 0x14;
  }
  *(short *)(puVar5 + 0x66) = sVar2;
  *(short *)(puVar5 + 0x66) = *(short *)(puVar5 + 0x66) * 0x3c;
  puVar5[0x49] = FLOAT_803e6b68;
  iVar4 = FUN_8001ffb4(0x9b9);
  if (iVar4 == 0) {
    *(byte *)((int)puVar5 + 0x19b) = *(byte *)((int)puVar5 + 0x19b) & 0xf7;
  }
  else {
    *(byte *)((int)puVar5 + 0x19b) = *(byte *)((int)puVar5 + 0x19b) & 0x7f | 0x80;
    *(byte *)((int)puVar5 + 0x19b) = *(byte *)((int)puVar5 + 0x19b) & 0xf7 | 8;
  }
  fVar1 = FLOAT_803e6b6c;
  *(float *)(param_1 + 0x16) = FLOAT_803e6b6c;
  *(float *)(param_1 + 0x14) = fVar1;
  *(float *)(param_1 + 0x12) = fVar1;
  return;
}

