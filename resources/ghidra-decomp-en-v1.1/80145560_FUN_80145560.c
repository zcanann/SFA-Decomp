// Function: FUN_80145560
// Entry: 80145560
// Size: 300 bytes

void FUN_80145560(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  float fVar1;
  ushort uVar3;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 extraout_f1;
  undefined8 uVar4;
  byte local_18 [16];
  
  local_18[0] = FUN_800dbf88((float *)(param_9 + 0x18),(undefined *)0x0);
  uVar4 = extraout_f1;
  if ((local_18[0] == 0) && (uVar3 = FUN_800dc158((float *)(param_9 + 0x18)), uVar3 != 0)) {
    uVar4 = FUN_800db4b0((uint)uVar3,local_18);
  }
  if (local_18[0] != 0) {
    *(ushort *)(param_10 + 0x532) = (ushort)local_18[0];
    *(undefined *)(param_10 + 8) = 1;
    *(undefined *)(param_10 + 10) = 0;
    fVar1 = FLOAT_803e306c;
    *(float *)(param_10 + 0x71c) = FLOAT_803e306c;
    *(float *)(param_10 + 0x720) = fVar1;
    *(uint *)(param_10 + 0x54) = *(uint *)(param_10 + 0x54) & 0xffffffef;
    *(uint *)(param_10 + 0x54) = *(uint *)(param_10 + 0x54) & 0xfffeffff;
    *(uint *)(param_10 + 0x54) = *(uint *)(param_10 + 0x54) & 0xfffdffff;
    *(uint *)(param_10 + 0x54) = *(uint *)(param_10 + 0x54) & 0xfffbffff;
    *(undefined *)(param_10 + 0xd) = 0xff;
  }
  if (DAT_803de6c8 == 0) {
    puVar2 = FUN_8002becc(0x18,0x25);
    DAT_803de6c8 = FUN_8002e088(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2
                                ,4,0xff,0xffffffff,*(uint **)(param_9 + 0x30),in_r8,in_r9,in_r10);
  }
  *(byte *)(param_10 + 0x58) = *(byte *)(param_10 + 0x58) & 0x7f | 0x80;
  return;
}

