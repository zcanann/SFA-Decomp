// Function: FUN_8029eb54
// Entry: 8029eb54
// Size: 372 bytes

undefined4
FUN_8029eb54(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  ushort uVar2;
  undefined4 uVar3;
  int iVar4;
  bool bVar5;
  bool bVar6;
  double dVar7;
  double dVar8;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(undefined2 *)(param_10 + 0x278) = 0x1c;
    *(undefined4 *)(iVar4 + 0x898) = 0;
  }
  fVar1 = FLOAT_803e8b3c;
  dVar7 = (double)FLOAT_803e8b3c;
  *(float *)(param_10 + 0x294) = FLOAT_803e8b3c;
  *(float *)(param_10 + 0x284) = fVar1;
  *(float *)(param_10 + 0x280) = fVar1;
  *(float *)(param_9 + 0x24) = fVar1;
  *(float *)(param_9 + 0x28) = fVar1;
  *(float *)(param_9 + 0x2c) = fVar1;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    dVar8 = (double)*(float *)(iVar4 + 0x654);
    bVar5 = dVar8 < dVar7;
    if (bVar5) {
      dVar8 = -dVar8;
    }
    dVar7 = (double)*(float *)(iVar4 + 0x65c);
    bVar6 = dVar7 < (double)FLOAT_803e8b3c;
    if (bVar6) {
      dVar7 = -dVar7;
    }
    if (dVar8 <= dVar7) {
      if (bVar6) {
        *(undefined *)(iVar4 + 0x682) = 2;
      }
      else {
        *(undefined *)(iVar4 + 0x682) = 3;
      }
    }
    else if (bVar5) {
      *(undefined *)(iVar4 + 0x682) = 0;
    }
    else {
      *(undefined *)(iVar4 + 0x682) = 1;
    }
    FUN_8003042c((double)FLOAT_803e8b3c,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x57,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8c80;
    if (*(short *)(iVar4 + 0x81a) == 0) {
      uVar2 = 0x2d3;
    }
    else {
      uVar2 = 0x2b;
    }
    FUN_8000bb38(param_9,uVar2);
  }
  if (*(char *)(param_10 + 0x346) == '\0') {
    uVar3 = 0;
  }
  else {
    *(code **)(param_10 + 0x308) = FUN_802a58ac;
    uVar3 = 0xffffffff;
  }
  return uVar3;
}

