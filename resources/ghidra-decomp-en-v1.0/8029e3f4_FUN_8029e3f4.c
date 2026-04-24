// Function: FUN_8029e3f4
// Entry: 8029e3f4
// Size: 372 bytes

undefined4 FUN_8029e3f4(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  undefined4 uVar3;
  int iVar4;
  bool bVar5;
  bool bVar6;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(undefined2 *)(param_2 + 0x278) = 0x1c;
    *(undefined4 *)(iVar4 + 0x898) = 0;
  }
  fVar2 = FLOAT_803e7ea4;
  *(float *)(param_2 + 0x294) = FLOAT_803e7ea4;
  *(float *)(param_2 + 0x284) = fVar2;
  *(float *)(param_2 + 0x280) = fVar2;
  *(float *)(param_1 + 0x24) = fVar2;
  *(float *)(param_1 + 0x28) = fVar2;
  *(float *)(param_1 + 0x2c) = fVar2;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    fVar1 = *(float *)(iVar4 + 0x654);
    bVar5 = fVar1 < fVar2;
    if (bVar5) {
      fVar1 = -fVar1;
    }
    fVar2 = *(float *)(iVar4 + 0x65c);
    bVar6 = fVar2 < FLOAT_803e7ea4;
    if (bVar6) {
      fVar2 = -fVar2;
    }
    if (fVar1 <= fVar2) {
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
    FUN_80030334((double)FLOAT_803e7ea4,param_1,0x57,0);
    *(float *)(param_2 + 0x2a0) = FLOAT_803e7fe8;
    if (*(short *)(iVar4 + 0x81a) == 0) {
      uVar3 = 0x2d3;
    }
    else {
      uVar3 = 0x2b;
    }
    FUN_8000bb18(param_1,uVar3);
  }
  if (*(char *)(param_2 + 0x346) == '\0') {
    uVar3 = 0;
  }
  else {
    *(code **)(param_2 + 0x308) = FUN_802a514c;
    uVar3 = 0xffffffff;
  }
  return uVar3;
}

