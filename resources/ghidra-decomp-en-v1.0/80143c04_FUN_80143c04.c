// Function: FUN_80143c04
// Entry: 80143c04
// Size: 464 bytes

undefined4 FUN_80143c04(int param_1,int param_2)

{
  float fVar1;
  bool bVar2;
  int iVar3;
  char cVar6;
  int iVar4;
  undefined4 uVar5;
  
  *(undefined4 *)(param_2 + 0x24) = *(undefined4 *)(param_2 + 4);
  iVar3 = *(int *)(param_2 + 0x24) + 0x18;
  if (*(int *)(param_2 + 0x28) != iVar3) {
    *(int *)(param_2 + 0x28) = iVar3;
    *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xfffffbff;
    *(undefined2 *)(param_2 + 0xd2) = 0;
  }
  if (FLOAT_803e23dc == *(float *)(param_2 + 0x71c)) {
    *(undefined *)(param_2 + 0xd) = 0xff;
    fVar1 = FLOAT_803e24c8;
  }
  else {
    fVar1 = FLOAT_803e2408;
    if ((*(uint *)(param_2 + 0x54) & 0x20000) != 0) {
      *(undefined *)(param_2 + 0xd) = 0;
      *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xfffdffff;
      fVar1 = FLOAT_803e2408;
    }
  }
  cVar6 = FUN_8013b368((double)fVar1,param_1,param_2);
  if (cVar6 == '\x01') {
    *(byte *)(param_2 + 0x728) = *(byte *)(param_2 + 0x728) & 0x7f | 0x80;
    uVar5 = 1;
  }
  else {
    if ((((cVar6 == '\x02') && ((*(uint *)(param_2 + 0x54) & 2) != 0)) &&
        (iVar3 = *(int *)(param_1 + 0xb8), (*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0)) &&
       (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
        (iVar4 = FUN_8000b578(param_1,0x10), iVar4 == 0)))) {
      FUN_800393f8(param_1,iVar3 + 0x3a8,0x35d,0x500,0xffffffff,0);
    }
    if (FLOAT_803e23dc == *(float *)(param_2 + 0x2ac)) {
      bVar2 = false;
    }
    else if (FLOAT_803e2410 == *(float *)(param_2 + 0x2b0)) {
      bVar2 = true;
    }
    else if (*(float *)(param_2 + 0x2b4) - *(float *)(param_2 + 0x2b0) <= FLOAT_803e2414) {
      bVar2 = false;
    }
    else {
      bVar2 = true;
    }
    if (bVar2) {
      uVar5 = 0;
    }
    else {
      uVar5 = FUN_80143dd4(param_1,param_2);
    }
  }
  return uVar5;
}

