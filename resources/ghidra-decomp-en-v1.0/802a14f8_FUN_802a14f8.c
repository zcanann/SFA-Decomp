// Function: FUN_802a14f8
// Entry: 802a14f8
// Size: 468 bytes

undefined4 FUN_802a14f8(int param_1,uint *param_2)

{
  float fVar1;
  undefined2 uVar2;
  int iVar3;
  undefined4 local_18;
  undefined4 local_14;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) & 0xfffffffd;
  *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) | 0x2000;
  param_2[1] = param_2[1] | 0x100000;
  fVar1 = FLOAT_803e7ea4;
  param_2[0xa0] = (uint)FLOAT_803e7ea4;
  param_2[0xa1] = (uint)fVar1;
  *param_2 = *param_2 | 0x200000;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x2c) = fVar1;
  param_2[1] = param_2[1] | 0x8000000;
  *(float *)(param_1 + 0x28) = fVar1;
  if (((*(char *)((int)param_2 + 0x27a) != '\0') && (DAT_803de44c != 0)) &&
     ((*(byte *)(iVar3 + 0x3f4) >> 6 & 1) != 0)) {
    *(undefined *)(iVar3 + 0x8b4) = 1;
    *(byte *)(iVar3 + 0x3f4) = *(byte *)(iVar3 + 0x3f4) & 0xf7 | 8;
  }
  if (*(short *)(param_1 + 0xa0) == 0x41a) {
    if (*(char *)((int)param_2 + 0x346) != '\0') {
      FUN_802ab5a4(param_1,iVar3 + 4,5);
      param_2[0xc2] = (uint)FUN_8029ffd0;
      return 0xffffffed;
    }
  }
  else {
    local_18 = *(undefined4 *)(iVar3 + 0x54c);
    local_14 = *(undefined4 *)(iVar3 + 0x550);
    if ((*(char *)(iVar3 + 0x8c8) != 'H') && (*(char *)(iVar3 + 0x8c8) != 'G')) {
      (**(code **)(*DAT_803dca50 + 0x1c))(0x4b,1,1,8,&local_18,0,0xff);
    }
    FUN_80030334((double)FLOAT_803e7ea4,param_1,0x41a,1);
    uVar2 = FUN_800217c0((double)*(float *)(iVar3 + 0x56c),(double)*(float *)(iVar3 + 0x574));
    *(undefined2 *)(iVar3 + 0x478) = uVar2;
    *(undefined2 *)(iVar3 + 0x484) = *(undefined2 *)(iVar3 + 0x478);
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar3 + 0x58c);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar3 + 0x76c);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar3 + 0x594);
    param_2[0xa8] = (uint)FLOAT_803e800c;
  }
  FUN_802ab5a4(param_1,iVar3 + 4,5);
  return 0;
}

