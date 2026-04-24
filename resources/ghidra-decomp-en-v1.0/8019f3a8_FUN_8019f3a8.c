// Function: FUN_8019f3a8
// Entry: 8019f3a8
// Size: 400 bytes

void FUN_8019f3a8(short *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  FUN_80035f20();
  FUN_80037964(param_1,4);
  *(code **)(param_1 + 0x5e) = FUN_8019e81c;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1d) << 8;
  FUN_80037200(param_1,3);
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined4 *)(iVar2 + 0xb0) = 0;
  *(undefined4 *)(iVar2 + 0xb4) = 0;
  *(undefined4 *)(iVar2 + 0xb8) = 0;
  *(undefined4 *)(iVar2 + 0xbc) = 0;
  *(undefined4 *)(iVar2 + 0xc0) = 0;
  *(uint *)(iVar2 + 0xc4) = (uint)*(byte *)(param_2 + 0x1c);
  *(undefined4 *)(iVar2 + 0xcc) = 0;
  FUN_8008016c(iVar2);
  *(undefined4 *)(iVar2 + 0x114) = 0;
  *(short *)(iVar2 + 0xd0) = *param_1;
  *(undefined *)(iVar2 + 0x22c) = 0;
  *(float *)(iVar2 + 0xa8) = FLOAT_803e422c;
  *(undefined4 *)(iVar2 + 0x230) = 0;
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x22));
  if (iVar1 == 0) {
    *(int *)(iVar2 + 0x234) = *(short *)(param_2 + 0x22) + -0x2fc;
    if (param_1[0x23] == 0x788) {
      *(undefined4 *)(iVar2 + 0x234) = 0xffffffff;
      *(float *)(iVar2 + 0x23c) = FLOAT_803e4244;
      *(undefined **)(iVar2 + 0x240) = &DAT_803dbe30;
    }
    else {
      if ((*(int *)(iVar2 + 0x234) < 0) || (4 < *(int *)(iVar2 + 0x234))) {
        *(undefined4 *)(iVar2 + 0x230) = 3;
      }
      *(float *)(iVar2 + 0x23c) = FLOAT_803e4258;
      *(undefined **)(iVar2 + 0x240) = &DAT_803dbe28;
      FUN_80037200(param_1,0x20);
    }
    *(byte *)(iVar2 + 0x244) = *(byte *)(iVar2 + 0x244) & 0x7f;
  }
  else {
    FUN_80035f00(param_1);
    param_1[3] = param_1[3] | 0x4000;
    *(byte *)(iVar2 + 0x22c) = *(byte *)(iVar2 + 0x22c) & 0xfe;
    FUN_8002ce88(param_1);
    FUN_80036fa4(param_1,3);
  }
  return;
}

