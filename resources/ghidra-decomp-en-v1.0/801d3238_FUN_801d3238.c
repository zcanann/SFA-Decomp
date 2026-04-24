// Function: FUN_801d3238
// Entry: 801d3238
// Size: 320 bytes

void FUN_801d3238(undefined2 *param_1,int param_2,int param_3)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x1f) << 8);
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(code **)(param_1 + 0x5e) = FUN_801d286c;
  puVar2[3] = *(undefined4 *)(param_1 + 4);
  if (param_3 == 0) {
    if ((*(short *)(param_2 + 0x1c) == -1) || (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
      iVar1 = *(int *)(param_1 + 0x26);
      *(undefined *)(param_1 + 0x1b) = 0xff;
      param_1[3] = param_1[3] & 0xbfff;
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar1 + 8);
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar1 + 0xc);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar1 + 0x10);
      FUN_80036044(param_1);
    }
    else {
      iVar1 = *(int *)(param_1 + 0x26);
      *(undefined *)(param_1 + 0x1b) = 0xff;
      param_1[3] = param_1[3] & 0xbfff;
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar1 + 8);
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar1 + 0xc);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar1 + 0x10);
      *(float *)(param_1 + 4) = FLOAT_803e5358;
      puVar2[2] = FLOAT_803e535c;
      puVar2[1] = puVar2[3];
      puVar2[4] = (float)puVar2[1] / (float)puVar2[2];
      *puVar2 = puVar2[2];
      FUN_80036044(param_1);
      *(undefined *)(puVar2 + 5) = 1;
    }
  }
  return;
}

