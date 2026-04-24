// Function: FUN_801dc76c
// Entry: 801dc76c
// Size: 352 bytes

void FUN_801dc76c(short *param_1,int param_2)

{
  int iVar1;
  float fVar2;
  int iVar3;
  undefined auStack56 [32];
  undefined4 local_18;
  uint uStack20;
  longlong local_10;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *(float *)(iVar3 + 0x34) = FLOAT_803e5594;
  fVar2 = FLOAT_803e5590;
  *(float *)(iVar3 + 0x30) = FLOAT_803e5590;
  *(ushort *)(iVar3 + 0x48) = (ushort)*(byte *)(param_2 + 0x1b) << 1;
  *(undefined *)(iVar3 + 0x4c) = *(undefined *)(param_2 + 0x23);
  *(float *)(iVar3 + 0x3c) = fVar2;
  *(undefined4 *)(iVar3 + 0x38) = *(undefined4 *)(param_2 + 0x1c);
  param_1[2] = (*(byte *)(param_2 + 0x18) - 0x7f) * 0x80;
  param_1[1] = (*(byte *)(param_2 + 0x19) - 0x7f) * 0x80;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  *(float *)(param_1 + 4) = FLOAT_803e55b8 * *(float *)(param_2 + 0x1c);
  *(undefined4 *)(param_1 + 0x7c) = 0;
  param_1[0x58] = param_1[0x58] | 0x2000;
  uStack20 = FUN_800221a0(1,99);
  uStack20 = uStack20 ^ 0x80000000;
  local_18 = 0x43300000;
  FUN_80030334((double)((float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e55c8) /
                       FLOAT_803e55bc),param_1,0,0);
  FUN_8002fa48((double)FLOAT_803e558c,(double)FLOAT_803e558c,param_1,auStack56);
  iVar1 = (int)(FLOAT_803e55c0 * *(float *)(iVar3 + 0x38));
  local_10 = (longlong)iVar1;
  FUN_80035b50(param_1,iVar1,0xfffffffb,0xff);
  if ((*(byte *)(iVar3 + 0x4c) & 0x80) != 0) {
    *(byte *)(iVar3 + 0x4c) = *(byte *)(iVar3 + 0x4c) | 0x20;
  }
  return;
}

