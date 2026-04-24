// Function: FUN_801b05a4
// Entry: 801b05a4
// Size: 196 bytes

void FUN_801b05a4(short *param_1,int param_2)

{
  undefined uVar1;
  int iVar2;
  
  *param_1 = (ushort)*(byte *)(param_2 + 0x1c) << 8;
  iVar2 = *(int *)(param_1 + 0x5c);
  *(float *)(iVar2 + 0x10) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x18) ^ 0x80000000) -
              DOUBLE_803e4818);
  *(float *)(iVar2 + 0xc) = FLOAT_803e4814;
  *(ushort *)(iVar2 + 0x14) = (ushort)*(byte *)(param_2 + 0x1d);
  uVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x22));
  *(undefined *)(iVar2 + 0x18) = uVar1;
  if ((*(short *)(param_2 + 0x24) == -1) && (*(char *)(iVar2 + 0x18) == '\0')) {
    *(undefined *)(iVar2 + 0x1b) = 1;
  }
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

