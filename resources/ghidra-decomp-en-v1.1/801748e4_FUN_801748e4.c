// Function: FUN_801748e4
// Entry: 801748e4
// Size: 336 bytes

undefined4 FUN_801748e4(uint param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_8002bac4();
  if (((*(ushort *)(param_2 + 0x100) & 0x80) == 0) && (uVar2 = FUN_80296164(iVar1,10), uVar2 == 0))
  {
    FUN_8000bb38(param_1,0x66);
    *(ushort *)(param_2 + 0x100) = *(ushort *)(param_2 + 0x100) | 2;
    if ((*(ushort *)(param_2 + 0x100) & 4) == 0) {
      FUN_801750a8();
    }
    if (*(float *)(param_1 + 0xc) <= FLOAT_803e41c4 + *(float *)(iVar3 + 8)) {
      FUN_800201ac((int)*(short *)(param_2 + 0xac),1);
      *(ushort *)(param_2 + 0x100) = *(ushort *)(param_2 + 0x100) | 0x80;
      *(float *)(param_1 + 0xc) = (float)((double)*(float *)(iVar3 + 8) - DOUBLE_803e41c8);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar3 + 0xc);
      *(float *)(param_1 + 0x14) = (float)(DOUBLE_803e41d0 + (double)*(float *)(iVar3 + 0x10));
      FUN_8000bb38(param_1,0x68);
    }
    uVar2 = FUN_80020078(0xa1a);
    if (uVar2 != 0) {
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar3 + 8);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar3 + 0x10);
    }
  }
  else {
    FUN_8000b7dc(param_1,8);
  }
  return 0;
}

