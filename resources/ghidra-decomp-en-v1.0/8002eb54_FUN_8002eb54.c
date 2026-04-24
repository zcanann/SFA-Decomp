// Function: FUN_8002eb54
// Entry: 8002eb54
// Size: 452 bytes

void FUN_8002eb54(undefined4 param_1,int param_2,int param_3,uint param_4,undefined2 param_5)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = (int)*(short *)(param_2 + ((int)param_4 >> 8) * 2 + 0x70) + (param_4 & 0xff);
  if ((int)(uint)*(ushort *)(param_2 + 0xec) <= iVar3) {
    iVar3 = *(ushort *)(param_2 + 0xec) - 1;
  }
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  if ((*(ushort *)(param_2 + 2) & 0x40) == 0) {
    *(short *)(param_3 + 0x48) = (short)iVar3;
    iVar3 = *(int *)(*(int *)(param_2 + 100) + (uint)*(ushort *)(param_3 + 0x48) * 4);
  }
  else {
    if (*(short *)(param_3 + 100) != iVar3) {
      *(short *)(param_3 + 0x48) = (short)*(char *)(param_3 + 0x62);
      *(short *)(param_3 + 0x4a) = 1 - *(char *)(param_3 + 0x62);
      if (*(short *)(*(int *)(param_2 + 0x6c) + iVar3 * 2) == -1) {
        FUN_8007d6dc(s__objanim_c____setBlendMove__WARN_802cad50,*(undefined2 *)(param_2 + 4));
        iVar3 = 0;
      }
      FUN_80024e7c((int)*(short *)(*(int *)(param_2 + 0x6c) + iVar3 * 2),(int)(short)iVar3,
                   *(undefined4 *)(param_3 + (uint)*(ushort *)(param_3 + 0x48) * 4 + 0x24),param_2);
      *(short *)(param_3 + 100) = (short)iVar3;
    }
    iVar3 = *(int *)(param_3 + (uint)*(ushort *)(param_3 + 0x48) * 4 + 0x24) + 0x80;
  }
  *(int *)(param_3 + 0x3c) = iVar3 + 6;
  uVar2 = (int)*(char *)(iVar3 + 1) & 0xf0;
  if (uVar2 == (int)*(char *)(param_3 + 0x60)) {
    fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(param_3 + 0x3c) + 1)) -
                   DOUBLE_803de8e8);
    if (uVar2 == 0) {
      fVar1 = fVar1 - FLOAT_803de8e0;
    }
    if (fVar1 == *(float *)(param_3 + 0x14)) {
      *(undefined2 *)(param_3 + 0x5a) = param_5;
    }
    else {
      *(undefined2 *)(param_3 + 0x5a) = 0;
    }
  }
  else {
    *(undefined2 *)(param_3 + 0x5a) = 0;
  }
  return;
}

