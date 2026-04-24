// Function: FUN_80220624
// Entry: 80220624
// Size: 260 bytes

void FUN_80220624(int param_1)

{
  byte bVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  byte *pbVar5;
  
  pbVar5 = *(byte **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar2 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x20));
  if (iVar2 != 0) {
    bVar1 = *pbVar5;
    if (-1 < (char)bVar1) {
      *pbVar5 = bVar1 & 0x7f | 0x80;
      FUN_8000bb18(param_1,0x30c);
    }
    puVar3 = (undefined4 *)FUN_800394ac(param_1,0,0);
    if (puVar3 != (undefined4 *)0x0) {
      *puVar3 = 0x100;
    }
    iVar2 = FUN_800394ac(param_1,0,0);
    if (iVar2 != 0) {
      *(ushort *)(iVar2 + 10) = *(short *)(iVar2 + 10) + (short)DAT_803dc380 * (ushort)DAT_803db410;
      if (*(short *)(iVar2 + 10) < -0x1000) {
        *(undefined2 *)(iVar2 + 10) = 0;
      }
    }
  }
  iVar2 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x1e));
  if (iVar2 != 0) {
    FUN_80030334((double)FLOAT_803e6bb0,param_1,0,0);
  }
  return;
}

