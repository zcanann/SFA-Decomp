// Function: FUN_801fc378
// Entry: 801fc378
// Size: 380 bytes

void FUN_801fc378(int param_1)

{
  int iVar1;
  int iVar2;
  short *psVar3;
  undefined auStack40 [28];
  
  psVar3 = *(short **)(param_1 + 0xb8);
  iVar1 = FUN_8000faac();
  if ((-1 < *(char *)(psVar3 + 1)) && (iVar2 = FUN_8001ffb4((int)*psVar3), iVar2 != 0)) {
    FUN_8000bb18(0,0x109);
    FUN_8000bb18(param_1,0x10d);
    FUN_8000bb18(param_1,0x494);
    *(byte *)(psVar3 + 1) = *(byte *)(psVar3 + 1) & 0x7f | 0x80;
  }
  if (((*(char *)(psVar3 + 1) < '\0') &&
      (FUN_8002fa48((double)FLOAT_803e6118,(double)FLOAT_803db414,param_1,0),
      (*(byte *)(psVar3 + 1) >> 6 & 1) == 0)) && (FLOAT_803e611c <= *(float *)(param_1 + 0x98))) {
    FUN_80247754(iVar1 + 0xc,param_1 + 0xc,auStack40);
    FUN_80247794(auStack40,auStack40);
    FUN_80247778((double)FLOAT_803e6120,auStack40,auStack40);
    FUN_80247730(param_1 + 0xc,auStack40,param_1 + 0xc);
    *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(param_1 + 0x20) = *(undefined4 *)(param_1 + 0x14);
    FUN_8009ab70((double)FLOAT_803e6124,param_1,1,1,0,0,0,0,0);
    *(byte *)(psVar3 + 1) = *(byte *)(psVar3 + 1) & 0xbf | 0x40;
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  return;
}

