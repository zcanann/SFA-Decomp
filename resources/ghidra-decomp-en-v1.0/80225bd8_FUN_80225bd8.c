// Function: FUN_80225bd8
// Entry: 80225bd8
// Size: 340 bytes

undefined4 FUN_80225bd8(int param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  short *psVar2;
  int iVar3;
  float *pfVar4;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  *(ushort *)((int)pfVar4 + 0x1a) = *(ushort *)((int)pfVar4 + 0x1a) | 1;
  *(ushort *)((int)pfVar4 + 0x1a) = *(ushort *)((int)pfVar4 + 0x1a) & 0xfffd;
  if (*(char *)((int)pfVar4 + 0xd) == '\x01') {
    fVar1 = *pfVar4 - FLOAT_803db414;
    *pfVar4 = fVar1;
    if (fVar1 <= FLOAT_803e6da8) {
      FUN_800200e8(0x7f7,1);
      psVar2 = (short *)FUN_8002b9ec();
      (**(code **)(*DAT_803dcaac + 0x1c))(psVar2 + 6,(int)*psVar2,1,0);
    }
  }
  else if ((*(char *)((int)pfVar4 + 0xd) == '\x02') &&
          (fVar1 = *pfVar4 - FLOAT_803db414, *pfVar4 = fVar1, fVar1 <= FLOAT_803e6da8)) {
    FUN_800200e8(0x802,1);
    psVar2 = (short *)FUN_8002b9ec();
    (**(code **)(*DAT_803dcaac + 0x1c))(psVar2 + 6,(int)*psVar2,1,0);
  }
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    if (*(char *)(param_3 + iVar3 + 0x81) == '\x01') {
      *(undefined *)(pfVar4 + 3) = 6;
    }
  }
  return 0;
}

