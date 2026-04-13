// Function: FUN_80226228
// Entry: 80226228
// Size: 340 bytes

undefined4 FUN_80226228(int param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(ushort *)(iVar4 + 0x1e) = *(ushort *)(iVar4 + 0x1e) | 1;
  *(ushort *)(iVar4 + 0x1e) = *(ushort *)(iVar4 + 0x1e) & 0xfffd;
  if (*(char *)(iVar4 + 0x11) == '\x01') {
    fVar1 = *(float *)(iVar4 + 4) - FLOAT_803dc074;
    *(float *)(iVar4 + 4) = fVar1;
    if (fVar1 <= FLOAT_803e7a40) {
      FUN_800201ac(0x7f7,1);
      psVar2 = (short *)FUN_8002bac4();
      (**(code **)(*DAT_803dd72c + 0x1c))(psVar2 + 6,(int)*psVar2,1,0);
    }
  }
  else if ((*(char *)(iVar4 + 0x11) == '\x02') &&
          (fVar1 = *(float *)(iVar4 + 4) - FLOAT_803dc074, *(float *)(iVar4 + 4) = fVar1,
          fVar1 <= FLOAT_803e7a40)) {
    FUN_800201ac(0x802,1);
    psVar2 = (short *)FUN_8002bac4();
    (**(code **)(*DAT_803dd72c + 0x1c))(psVar2 + 6,(int)*psVar2,1,0);
  }
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    if (*(char *)(param_3 + iVar3 + 0x81) == '\x01') {
      *(undefined *)(iVar4 + 0x10) = 6;
    }
  }
  return 0;
}

