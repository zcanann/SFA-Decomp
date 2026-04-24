// Function: FUN_801c80cc
// Entry: 801c80cc
// Size: 428 bytes

void FUN_801c80cc(short *param_1)

{
  int iVar1;
  char cVar3;
  short *psVar2;
  float *pfVar4;
  
  pfVar4 = *(float **)(param_1 + 0x5c);
  iVar1 = FUN_8001ffb4(0x5af);
  if (iVar1 != 0) {
    *(undefined4 *)(param_1 + 0x7c) = 0;
    *(byte *)((int)pfVar4 + 5) = *(byte *)((int)pfVar4 + 5) & 0x7f;
    *(undefined *)((int)param_1 + 0x37) = 0xff;
    *(undefined *)(param_1 + 0x1b) = 0xff;
  }
  if (-1 < *(char *)((int)pfVar4 + 5)) {
    if ((*(int *)(param_1 + 0x7c) == 0) && (iVar1 = FUN_8001ffb4(0x148), iVar1 != 0)) {
      *pfVar4 = FLOAT_803e504c;
      *(undefined4 *)(param_1 + 0x7c) = 1;
    }
    cVar3 = FUN_8002e04c();
    if ((cVar3 != '\0') && (*pfVar4 != FLOAT_803e5050)) {
      *pfVar4 = *pfVar4 - FLOAT_803db414;
      FUN_80097070((double)FLOAT_803e5054,param_1,2,1,1,0);
      if (*pfVar4 <= FLOAT_803e5050) {
        FUN_8000b4d0(0,0x167,1);
        psVar2 = (short *)FUN_8002bdf4(0x24,*(byte *)(pfVar4 + 1) + 500);
        *(byte *)((int)pfVar4 + 5) = *(byte *)((int)pfVar4 + 5) & 0x7f | 0x80;
        *(undefined *)((int)psVar2 + 7) = 0xff;
        *(undefined *)(psVar2 + 2) = 0x20;
        *(undefined *)((int)psVar2 + 5) = 2;
        *(undefined4 *)(psVar2 + 4) = *(undefined4 *)(param_1 + 6);
        *(undefined4 *)(psVar2 + 6) = *(undefined4 *)(param_1 + 8);
        *(undefined4 *)(psVar2 + 8) = *(undefined4 *)(param_1 + 10);
        *psVar2 = *(byte *)(pfVar4 + 1) + 500;
        *(char *)(psVar2 + 0xc) = (char)((uint)(int)*param_1 >> 8);
        psVar2[0xd] = u___00___803263b8[*(byte *)(pfVar4 + 1)];
        FUN_8002df90(psVar2,5,(int)*(char *)(param_1 + 0x56),0xffffffff,
                     *(undefined4 *)(param_1 + 0x18));
      }
    }
  }
  return;
}

