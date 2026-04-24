// Function: FUN_8029a4a8
// Entry: 8029a4a8
// Size: 316 bytes

void FUN_8029a4a8(int param_1,int param_2)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  sVar1 = *(short *)(param_2 + 0x274);
  if ((((sVar1 != 0x2a) && (sVar1 != 0x2e)) && (sVar1 != 0x2f)) && (sVar1 != 0x2c)) {
    *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) | 0x800000;
    *(undefined2 *)(iVar3 + 0x80a) = 0xffff;
    *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) & 0xfdfffbff;
    if (*(short *)(param_2 + 0x274) != 0x2b) {
      if ((*(char *)(iVar3 + 0x8c8) != 'B') && (iVar2 = FUN_80080204(), iVar2 == 0)) {
        (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x3c,0xfe);
      }
      *(byte *)(iVar3 + 0x3f6) = *(byte *)(iVar3 + 0x3f6) & 0xbf;
    }
    DAT_803de42c = 0;
    iVar3 = 0;
    piVar4 = &DAT_80332ed4;
    do {
      if (*piVar4 != 0) {
        FUN_8002cbc4();
        *piVar4 = 0;
      }
      piVar4 = piVar4 + 1;
      iVar3 = iVar3 + 1;
    } while (iVar3 < 7);
    if (DAT_803de454 != 0) {
      FUN_80013e2c();
      DAT_803de454 = 0;
    }
  }
  return;
}

