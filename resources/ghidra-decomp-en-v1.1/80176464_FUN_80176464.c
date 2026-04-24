// Function: FUN_80176464
// Entry: 80176464
// Size: 300 bytes

void FUN_80176464(void)

{
  short sVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  char in_r8;
  
  iVar3 = FUN_80286840();
  fVar2 = FLOAT_803e41c0;
  if (in_r8 == '\0') goto LAB_80176578;
  iVar4 = *(int *)(iVar3 + 0xb8);
  sVar1 = *(short *)(iVar3 + 0x46);
  if (sVar1 == 0x411) {
    uVar5 = FUN_80020078((int)*(short *)(iVar4 + 0xac));
joined_r0x801764e4:
    if (uVar5 != 0) goto LAB_80176578;
  }
  else if (sVar1 < 0x411) {
    if (sVar1 == 0x21e) {
      uVar5 = FUN_80020078((int)*(short *)(iVar4 + 0xac));
      goto joined_r0x801764e4;
    }
  }
  else if ((sVar1 == 0x54a) && (FLOAT_803e41c0 < *(float *)(iVar4 + 0x14))) {
    *(float *)(iVar4 + 0x14) = *(float *)(iVar4 + 0x14) - FLOAT_803dc074;
    if (fVar2 < *(float *)(iVar4 + 0x14)) {
      FUN_8003b6d8(200,0,0,0xff);
    }
    else {
      *(float *)(iVar4 + 0x14) = fVar2;
    }
  }
  iVar4 = **(int **)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4);
  *(ushort *)(iVar4 + 2) = *(ushort *)(iVar4 + 2) | 2;
  FUN_8003b9ec(iVar3);
LAB_80176578:
  FUN_8028688c();
  return;
}

