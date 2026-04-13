// Function: FUN_80192298
// Entry: 80192298
// Size: 308 bytes

void FUN_80192298(int param_1)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  uint *puVar4;
  
  puVar4 = *(uint **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if ((((*(byte *)(puVar4 + 5) >> 5 & 1) == 0) &&
      (uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x20)), uVar1 != 0)) &&
     ((*(byte *)(puVar4 + 5) >> 6 & 1) == 0)) {
    *(byte *)(puVar4 + 5) = *(byte *)(puVar4 + 5) & 0xdf | 0x20;
    puVar4[4] = 0;
  }
  if (((*(byte *)(puVar4 + 5) >> 5 & 1) != 0) &&
     (puVar2 = (uint *)FUN_800395a4(param_1,*puVar4), puVar2 != (uint *)0x0)) {
    puVar4[4] = puVar4[4] + (uint)*(byte *)(puVar4 + 1);
    if ((int)puVar4[4] < 0) {
      puVar4[4] = 0;
    }
    else if ((int)puVar4[2] < (int)puVar4[4]) {
      uVar1 = (uint)*(short *)(iVar3 + 0x1e);
      if (uVar1 == 0xffffffff) {
        puVar4[4] = puVar4[3];
      }
      else {
        FUN_800201ac(uVar1,1);
        *(byte *)(puVar4 + 5) = *(byte *)(puVar4 + 5) & 0xdf;
        *(byte *)(puVar4 + 5) = *(byte *)(puVar4 + 5) & 0xbf | 0x40;
        puVar4[4] = puVar4[2];
      }
    }
    *puVar2 = puVar4[4];
  }
  return;
}

