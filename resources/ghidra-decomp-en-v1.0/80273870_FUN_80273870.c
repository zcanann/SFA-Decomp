// Function: FUN_80273870
// Entry: 80273870
// Size: 328 bytes

void FUN_80273870(void)

{
  uint uVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  
  FUN_80284af4();
  dVar3 = (double)FLOAT_803e77d8;
  iVar2 = -0x7fc41c88;
  dVar4 = DOUBLE_803e77e0;
  for (uVar1 = 0; uVar1 < DAT_803bd360; uVar1 = uVar1 + 1) {
    if (*(char *)(iVar2 + 8) != '\0') {
      *(undefined *)(iVar2 + 0x56) = *(undefined *)(iVar2 + 0x5a);
      *(undefined *)(iVar2 + 0x57) = *(undefined *)(iVar2 + 0x5b);
      if ((DAT_803de264 & 1) == 0) {
        if ((DAT_803de264 & 2) == 0) {
          *(undefined *)(iVar2 + 0x57) = 0;
        }
      }
      else {
        *(undefined *)(iVar2 + 0x56) = 0x40;
        *(undefined *)(iVar2 + 0x57) = 0;
      }
      if (*(char *)(iVar2 + 8) != '\x03') {
        FUN_8028383c((double)(float)(dVar3 * (double)(float)((double)CONCAT44(0x43300000,
                                                                              (uint)*(byte *)(iVar2 
                                                  + 0x55)) - dVar4)),
                     (double)(float)(dVar3 * (double)(float)((double)CONCAT44(0x43300000,
                                                                              (uint)*(byte *)(iVar2 
                                                  + 0x58)) - dVar4)),
                     (double)(float)(dVar3 * (double)(float)((double)CONCAT44(0x43300000,
                                                                              (uint)*(byte *)(iVar2 
                                                  + 0x59)) - dVar4)),*(undefined4 *)(iVar2 + 0x48),0
                     ,(uint)*(byte *)(iVar2 + 0x56) << 0x10,(uint)*(byte *)(iVar2 + 0x57) << 0x10);
      }
    }
    iVar2 = iVar2 + 100;
  }
  FUN_80284abc();
  return;
}

