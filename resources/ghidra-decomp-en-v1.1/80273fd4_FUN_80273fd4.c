// Function: FUN_80273fd4
// Entry: 80273fd4
// Size: 328 bytes

void FUN_80273fd4(void)

{
  uint uVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  
  FUN_80285258();
  dVar3 = (double)FLOAT_803e8470;
  iVar2 = -0x7fc41028;
  dVar4 = DOUBLE_803e8478;
  for (uVar1 = 0; uVar1 < DAT_803bdfc0; uVar1 = uVar1 + 1) {
    if (*(char *)(iVar2 + 8) != '\0') {
      *(undefined *)(iVar2 + 0x56) = *(undefined *)(iVar2 + 0x5a);
      *(undefined *)(iVar2 + 0x57) = *(undefined *)(iVar2 + 0x5b);
      if ((DAT_803deee4 & 1) == 0) {
        if ((DAT_803deee4 & 2) == 0) {
          *(undefined *)(iVar2 + 0x57) = 0;
        }
      }
      else {
        *(undefined *)(iVar2 + 0x56) = 0x40;
        *(undefined *)(iVar2 + 0x57) = 0;
      }
      if (*(char *)(iVar2 + 8) != '\x03') {
        FUN_80283fa0((double)(float)(dVar3 * (double)(float)((double)CONCAT44(0x43300000,
                                                                              (uint)*(byte *)(iVar2 
                                                  + 0x55)) - dVar4)),
                     (double)(float)(dVar3 * (double)(float)((double)CONCAT44(0x43300000,
                                                                              (uint)*(byte *)(iVar2 
                                                  + 0x58)) - dVar4)),
                     (double)(float)(dVar3 * (double)(float)((double)CONCAT44(0x43300000,
                                                                              (uint)*(byte *)(iVar2 
                                                  + 0x59)) - dVar4)),*(int *)(iVar2 + 0x48),'\0',
                     (uint)*(byte *)(iVar2 + 0x56) << 0x10,(uint)*(byte *)(iVar2 + 0x57) << 0x10);
      }
    }
    iVar2 = iVar2 + 100;
  }
  FUN_80285220();
  return;
}

