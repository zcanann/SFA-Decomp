// Function: FUN_80142b6c
// Entry: 80142b6c
// Size: 448 bytes

void FUN_80142b6c(void)

{
  int iVar1;
  char cVar4;
  int iVar2;
  undefined4 uVar3;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar7 >> 0x20);
  iVar5 = (int)uVar7;
  if (*(short *)(iVar1 + 0xa0) == 0x1a) {
    if ((*(float *)(iVar1 + 0x98) <= FLOAT_803e24ac) || ((*(uint *)(iVar5 + 0x54) & 0x800) != 0)) {
      if ((*(uint *)(iVar5 + 0x54) & 0x8000000) != 0) {
        *(uint *)(iVar5 + 0x54) = *(uint *)(iVar5 + 0x54) & 0xfffff7ff;
        *(uint *)(iVar5 + 0x54) = *(uint *)(iVar5 + 0x54) | 0x1000;
        iVar2 = 0;
        iVar6 = iVar5;
        do {
          FUN_8017804c(*(undefined4 *)(iVar6 + 0x700));
          iVar6 = iVar6 + 4;
          iVar2 = iVar2 + 1;
        } while (iVar2 < 7);
        FUN_8000db90(iVar1,0x3dc);
        iVar6 = *(int *)(iVar1 + 0xb8);
        if (((*(byte *)(iVar6 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(iVar1 + 0xa0) || (*(short *)(iVar1 + 0xa0) < 0x29)) &&
            (iVar2 = FUN_8000b578(iVar1,0x10), iVar2 == 0)))) {
          FUN_800393f8(iVar1,iVar6 + 0x3a8,0x29d,0,0xffffffff,0);
        }
        *(undefined *)(iVar5 + 10) = 10;
      }
    }
    else {
      cVar4 = FUN_8002e04c();
      if (cVar4 != '\0') {
        *(uint *)(iVar5 + 0x54) = *(uint *)(iVar5 + 0x54) | 0x800;
        iVar6 = 0;
        do {
          iVar2 = FUN_8002bdf4(0x24,0x4f0);
          *(undefined *)(iVar2 + 4) = 2;
          *(undefined *)(iVar2 + 5) = 1;
          *(short *)(iVar2 + 0x1a) = (short)iVar6;
          uVar3 = FUN_8002df90(iVar2,5,(int)*(char *)(iVar1 + 0xac),0xffffffff,
                               *(undefined4 *)(iVar1 + 0x30));
          *(undefined4 *)(iVar5 + 0x700) = uVar3;
          iVar5 = iVar5 + 4;
          iVar6 = iVar6 + 1;
        } while (iVar6 < 7);
        FUN_8000bb18(iVar1,0x3db);
        FUN_8000dcbc(iVar1,0x3dc);
      }
    }
  }
  else {
    FUN_8013a3f0((double)FLOAT_803e23e4,iVar1,0x1a,0);
  }
  FUN_80286128(1);
  return;
}

