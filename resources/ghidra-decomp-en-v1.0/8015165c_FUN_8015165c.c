// Function: FUN_8015165c
// Entry: 8015165c
// Size: 760 bytes

void FUN_8015165c(void)

{
  float fVar1;
  int iVar2;
  char cVar4;
  int iVar3;
  int iVar5;
  uint uVar6;
  undefined *puVar7;
  undefined *puVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_802860dc();
  iVar2 = (int)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  uVar6 = (uint)*(byte *)(iVar5 + 0x33b);
  puVar8 = (&PTR_DAT_8031f180)[uVar6 * 10];
  puVar7 = (&PTR_DAT_8031f188)[uVar6 * 10];
  if ((uVar6 == 5) && ((*(uint *)(iVar5 + 0x2dc) & 0x800000) != 0)) {
    FUN_800200e8(0x1c8,1);
  }
  if ((*(int *)(iVar5 + 0x29c) != 0) && (*(short *)(*(int *)(iVar5 + 0x29c) + 0x44) == 1)) {
    FUN_8001fea8();
  }
  FUN_8015039c(iVar2,iVar5);
  fVar1 = FLOAT_803e2740;
  if (((*(float *)(iVar5 + 0x328) != FLOAT_803e2740) && (*(short *)(iVar5 + 0x338) != 0)) &&
     (*(float *)(iVar5 + 0x328) = *(float *)(iVar5 + 0x328) - FLOAT_803db414,
     *(float *)(iVar5 + 0x328) <= fVar1)) {
    *(float *)(iVar5 + 0x328) = fVar1;
    *(uint *)(iVar5 + 0x2dc) = *(uint *)(iVar5 + 0x2dc) | 0x40000000;
    *(ushort *)(iVar5 + 0x338) = (ushort)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 10];
  }
  cVar4 = FUN_8014ffb4(iVar2,iVar5,1);
  if (cVar4 == '\0') {
    if ((*(uint *)(iVar5 + 0x2dc) & 0x40000000) != 0) {
      iVar3 = FUN_8002b9ec();
      FUN_8014c11c((double)FLOAT_803e27ac,iVar2,3,0x10,&DAT_803ac428);
      if (*(ushort *)(iVar5 + 0x338) == 0) {
        if ((iVar3 == 0) ||
           (((*(uint *)(iVar5 + 0x2dc) & 0x800080) == 0 && (iVar3 = FUN_80296118(iVar3), iVar3 != 0)
            ))) {
          FUN_801513ac(iVar2,iVar5);
        }
        else {
          FUN_801511e8(iVar2,iVar5);
        }
      }
      else {
        *(char *)(iVar5 + 0x2f2) =
             (char)*(undefined4 *)(puVar7 + (uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 0xc);
        iVar3 = (uint)*(ushort *)(iVar5 + 0x338) * 0x10;
        FUN_8014d08c((double)*(float *)(puVar7 + iVar3),iVar2,iVar5,puVar7[iVar3 + 8],0,
                     *(uint *)(puVar7 + iVar3 + 4) & 0xff);
        FUN_80030304((double)*(float *)(&DAT_8031dd30 +
                                       (uint)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 +
                                                          8] * 4),iVar2);
        *(ushort *)(iVar5 + 0x338) =
             (ushort)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 9];
      }
    }
    *(undefined *)(*(int *)(iVar2 + 0x54) + 0x6e) = 0;
    *(undefined *)(*(int *)(iVar2 + 0x54) + 0x6f) = 0;
    if (*(ushort *)(iVar2 + 0xa0) == (ushort)(byte)puVar8[8]) {
      *(char *)(*(int *)(iVar2 + 0x54) + 0x6e) = (char)*(undefined4 *)(puVar8 + 4);
      *(undefined *)(*(int *)(iVar2 + 0x54) + 0x6f) = puVar8[9];
    }
    if (*(ushort *)(iVar2 + 0xa0) == (ushort)(byte)puVar8[0x14]) {
      *(char *)(*(int *)(iVar2 + 0x54) + 0x6e) = (char)*(undefined4 *)(puVar8 + 0x10);
      *(undefined *)(*(int *)(iVar2 + 0x54) + 0x6f) = puVar8[0x15];
    }
    if (*(ushort *)(iVar2 + 0xa0) == (ushort)(byte)puVar8[0x20]) {
      *(char *)(*(int *)(iVar2 + 0x54) + 0x6e) = (char)*(undefined4 *)(puVar8 + 0x1c);
      *(undefined *)(*(int *)(iVar2 + 0x54) + 0x6f) = puVar8[0x21];
    }
    if ((*(byte *)(iVar5 + 0x323) & 8) == 0) {
      FUN_8014cf7c((double)*(float *)(*(int *)(iVar5 + 0x29c) + 0xc),
                   (double)*(float *)(*(int *)(iVar5 + 0x29c) + 0x14),iVar2,iVar5,10,0);
    }
  }
  FUN_80286128();
  return;
}

