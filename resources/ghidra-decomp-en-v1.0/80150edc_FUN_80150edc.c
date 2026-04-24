// Function: FUN_80150edc
// Entry: 80150edc
// Size: 780 bytes

void FUN_80150edc(void)

{
  float fVar1;
  int iVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  uint uVar6;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar10 >> 0x20);
  iVar5 = (int)uVar10;
  uVar6 = (uint)*(byte *)(iVar5 + 0x33b);
  puVar9 = (&PTR_DAT_8031f16c)[uVar6 * 10];
  puVar8 = (&PTR_DAT_8031f184)[uVar6 * 10];
  puVar7 = (&PTR_DAT_8031f188)[uVar6 * 10];
  if ((uVar6 == 5) && ((*(uint *)(iVar5 + 0x2dc) & 0x800000) != 0)) {
    FUN_800200e8(0x1c8,1);
  }
  if ((*(int *)(iVar5 + 0x29c) != 0) && (*(short *)(*(int *)(iVar5 + 0x29c) + 0x44) == 1)) {
    FUN_8001fea8();
  }
  FUN_8015039c(iVar3,iVar5);
  fVar1 = FLOAT_803e2740;
  if (((*(float *)(iVar5 + 0x328) != FLOAT_803e2740) && (*(short *)(iVar5 + 0x338) != 0)) &&
     (*(float *)(iVar5 + 0x328) = *(float *)(iVar5 + 0x328) - FLOAT_803db414,
     *(float *)(iVar5 + 0x328) <= fVar1)) {
    *(float *)(iVar5 + 0x328) = fVar1;
    *(uint *)(iVar5 + 0x2dc) = *(uint *)(iVar5 + 0x2dc) | 0x40000000;
    *(ushort *)(iVar5 + 0x338) = (ushort)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 10];
  }
  cVar4 = FUN_8014ffb4(iVar3,iVar5,0);
  if (cVar4 == '\0') {
    if (((*(uint *)(iVar5 + 0x2dc) & 0x20000000) != 0) &&
       ((*(uint *)(iVar5 + 0x2e0) & 0x20000000) == 0)) {
      FUN_8000bb18(iVar3,0x17);
      *(uint *)(iVar5 + 0x2dc) = *(uint *)(iVar5 + 0x2dc) | 0x40000000;
    }
    if ((*(uint *)(iVar5 + 0x2dc) & 0x40000000) != 0) {
      if (*(ushort *)(iVar5 + 0x338) == 0) {
        *(undefined *)(iVar5 + 0x2f2) = 0;
        *(undefined *)(iVar5 + 0x2f3) = 0;
        *(undefined *)(iVar5 + 0x2f4) = 0;
        iVar2 = (uint)*(ushort *)(iVar5 + 0x2a0) * 0xc;
        if (puVar8[iVar2 + 8] == '\0') {
          *(undefined *)(iVar5 + 0x323) = 3;
          FUN_80030334((double)FLOAT_803e2740,iVar3,puVar9[0x2c],0);
        }
        else {
          FUN_8014d08c((double)*(float *)(puVar8 + iVar2),iVar3,iVar5,puVar8[iVar2 + 8],0,0xb);
          FUN_80030304((double)*(float *)(&DAT_8031dd30 +
                                         (uint)(byte)puVar8[(uint)*(ushort *)(iVar5 + 0x2a0) * 0xc +
                                                            8] * 4),iVar3);
        }
      }
      else {
        *(char *)(iVar5 + 0x2f2) =
             (char)*(undefined4 *)(puVar7 + (uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 0xc);
        iVar2 = (uint)*(ushort *)(iVar5 + 0x338) * 0x10;
        FUN_8014d08c((double)*(float *)(puVar7 + iVar2),iVar3,iVar5,puVar7[iVar2 + 8],0,
                     *(uint *)(puVar7 + iVar2 + 4) & 0xff);
        FUN_80030304((double)*(float *)(&DAT_8031dd30 +
                                       (uint)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 +
                                                          8] * 4),iVar3);
        *(ushort *)(iVar5 + 0x338) =
             (ushort)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 9];
      }
    }
    if (*(ushort *)(iVar3 + 0xa0) == (ushort)(byte)puVar9[0x2c]) {
      *(float *)(iVar5 + 0x308) =
           *(float *)(iVar5 + 0x2fc) *
           (((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar5 + 0x2a4)) - DOUBLE_803e2770
                    ) / *(float *)(iVar5 + 0x2a8)) / FLOAT_803e274c) *
           *(float *)(&DAT_8031f268 + (uint)*(byte *)(iVar5 + 0x33b) * 4);
      if (*(float *)(iVar5 + 0x308) < FLOAT_803e27a0) {
        *(float *)(iVar5 + 0x308) = FLOAT_803e27a0;
      }
    }
    if ((*(byte *)(iVar5 + 0x323) & 8) == 0) {
      FUN_8014cf7c((double)*(float *)(*(int *)(iVar5 + 0x29c) + 0xc),
                   (double)*(float *)(*(int *)(iVar5 + 0x29c) + 0x14),iVar3,iVar5,0xf,0);
    }
  }
  FUN_80286124();
  return;
}

