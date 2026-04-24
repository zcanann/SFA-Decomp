// Function: FUN_80159284
// Entry: 80159284
// Size: 976 bytes

void FUN_80159284(void)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined *puVar6;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar10 >> 0x20);
  iVar4 = (int)uVar10;
  uVar2 = (uint)*(byte *)(iVar4 + 0x33b);
  puVar9 = (&PTR_DAT_8031faf8)[uVar2 * 8];
  puVar8 = (&PTR_DAT_8031fb00)[uVar2 * 8];
  puVar7 = (&PTR_DAT_8031faf4)[uVar2 * 8];
  puVar6 = (&PTR_DAT_8031fafc)[uVar2 * 8];
  if ((*(int *)(iVar4 + 0x29c) != 0) && (*(short *)(*(int *)(iVar4 + 0x29c) + 0x44) == 1)) {
    FUN_8001fe90();
  }
  if ((*(uint *)(iVar4 + 0x2dc) & 0x80000000) != 0) {
    if (*(char *)(iVar4 + 0x33b) == '\0') {
      (**(code **)(*DAT_803dca50 + 0x24))(0,0x6c,0);
    }
    if ((*(short *)(iVar3 + 0x46) == 0x6a2) && (*(int *)(iVar3 + 200) != 0)) {
      FUN_8021fab4();
    }
    *(byte *)(iVar4 + 0x33d) = *(byte *)(iVar4 + 0x33d) | 0x10;
  }
  fVar1 = FLOAT_803e2ba8;
  if (((*(float *)(iVar4 + 0x328) != FLOAT_803e2ba8) && (*(char *)(iVar4 + 0x33f) != '\0')) &&
     (*(float *)(iVar4 + 0x328) = *(float *)(iVar4 + 0x328) - FLOAT_803db414,
     *(float *)(iVar4 + 0x328) <= fVar1)) {
    *(float *)(iVar4 + 0x328) = fVar1;
    *(uint *)(iVar4 + 0x2dc) = *(uint *)(iVar4 + 0x2dc) | 0x40000000;
    *(char *)(iVar4 + 0x33c) =
         (char)*(undefined4 *)(puVar6 + (uint)*(byte *)(iVar4 + 0x33f) * 0x10 + 0xc);
    *(byte *)(iVar3 + 0xe4) = *(byte *)(iVar4 + 0x33c) & 1;
    *(undefined *)(iVar4 + 0x33f) = puVar6[(uint)*(byte *)(iVar4 + 0x33f) * 0x10 + 10];
  }
  if ((*(uint *)(iVar4 + 0x2dc) & 0x40000000) != 0) {
    *(byte *)(iVar4 + 0x33d) = *(byte *)(iVar4 + 0x33d) & 0xcf;
    if ((*(short *)(iVar3 + 0x46) == 0x6a2) && (*(int *)(iVar3 + 200) != 0)) {
      FUN_8021fab4();
    }
    if (*(byte *)(iVar4 + 0x33f) == 0) {
      iVar5 = (uint)*(ushort *)(iVar4 + 0x2a0) * 0xc;
      if (puVar7[iVar5 + 8] == '\0') {
        if (0x4f < *(ushort *)(iVar4 + 0x2a4)) {
          *(undefined *)(iVar4 + 0x33a) = 0;
        }
        FUN_8014c11c((double)FLOAT_803e2bb8,iVar3,6,0x28,&DAT_803ac4a8);
        if (((*(uint *)(iVar4 + 0x2dc) &
             *(uint *)(puVar9 + (uint)*(byte *)(iVar4 + 0x33a) * 0xc + 4)) == 0) &&
           (puVar9[(uint)*(byte *)(iVar4 + 0x33a) * 0xc + 9] != '\0')) {
          *(undefined *)(iVar4 + 0x33a) = puVar9[(uint)*(byte *)(iVar4 + 0x33a) * 0xc + 9];
        }
        iVar5 = (uint)*(byte *)(iVar4 + 0x33a) * 0xc;
        FUN_8014d08c((double)*(float *)(puVar9 + iVar5),iVar3,iVar4,puVar9[iVar5 + 8],0,
                     puVar9[iVar5 + 10]);
        *(undefined *)(iVar4 + 0x33a) = puVar9[(uint)*(byte *)(iVar4 + 0x33a) * 0xc + 9];
      }
      else {
        FUN_8014d08c((double)*(float *)(puVar7 + iVar5),iVar3,iVar4,puVar7[iVar5 + 8],0,
                     puVar7[iVar5 + 10]);
      }
    }
    else {
      iVar5 = (uint)*(byte *)(iVar4 + 0x33f) * 0x10;
      FUN_8014d08c((double)*(float *)(puVar6 + iVar5),iVar3,iVar4,puVar6[iVar5 + 8],0,
                   *(uint *)(puVar6 + iVar5 + 4) & 0xff);
      *(char *)(iVar4 + 0x33c) =
           (char)*(undefined4 *)(puVar6 + (uint)*(byte *)(iVar4 + 0x33f) * 0x10 + 0xc);
      *(byte *)(iVar3 + 0xe4) = *(byte *)(iVar4 + 0x33c) & 1;
      *(undefined *)(iVar4 + 0x33f) = puVar6[(uint)*(byte *)(iVar4 + 0x33f) * 0x10 + 9];
    }
  }
  *(undefined *)(*(int *)(iVar3 + 0x54) + 0x6e) = 0;
  *(undefined *)(*(int *)(iVar3 + 0x54) + 0x6f) = 0;
  iVar5 = 1;
  uVar2 = (uint)(byte)puVar8[8];
  puVar6 = puVar8;
  do {
    if (uVar2 == 0) {
LAB_801595f0:
      if (((*(byte *)(iVar4 + 0x323) & 8) == 0) && ((*(byte *)(iVar4 + 0x33d) & 0x10) == 0)) {
        FUN_8014cf7c((double)*(float *)(*(int *)(iVar4 + 0x29c) + 0xc),
                     (double)*(float *)(*(int *)(iVar4 + 0x29c) + 0x14),iVar3,iVar4,0x1e,0);
      }
      FUN_80157cdc(iVar3,iVar4);
      FUN_80286124();
      return;
    }
    if (*(ushort *)(iVar3 + 0xa0) == (ushort)(byte)puVar6[0x14]) {
      *(char *)(*(int *)(iVar3 + 0x54) + 0x6e) = (char)*(undefined4 *)(puVar8 + iVar5 * 0xc + 4);
      *(undefined *)(*(int *)(iVar3 + 0x54) + 0x6f) = puVar8[iVar5 * 0xc + 9];
      if (*(char *)(*(int *)(iVar3 + 0x54) + 0x6e) == '\x1f') {
        *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x40;
      }
      else {
        *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) & 0xffffffbf;
      }
      goto LAB_801595f0;
    }
    iVar5 = iVar5 + 1;
    uVar2 = uVar2 - 1;
    puVar6 = puVar6 + 0xc;
  } while( true );
}

