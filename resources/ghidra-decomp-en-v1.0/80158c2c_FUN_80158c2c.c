// Function: FUN_80158c2c
// Entry: 80158c2c
// Size: 1624 bytes

void FUN_80158c2c(void)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  undefined *puVar10;
  undefined *puVar11;
  float *pfVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_802860d0();
  psVar4 = (short *)((ulonglong)uVar13 >> 0x20);
  iVar6 = (int)uVar13;
  uVar2 = (uint)*(byte *)(iVar6 + 0x33b);
  pfVar12 = (float *)(&PTR_DAT_8031faf8)[uVar2 * 8];
  puVar11 = (&PTR_DAT_8031faf0)[uVar2 * 8];
  puVar10 = (&PTR_DAT_8031faf4)[uVar2 * 8];
  puVar9 = (&PTR_DAT_8031fafc)[uVar2 * 8];
  puVar8 = (&PTR_DAT_8031faec)[uVar2 * 8];
  puVar7 = (&PTR_DAT_8031fb00)[uVar2 * 8];
  if ((*(int *)(iVar6 + 0x29c) != 0) && (*(short *)(*(int *)(iVar6 + 0x29c) + 0x44) == 1)) {
    FUN_8001fe90();
  }
  if ((*(uint *)(iVar6 + 0x2dc) & 0x80000000) != 0) {
    if (*(char *)(iVar6 + 0x33b) == '\0') {
      (**(code **)(*DAT_803dca50 + 0x24))(0,0x6c,0);
    }
    *(byte *)(iVar6 + 0x33d) = *(byte *)(iVar6 + 0x33d) | 0x10;
    *(undefined *)(iVar6 + 0x33a) = 0;
    if ((psVar4[0x23] == 0x6a2) && (FUN_8000bb18(psVar4,0x4a9), *(int *)(psVar4 + 100) != 0)) {
      FUN_8021fab4();
    }
  }
  fVar1 = FLOAT_803e2ba8;
  if (((*(float *)(iVar6 + 0x328) != FLOAT_803e2ba8) && (*(char *)(iVar6 + 0x33f) != '\0')) &&
     (*(float *)(iVar6 + 0x328) = *(float *)(iVar6 + 0x328) - FLOAT_803db414,
     *(float *)(iVar6 + 0x328) <= fVar1)) {
    *(float *)(iVar6 + 0x328) = fVar1;
    *(uint *)(iVar6 + 0x2dc) = *(uint *)(iVar6 + 0x2dc) | 0x40000000;
    *(char *)(iVar6 + 0x33c) =
         (char)*(undefined4 *)(puVar9 + (uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 0xc);
    *(byte *)(psVar4 + 0x72) = *(byte *)(iVar6 + 0x33c) & 1;
    *(undefined *)(iVar6 + 0x33f) = puVar9[(uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 10];
  }
  iVar5 = FUN_8014c11c((double)FLOAT_803e2be0,psVar4,1,0x28,&DAT_803ac4a8);
  if (iVar5 < 1) {
    if ((*(uint *)(iVar6 + 0x2dc) & 0x40000000) != 0) {
      *(byte *)(iVar6 + 0x33d) = *(byte *)(iVar6 + 0x33d) & 0xcf;
      if ((psVar4[0x23] == 0x6a2) && (*(int *)(psVar4 + 100) != 0)) {
        FUN_8021fab4();
      }
      if (*(byte *)(iVar6 + 0x33f) == 0) {
        iVar5 = (uint)*(byte *)(iVar6 + 0x33e) * 0xc;
        if ((*(uint *)(iVar6 + 0x2dc) & *(uint *)(puVar8 + iVar5 + 4)) == 0) {
          iVar5 = (uint)*(ushort *)(iVar6 + 0x2a0) * 0xc;
          if (puVar10[iVar5 + 8] == '\0') {
            uVar2 = FUN_800221a0(1,puVar11[8]);
            iVar5 = (uVar2 & 0xff) * 0xc;
            FUN_8014d08c((double)*(float *)(puVar11 + iVar5),psVar4,iVar6,puVar11[iVar5 + 8],0,
                         puVar11[iVar5 + 10]);
          }
          else {
            FUN_8014d08c((double)*(float *)(puVar10 + iVar5),psVar4,iVar6,puVar10[iVar5 + 8],0,
                         puVar10[iVar5 + 10]);
          }
        }
        else {
          iVar3 = (uint)*(ushort *)(iVar6 + 0x2a0) * 0xc;
          if (puVar10[iVar3 + 8] == '\0') {
            FUN_8014d08c((double)*(float *)(puVar8 + iVar5),psVar4,iVar6,puVar8[iVar5 + 8],0,
                         puVar8[iVar5 + 10]);
          }
          else {
            FUN_8014d08c((double)*(float *)(puVar10 + iVar3),psVar4,iVar6,puVar10[iVar3 + 8],0,
                         puVar10[iVar3 + 10]);
          }
        }
        *(undefined *)(iVar6 + 0x33e) = puVar8[(uint)*(byte *)(iVar6 + 0x33e) * 0xc + 9];
      }
      else {
        iVar5 = (uint)*(byte *)(iVar6 + 0x33f) * 0x10;
        FUN_8014d08c((double)*(float *)(puVar9 + iVar5),psVar4,iVar6,puVar9[iVar5 + 8],0,
                     *(uint *)(puVar9 + iVar5 + 4) & 0xff);
        *(char *)(iVar6 + 0x33c) =
             (char)*(undefined4 *)(puVar9 + (uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 0xc);
        *(byte *)(psVar4 + 0x72) = *(byte *)(iVar6 + 0x33c) & 1;
        *(undefined *)(iVar6 + 0x33f) = puVar9[(uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 9];
      }
    }
  }
  else if (((*(byte *)(iVar6 + 0x33d) & 0x20) == 0) ||
          ((*(uint *)(iVar6 + 0x2dc) & 0x40000000) != 0)) {
    if (*(byte *)(iVar6 + 0x33f) == 0) {
      uVar2 = FUN_800217c0(-(double)(*(float *)(psVar4 + 0xc) - *(float *)(DAT_803ac4a8 + 0x18)),
                           -(double)(*(float *)(psVar4 + 0x10) - *(float *)(DAT_803ac4a8 + 0x20)));
      uVar2 = (uVar2 & 0xffff) - ((int)*psVar4 & 0xffffU);
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      uVar2 = (uVar2 & 0xffff) >> 0xd;
      if ((uVar2 == 0) || (6 < uVar2)) {
        FUN_8014d08c((double)*pfVar12,psVar4,iVar6,*(undefined *)(pfVar12 + 2),0,
                     *(undefined *)((int)pfVar12 + 10));
      }
      else if ((uVar2 < 3) || (4 < uVar2)) {
        iVar5 = (uint)*(ushort *)(iVar6 + 0x2a0) * 0xc;
        if (puVar10[iVar5 + 8] == '\0') {
          iVar5 = (uint)*(byte *)(iVar6 + 0x33e) * 0xc;
          FUN_8014d08c((double)*(float *)(puVar8 + iVar5),psVar4,iVar6,puVar8[iVar5 + 8],0,
                       puVar8[iVar5 + 10]);
          *(undefined *)(iVar6 + 0x33e) = puVar8[(uint)*(byte *)(iVar6 + 0x33e) * 0xc + 9];
        }
        else {
          FUN_8014d08c((double)*(float *)(puVar10 + iVar5),psVar4,iVar6,puVar10[iVar5 + 8],0,
                       puVar10[iVar5 + 10]);
        }
      }
      else {
        uVar2 = FUN_800221a0(1,puVar11[8]);
        iVar5 = (uVar2 & 0xff) * 0xc;
        FUN_8014d08c((double)*(float *)(puVar11 + iVar5),psVar4,iVar6,puVar11[iVar5 + 8],0,
                     puVar11[iVar5 + 10]);
      }
      *(byte *)(iVar6 + 0x33d) = *(byte *)(iVar6 + 0x33d) | 0x20;
      *(byte *)(iVar6 + 0x33d) = *(byte *)(iVar6 + 0x33d) & 0xef;
    }
    else {
      iVar5 = (uint)*(byte *)(iVar6 + 0x33f) * 0x10;
      FUN_8014d08c((double)*(float *)(puVar9 + iVar5),psVar4,iVar6,puVar9[iVar5 + 8],0,
                   *(uint *)(puVar9 + iVar5 + 4) & 0xff);
      *(char *)(iVar6 + 0x33c) =
           (char)*(undefined4 *)(puVar9 + (uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 0xc);
      *(byte *)(psVar4 + 0x72) = *(byte *)(iVar6 + 0x33c) & 1;
      *(undefined *)(iVar6 + 0x33f) = puVar9[(uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 9];
    }
  }
  *(undefined *)(*(int *)(psVar4 + 0x2a) + 0x6e) = 0;
  *(undefined *)(*(int *)(psVar4 + 0x2a) + 0x6f) = 0;
  iVar5 = 1;
  uVar2 = (uint)(byte)puVar7[8];
  puVar8 = puVar7;
  do {
    if (uVar2 == 0) {
LAB_80159220:
      if (((*(byte *)(iVar6 + 0x323) & 8) == 0) && ((*(byte *)(iVar6 + 0x33d) & 0x10) == 0)) {
        FUN_8014cf7c((double)*(float *)(*(int *)(iVar6 + 0x29c) + 0xc),
                     (double)*(float *)(*(int *)(iVar6 + 0x29c) + 0x14),psVar4,iVar6,0x1e,0);
      }
      FUN_80157cdc(psVar4,iVar6);
      FUN_8028611c();
      return;
    }
    if (psVar4[0x50] == (ushort)(byte)puVar8[0x14]) {
      *(char *)(*(int *)(psVar4 + 0x2a) + 0x6e) = (char)*(undefined4 *)(puVar7 + iVar5 * 0xc + 4);
      *(undefined *)(*(int *)(psVar4 + 0x2a) + 0x6f) = puVar7[iVar5 * 0xc + 9];
      if (*(char *)(*(int *)(psVar4 + 0x2a) + 0x6e) == '\x1f') {
        *(uint *)(iVar6 + 0x2e8) = *(uint *)(iVar6 + 0x2e8) | 0x40;
      }
      else {
        *(uint *)(iVar6 + 0x2e8) = *(uint *)(iVar6 + 0x2e8) & 0xffffffbf;
      }
      goto LAB_80159220;
    }
    iVar5 = iVar5 + 1;
    uVar2 = uVar2 - 1;
    puVar8 = puVar8 + 0xc;
  } while( true );
}

