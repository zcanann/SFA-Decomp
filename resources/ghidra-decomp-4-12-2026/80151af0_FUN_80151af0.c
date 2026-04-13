// Function: FUN_80151af0
// Entry: 80151af0
// Size: 760 bytes

void FUN_80151af0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  short *psVar2;
  char cVar4;
  int iVar3;
  int iVar5;
  uint uVar6;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar7;
  undefined *puVar8;
  double dVar9;
  double dVar10;
  undefined8 uVar11;
  
  uVar11 = FUN_80286840();
  psVar2 = (short *)((ulonglong)uVar11 >> 0x20);
  iVar5 = (int)uVar11;
  uVar6 = (uint)*(byte *)(iVar5 + 0x33b);
  puVar8 = (&PTR_DAT_8031fdd0)[uVar6 * 10];
  puVar7 = (&PTR_DAT_8031fdd8)[uVar6 * 10];
  if ((uVar6 == 5) && ((*(uint *)(iVar5 + 0x2dc) & 0x800000) != 0)) {
    FUN_800201ac(0x1c8,1);
  }
  if ((*(int *)(iVar5 + 0x29c) != 0) && (*(short *)(*(int *)(iVar5 + 0x29c) + 0x44) == 1)) {
    FUN_8001ff6c();
  }
  FUN_80150830((uint)psVar2,iVar5);
  fVar1 = FLOAT_803e33d8;
  dVar10 = (double)*(float *)(iVar5 + 0x328);
  dVar9 = (double)FLOAT_803e33d8;
  if ((dVar10 != dVar9) && (*(short *)(iVar5 + 0x338) != 0)) {
    *(float *)(iVar5 + 0x328) = (float)(dVar10 - (double)FLOAT_803dc074);
    if ((double)*(float *)(iVar5 + 0x328) <= dVar9) {
      *(float *)(iVar5 + 0x328) = fVar1;
      *(uint *)(iVar5 + 0x2dc) = *(uint *)(iVar5 + 0x2dc) | 0x40000000;
      *(ushort *)(iVar5 + 0x338) =
           (ushort)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 10];
    }
  }
  cVar4 = FUN_80150448(dVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,psVar2,iVar5,1,
                       in_r6,in_r7,in_r8,in_r9,in_r10);
  if (cVar4 == '\0') {
    if ((*(uint *)(iVar5 + 0x2dc) & 0x40000000) != 0) {
      iVar3 = FUN_8002bac4();
      uVar11 = FUN_8014c594(psVar2,3,0x10,&DAT_803ad088);
      if (*(ushort *)(iVar5 + 0x338) == 0) {
        if ((iVar3 == 0) ||
           (((*(uint *)(iVar5 + 0x2dc) & 0x800080) == 0 && (iVar3 = FUN_80296878(iVar3), iVar3 != 0)
            ))) {
          FUN_80151840(uVar11,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,psVar2,iVar5);
        }
        else {
          FUN_8015167c((int)psVar2,iVar5);
        }
      }
      else {
        *(char *)(iVar5 + 0x2f2) =
             (char)*(undefined4 *)(puVar7 + (uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 0xc);
        iVar3 = (uint)*(ushort *)(iVar5 + 0x338) * 0x10;
        FUN_8014d504((double)*(float *)(puVar7 + iVar3),dVar10,param_3,param_4,param_5,param_6,
                     param_7,param_8,(int)psVar2,iVar5,(uint)(byte)puVar7[iVar3 + 8],0,
                     *(uint *)(puVar7 + iVar3 + 4) & 0xff,in_r8,in_r9,in_r10);
        FUN_800303fc((double)*(float *)(&DAT_8031e980 +
                                       (uint)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 +
                                                          8] * 4),(int)psVar2);
        *(ushort *)(iVar5 + 0x338) =
             (ushort)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 9];
      }
    }
    *(undefined *)(*(int *)(psVar2 + 0x2a) + 0x6e) = 0;
    *(undefined *)(*(int *)(psVar2 + 0x2a) + 0x6f) = 0;
    if (psVar2[0x50] == (ushort)(byte)puVar8[8]) {
      *(char *)(*(int *)(psVar2 + 0x2a) + 0x6e) = (char)*(undefined4 *)(puVar8 + 4);
      *(undefined *)(*(int *)(psVar2 + 0x2a) + 0x6f) = puVar8[9];
    }
    if (psVar2[0x50] == (ushort)(byte)puVar8[0x14]) {
      *(char *)(*(int *)(psVar2 + 0x2a) + 0x6e) = (char)*(undefined4 *)(puVar8 + 0x10);
      *(undefined *)(*(int *)(psVar2 + 0x2a) + 0x6f) = puVar8[0x15];
    }
    if (psVar2[0x50] == (ushort)(byte)puVar8[0x20]) {
      *(char *)(*(int *)(psVar2 + 0x2a) + 0x6e) = (char)*(undefined4 *)(puVar8 + 0x1c);
      *(undefined *)(*(int *)(psVar2 + 0x2a) + 0x6f) = puVar8[0x21];
    }
    if ((*(byte *)(iVar5 + 0x323) & 8) == 0) {
      FUN_8014d3f4(psVar2,iVar5,10,0);
    }
  }
  FUN_8028688c();
  return;
}

