// Function: FUN_80151370
// Entry: 80151370
// Size: 780 bytes

void FUN_80151370(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  int iVar2;
  short *psVar3;
  char cVar4;
  int iVar5;
  uint uVar6;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  double dVar10;
  double dVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_8028683c();
  psVar3 = (short *)((ulonglong)uVar12 >> 0x20);
  iVar5 = (int)uVar12;
  uVar6 = (uint)*(byte *)(iVar5 + 0x33b);
  puVar9 = (&PTR_DAT_8031fdbc)[uVar6 * 10];
  puVar8 = (&PTR_DAT_8031fdd4)[uVar6 * 10];
  puVar7 = (&PTR_DAT_8031fdd8)[uVar6 * 10];
  if ((uVar6 == 5) && ((*(uint *)(iVar5 + 0x2dc) & 0x800000) != 0)) {
    FUN_800201ac(0x1c8,1);
  }
  if ((*(int *)(iVar5 + 0x29c) != 0) && (*(short *)(*(int *)(iVar5 + 0x29c) + 0x44) == 1)) {
    FUN_8001ff6c();
  }
  FUN_80150830((uint)psVar3,iVar5);
  fVar1 = FLOAT_803e33d8;
  dVar11 = (double)*(float *)(iVar5 + 0x328);
  dVar10 = (double)FLOAT_803e33d8;
  if ((dVar11 != dVar10) && (*(short *)(iVar5 + 0x338) != 0)) {
    *(float *)(iVar5 + 0x328) = (float)(dVar11 - (double)FLOAT_803dc074);
    if ((double)*(float *)(iVar5 + 0x328) <= dVar10) {
      *(float *)(iVar5 + 0x328) = fVar1;
      *(uint *)(iVar5 + 0x2dc) = *(uint *)(iVar5 + 0x2dc) | 0x40000000;
      *(ushort *)(iVar5 + 0x338) =
           (ushort)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 10];
    }
  }
  cVar4 = FUN_80150448(dVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,psVar3,iVar5,0,
                       in_r6,in_r7,in_r8,in_r9,in_r10);
  if (cVar4 == '\0') {
    if (((*(uint *)(iVar5 + 0x2dc) & 0x20000000) != 0) &&
       ((*(uint *)(iVar5 + 0x2e0) & 0x20000000) == 0)) {
      FUN_8000bb38((uint)psVar3,0x17);
      *(uint *)(iVar5 + 0x2dc) = *(uint *)(iVar5 + 0x2dc) | 0x40000000;
    }
    if ((*(uint *)(iVar5 + 0x2dc) & 0x40000000) != 0) {
      if (*(ushort *)(iVar5 + 0x338) == 0) {
        *(undefined *)(iVar5 + 0x2f2) = 0;
        *(undefined *)(iVar5 + 0x2f3) = 0;
        *(undefined *)(iVar5 + 0x2f4) = 0;
        iVar2 = (uint)*(ushort *)(iVar5 + 0x2a0) * 0xc;
        if ((byte)puVar8[iVar2 + 8] == 0) {
          *(undefined *)(iVar5 + 0x323) = 3;
          FUN_8003042c((double)FLOAT_803e33d8,dVar11,param_3,param_4,param_5,param_6,param_7,param_8
                       ,psVar3,(uint)(byte)puVar9[0x2c],0,in_r6,in_r7,in_r8,in_r9,in_r10);
        }
        else {
          FUN_8014d504((double)*(float *)(puVar8 + iVar2),dVar11,param_3,param_4,param_5,param_6,
                       param_7,param_8,(int)psVar3,iVar5,(uint)(byte)puVar8[iVar2 + 8],0,0xb,in_r8,
                       in_r9,in_r10);
          FUN_800303fc((double)*(float *)(&DAT_8031e980 +
                                         (uint)(byte)puVar8[(uint)*(ushort *)(iVar5 + 0x2a0) * 0xc +
                                                            8] * 4),(int)psVar3);
        }
      }
      else {
        *(char *)(iVar5 + 0x2f2) =
             (char)*(undefined4 *)(puVar7 + (uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 0xc);
        iVar2 = (uint)*(ushort *)(iVar5 + 0x338) * 0x10;
        FUN_8014d504((double)*(float *)(puVar7 + iVar2),dVar11,param_3,param_4,param_5,param_6,
                     param_7,param_8,(int)psVar3,iVar5,(uint)(byte)puVar7[iVar2 + 8],0,
                     *(uint *)(puVar7 + iVar2 + 4) & 0xff,in_r8,in_r9,in_r10);
        FUN_800303fc((double)*(float *)(&DAT_8031e980 +
                                       (uint)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 +
                                                          8] * 4),(int)psVar3);
        *(ushort *)(iVar5 + 0x338) =
             (ushort)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 9];
      }
    }
    if (psVar3[0x50] == (ushort)(byte)puVar9[0x2c]) {
      *(float *)(iVar5 + 0x308) =
           *(float *)(iVar5 + 0x2fc) *
           (((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar5 + 0x2a4)) - DOUBLE_803e3408
                    ) / *(float *)(iVar5 + 0x2a8)) / FLOAT_803e33e4) *
           *(float *)(&DAT_8031feb8 + (uint)*(byte *)(iVar5 + 0x33b) * 4);
      if (*(float *)(iVar5 + 0x308) < FLOAT_803e3438) {
        *(float *)(iVar5 + 0x308) = FLOAT_803e3438;
      }
    }
    if ((*(byte *)(iVar5 + 0x323) & 8) == 0) {
      FUN_8014d3f4(psVar3,iVar5,0xf,0);
    }
  }
  FUN_80286888();
  return;
}

