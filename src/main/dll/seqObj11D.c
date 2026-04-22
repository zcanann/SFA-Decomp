#include "ghidra_import.h"
#include "main/dll/seqObj11D.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8001ff6c();
extern undefined4 FUN_800201ac();
extern int FUN_80021884();
extern undefined4 FUN_80026cf4();
extern undefined4 FUN_80026cfc();
extern undefined4 FUN_80026dc0();
extern int FUN_8002bac4();
extern undefined4 FUN_800303fc();
extern undefined4 FUN_8003042c();
extern int FUN_8014c594();
extern undefined4 FUN_8014d3f4();
extern undefined4 FUN_8014d504();
extern undefined4 FUN_8014d584();
extern char FUN_80150448();
extern undefined4 FUN_80150830();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern int FUN_80296878();

extern undefined4 DAT_8031e980;
extern undefined4 DAT_8031feb8;
extern undefined4 DAT_803ad088;
extern undefined4 DAT_803ad08c;
extern undefined4 DAT_803dc8f0;
extern f64 DOUBLE_803e3408;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e33d8;
extern f32 FLOAT_803e33e0;
extern f32 FLOAT_803e33e4;
extern f32 FLOAT_803e33ec;
extern f32 FLOAT_803e3438;
extern f32 FLOAT_803e343c;
extern f32 FLOAT_803e3440;
extern f32 FLOAT_803e3448;
extern f32 FLOAT_803e344c;
extern f32 FLOAT_803e3450;
extern f32 FLOAT_803e3454;
extern f32 FLOAT_803e3458;
extern f32 FLOAT_803e345c;
extern f32 FLOAT_803e3460;
extern f32 FLOAT_803e3464;
extern f32 FLOAT_803e3468;
extern void* PTR_DAT_8031fdbc;
extern void* PTR_DAT_8031fdc8;
extern void* PTR_DAT_8031fdd0;
extern void* PTR_DAT_8031fdd4;
extern void* PTR_DAT_8031fdd8;

/*
 * --INFO--
 *
 * Function: FUN_80151370
 * EN v1.0 Address: 0x80151370
 * EN v1.0 Size: 780b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_8015167c
 * EN v1.0 Address: 0x8015167C
 * EN v1.0 Size: 452b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015167c(int param_1,int param_2)
{
  int iVar1;
  double dVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar3;
  double dVar4;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  dVar2 = DOUBLE_803e3408;
  puVar3 = (&PTR_DAT_8031fdc8)[(uint)*(byte *)(param_2 + 0x33b) * 10];
  dVar4 = (double)*(float *)(param_2 + 0x2ac);
  if ((float)((double)FLOAT_803e343c * dVar4) <
      (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x2a4)) - DOUBLE_803e3408)) {
    if ((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x2a4)) - DOUBLE_803e3408)
        <= (float)((double)FLOAT_803e3440 * dVar4)) {
      *(char *)(param_2 + 0x33a) = puVar3[8] + '\x03';
    }
    else {
      *(char *)(param_2 + 0x33a) = puVar3[8] + '\x02';
    }
  }
  while( true ) {
    if ((*(uint *)(puVar3 + (uint)*(byte *)(param_2 + 0x33a) * 0x10 + 4) == 0) ||
       ((*(uint *)(param_2 + 0x2dc) &
        *(uint *)(puVar3 + (uint)*(byte *)(param_2 + 0x33a) * 0x10 + 4)) != 0)) break;
    *(char *)(param_2 + 0x33a) = *(char *)(param_2 + 0x33a) + '\x01';
    if ((byte)puVar3[8] < *(byte *)(param_2 + 0x33a)) {
      *(undefined *)(param_2 + 0x33a) = 1;
    }
  }
  *(undefined *)(param_2 + 0x2f2) = puVar3[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 10];
  *(undefined *)(param_2 + 0x2f3) = puVar3[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 0xb];
  *(undefined *)(param_2 + 0x2f4) = puVar3[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 0xc];
  iVar1 = (uint)*(byte *)(param_2 + 0x33a) * 0x10;
  FUN_8014d504((double)*(float *)(puVar3 + iVar1),dVar2,dVar4,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,
               param_2,(uint)(byte)puVar3[iVar1 + 8],0,3,in_r8,in_r9,in_r10);
  FUN_800303fc((double)*(float *)(&DAT_8031e980 +
                                 (uint)(byte)puVar3[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 8] * 4
                                 ),param_1);
  *(char *)(param_2 + 0x33a) = *(char *)(param_2 + 0x33a) + '\x01';
  if ((byte)puVar3[8] < *(byte *)(param_2 + 0x33a)) {
    *(undefined *)(param_2 + 0x33a) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80151840
 * EN v1.0 Address: 0x80151840
 * EN v1.0 Size: 688b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80151840(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)
{
  short sVar1;
  int iVar2;
  uint uVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar4;
  double dVar5;
  
  puVar4 = (&PTR_DAT_8031fdc8)[(uint)*(byte *)(param_10 + 0x33b) * 10];
  iVar2 = FUN_8014c594(param_9,1,0x10,&DAT_803ad088);
  if (0 < iVar2) {
    if (((DAT_803ad08c < 0x29) && (*(short *)(param_10 + 0x2a0) != 3)) &&
       (*(short *)(param_10 + 0x2a0) != 4)) {
      iVar2 = FUN_80021884();
      sVar1 = (short)iVar2 - *param_9;
      uVar3 = (uint)sVar1;
      if (0x8000 < (int)uVar3) {
        uVar3 = (uint)(short)(sVar1 + 1);
      }
      if ((short)uVar3 < -0x8000) {
        uVar3 = (uint)(short)((short)uVar3 + -1);
      }
      *(undefined *)(param_10 + 0x33a) =
           puVar4[8] + (&DAT_803dc8f0)[(short)((uVar3 & 0xffff) >> 0xd)];
    }
    else if (DAT_803ad08c < 0x47) {
      while ((puVar4[(uint)*(byte *)(param_10 + 0x33a) * 0x10 + 10] & 1) != 0) {
        *(char *)(param_10 + 0x33a) = *(char *)(param_10 + 0x33a) + '\x01';
        if ((byte)puVar4[8] < *(byte *)(param_10 + 0x33a)) {
          *(undefined *)(param_10 + 0x33a) = 1;
        }
      }
    }
  }
  dVar5 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x2a4)) -
                         DOUBLE_803e3408);
  if (dVar5 < (double)(FLOAT_803e3440 * *(float *)(param_10 + 0x2ac))) {
    *(char *)(param_10 + 0x33a) = puVar4[8] + '\x01';
  }
  while( true ) {
    if ((*(uint *)(puVar4 + (uint)*(byte *)(param_10 + 0x33a) * 0x10 + 4) == 0) ||
       ((*(uint *)(param_10 + 0x2dc) &
        *(uint *)(puVar4 + (uint)*(byte *)(param_10 + 0x33a) * 0x10 + 4)) != 0)) break;
    *(char *)(param_10 + 0x33a) = *(char *)(param_10 + 0x33a) + '\x01';
    if ((byte)puVar4[8] < *(byte *)(param_10 + 0x33a)) {
      *(undefined *)(param_10 + 0x33a) = 1;
    }
  }
  *(undefined *)(param_10 + 0x2f2) = puVar4[(uint)*(byte *)(param_10 + 0x33a) * 0x10 + 10];
  *(undefined *)(param_10 + 0x2f3) = puVar4[(uint)*(byte *)(param_10 + 0x33a) * 0x10 + 0xb];
  *(undefined *)(param_10 + 0x2f4) = puVar4[(uint)*(byte *)(param_10 + 0x33a) * 0x10 + 0xc];
  iVar2 = (uint)*(byte *)(param_10 + 0x33a) * 0x10;
  FUN_8014d504((double)*(float *)(puVar4 + iVar2),dVar5,param_3,param_4,param_5,param_6,param_7,
               param_8,(int)param_9,param_10,(uint)(byte)puVar4[iVar2 + 8],0,3,in_r8,in_r9,in_r10);
  FUN_800303fc((double)*(float *)(&DAT_8031e980 +
                                 (uint)(byte)puVar4[(uint)*(byte *)(param_10 + 0x33a) * 0x10 + 8] *
                                 4),(int)param_9);
  *(char *)(param_10 + 0x33a) = *(char *)(param_10 + 0x33a) + '\x01';
  if ((byte)puVar4[8] < *(byte *)(param_10 + 0x33a)) {
    *(undefined *)(param_10 + 0x33a) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80151af0
 * EN v1.0 Address: 0x80151AF0
 * EN v1.0 Size: 760b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_80151de8
 * EN v1.0 Address: 0x80151DE8
 * EN v1.0 Size: 788b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80151de8(int param_1,int param_2)
{
}
