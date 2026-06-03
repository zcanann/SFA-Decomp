#include "ghidra_import.h"
#include "main/dll/seqObj11D.h"

#define SFXdn_boar5_c 23
#define SFXen_cavedirt22 35

extern undefined4 FUN_80006824();
extern undefined4 FUN_8001766c();
extern undefined4 GameBit_Set(int eventId, int value);
extern int FUN_80017730();
extern undefined4 FUN_800178a0();
extern undefined4 FUN_800178a4();
extern undefined4 FUN_800178b4();
extern int FUN_80017a98();
extern undefined4 FUN_800305c4();
extern undefined4 FUN_800305f8();
extern int FUN_8014c78c();
extern undefined4 FUN_8014d3d0();
extern undefined4 FUN_8014d4c8();
extern undefined4 FUN_8014d59c();
extern char FUN_8014ffa8();
extern undefined4 FUN_801504f8();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern int FUN_80294c54();

extern undefined4 DAT_8031e980;
extern undefined4 DAT_8031feb8;
extern undefined4 DAT_803ad088;
extern undefined4 DAT_803ad08c;
extern undefined4 DAT_803dc8f0;
extern f64 DOUBLE_803e3408;
extern f32 lbl_803DC074;
extern f32 lbl_803E33D8;
extern f32 lbl_803E33E0;
extern f32 lbl_803E33E4;
extern f32 lbl_803E33EC;
extern f32 lbl_803E3438;
extern f32 lbl_803E343C;
extern f32 lbl_803E3440;
extern f32 lbl_803E3448;
extern f32 lbl_803E344C;
extern f32 lbl_803E3450;
extern f32 lbl_803E3454;
extern f32 lbl_803E3458;
extern f32 lbl_803E345C;
extern f32 lbl_803E3460;
extern f32 lbl_803E3464;
extern f32 lbl_803E3468;
extern void* PTR_DAT_8031fdbc;
extern void* PTR_DAT_8031fdc8;
extern void* PTR_DAT_8031fdd0;
extern void* PTR_DAT_8031fdd4;
extern void* PTR_DAT_8031fdd8;

/*
 * --INFO--
 *
 * Function: FUN_801511e8
 * EN v1.0 Address: 0x801511E8
 * EN v1.0 Size: 1112b
 * EN v1.1 Address: 0x80151370
 * EN v1.1 Size: 780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801511e8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
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
    GameBit_Set(0x1c8,1);
  }
  if ((*(int *)(iVar5 + 0x29c) != 0) && (*(short *)(*(int *)(iVar5 + 0x29c) + 0x44) == 1)) {
    FUN_8001766c();
  }
  FUN_801504f8((uint)psVar3,iVar5);
  fVar1 = lbl_803E33D8;
  dVar11 = (double)*(float *)(iVar5 + 0x328);
  dVar10 = (double)lbl_803E33D8;
  if ((dVar11 != dVar10) && (*(short *)(iVar5 + 0x338) != 0)) {
    *(float *)(iVar5 + 0x328) = (float)(dVar11 - (double)lbl_803DC074);
    if ((double)*(float *)(iVar5 + 0x328) <= dVar10) {
      *(float *)(iVar5 + 0x328) = fVar1;
      *(uint *)(iVar5 + 0x2dc) = *(uint *)(iVar5 + 0x2dc) | 0x40000000;
      *(ushort *)(iVar5 + 0x338) =
           (ushort)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 10];
    }
  }
  cVar4 = FUN_8014ffa8(dVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,psVar3,iVar5,0,
                       in_r6,in_r7,in_r8,in_r9,in_r10);
  if (cVar4 == '\0') {
    if (((*(uint *)(iVar5 + 0x2dc) & 0x20000000) != 0) &&
       ((*(uint *)(iVar5 + 0x2e0) & 0x20000000) == 0)) {
      FUN_80006824((uint)psVar3,SFXdn_boar5_c);
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
          FUN_800305f8((double)lbl_803E33D8,dVar11,param_3,param_4,param_5,param_6,param_7,param_8
                       ,psVar3,(uint)(byte)puVar9[0x2c],0,in_r6,in_r7,in_r8,in_r9,in_r10);
        }
        else {
          FUN_8014d4c8((double)*(float *)(puVar8 + iVar2),dVar11,param_3,param_4,param_5,param_6,
                       param_7,param_8,(int)psVar3,iVar5,(uint)(byte)puVar8[iVar2 + 8],0,0xb,in_r8,
                       in_r9,in_r10);
          FUN_800305c4((double)*(float *)(&DAT_8031e980 +
                                         (uint)(byte)puVar8[(uint)*(ushort *)(iVar5 + 0x2a0) * 0xc +
                                                            8] * 4),(int)psVar3);
        }
      }
      else {
        *(char *)(iVar5 + 0x2f2) =
             (char)*(undefined4 *)(puVar7 + (uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 0xc);
        iVar2 = (uint)*(ushort *)(iVar5 + 0x338) * 0x10;
        FUN_8014d4c8((double)*(float *)(puVar7 + iVar2),dVar11,param_3,param_4,param_5,param_6,
                     param_7,param_8,(int)psVar3,iVar5,(uint)(byte)puVar7[iVar2 + 8],0,
                     *(uint *)(puVar7 + iVar2 + 4) & 0xff,in_r8,in_r9,in_r10);
        FUN_800305c4((double)*(float *)(&DAT_8031e980 +
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
                    ) / *(float *)(iVar5 + 0x2a8)) / lbl_803E33E4) *
           *(float *)(&DAT_8031feb8 + (uint)*(byte *)(iVar5 + 0x33b) * 4);
      if (*(float *)(iVar5 + 0x308) < lbl_803E3438) {
        *(float *)(iVar5 + 0x308) = lbl_803E3438;
      }
    }
    if ((*(byte *)(iVar5 + 0x323) & 8) == 0) {
      FUN_8014d3d0(psVar3,iVar5,0xf,0);
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80151640
 * EN v1.0 Address: 0x80151640
 * EN v1.0 Size: 516b
 * EN v1.1 Address: 0x8015167C
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80151640(int param_1,int param_2)
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
  if ((float)((double)lbl_803E343C * dVar4) <
      (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x2a4)) - DOUBLE_803e3408)) {
    if ((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x2a4)) - DOUBLE_803e3408)
        <= (float)((double)lbl_803E3440 * dVar4)) {
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
  FUN_8014d4c8((double)*(float *)(puVar3 + iVar1),dVar2,dVar4,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,
               param_2,(uint)(byte)puVar3[iVar1 + 8],0,3,in_r8,in_r9,in_r10);
  FUN_800305c4((double)*(float *)(&DAT_8031e980 +
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
 * Function: FUN_80151844
 * EN v1.0 Address: 0x80151844
 * EN v1.0 Size: 728b
 * EN v1.1 Address: 0x80151840
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80151844(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
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
  iVar2 = FUN_8014c78c(param_9,1,0x10,&DAT_803ad088);
  if (0 < iVar2) {
    if (((DAT_803ad08c < 0x29) && (*(short *)(param_10 + 0x2a0) != 3)) &&
       (*(short *)(param_10 + 0x2a0) != 4)) {
      iVar2 = FUN_80017730();
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
  if (dVar5 < (double)(lbl_803E3440 * *(float *)(param_10 + 0x2ac))) {
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
  FUN_8014d4c8((double)*(float *)(puVar4 + iVar2),dVar5,param_3,param_4,param_5,param_6,param_7,
               param_8,(int)param_9,param_10,(uint)(byte)puVar4[iVar2 + 8],0,3,in_r8,in_r9,in_r10);
  FUN_800305c4((double)*(float *)(&DAT_8031e980 +
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
 * Function: FUN_80151b1c
 * EN v1.0 Address: 0x80151B1C
 * EN v1.0 Size: 1408b
 * EN v1.1 Address: 0x80151AF0
 * EN v1.1 Size: 760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80151b1c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
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
    GameBit_Set(0x1c8,1);
  }
  if ((*(int *)(iVar5 + 0x29c) != 0) && (*(short *)(*(int *)(iVar5 + 0x29c) + 0x44) == 1)) {
    FUN_8001766c();
  }
  FUN_801504f8((uint)psVar2,iVar5);
  fVar1 = lbl_803E33D8;
  dVar10 = (double)*(float *)(iVar5 + 0x328);
  dVar9 = (double)lbl_803E33D8;
  if ((dVar10 != dVar9) && (*(short *)(iVar5 + 0x338) != 0)) {
    *(float *)(iVar5 + 0x328) = (float)(dVar10 - (double)lbl_803DC074);
    if ((double)*(float *)(iVar5 + 0x328) <= dVar9) {
      *(float *)(iVar5 + 0x328) = fVar1;
      *(uint *)(iVar5 + 0x2dc) = *(uint *)(iVar5 + 0x2dc) | 0x40000000;
      *(ushort *)(iVar5 + 0x338) =
           (ushort)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 10];
    }
  }
  cVar4 = FUN_8014ffa8(dVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,psVar2,iVar5,1,
                       in_r6,in_r7,in_r8,in_r9,in_r10);
  if (cVar4 == '\0') {
    if ((*(uint *)(iVar5 + 0x2dc) & 0x40000000) != 0) {
      iVar3 = FUN_80017a98();
      uVar11 = FUN_8014c78c(psVar2,3,0x10,&DAT_803ad088);
      if (*(ushort *)(iVar5 + 0x338) == 0) {
        if ((iVar3 == 0) ||
           (((*(uint *)(iVar5 + 0x2dc) & 0x800080) == 0 && (iVar3 = FUN_80294c54(iVar3), iVar3 != 0)
            ))) {
          FUN_80151844(uVar11,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,psVar2,iVar5);
        }
        else {
          FUN_80151640((int)psVar2,iVar5);
        }
      }
      else {
        *(char *)(iVar5 + 0x2f2) =
             (char)*(undefined4 *)(puVar7 + (uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 0xc);
        iVar3 = (uint)*(ushort *)(iVar5 + 0x338) * 0x10;
        FUN_8014d4c8((double)*(float *)(puVar7 + iVar3),dVar10,param_3,param_4,param_5,param_6,
                     param_7,param_8,(int)psVar2,iVar5,(uint)(byte)puVar7[iVar3 + 8],0,
                     *(uint *)(puVar7 + iVar3 + 4) & 0xff,in_r8,in_r9,in_r10);
        FUN_800305c4((double)*(float *)(&DAT_8031e980 +
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
      FUN_8014d3d0(psVar2,iVar5,10,0);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015209c
 * EN v1.0 Address: 0x8015209C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80151DE8
 * EN v1.1 Size: 788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015209c(int param_1,int param_2)
{
}

extern void Sfx_PlayFromObject(int obj, int sfx);
void fn_80152004(int obj, int *state) {
    Sfx_PlayFromObject(obj, SFXen_cavedirt22);
    *(u32*)((char*)state + 0x2e8) |= 0x10;
}

extern void fn_8014D08C(int obj, u8 *state, int a, int b, int c, f32 f);
extern f32 ObjAnim_SetMoveProgress(int obj, f32 f);
extern char lbl_8031F16C[];
extern char lbl_8031DD30[];
extern f32 lbl_803E27A4;
extern f32 lbl_803E27A8;

typedef struct {
    f32 speed;
    u32 mask;
    u8 anim;
    u8 pad9;
    u8 r;
    u8 g;
    u8 b;
    u8 pad13[3];
} SeqEntry;

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void fn_801511E8(int obj, u8 *state)
{
    u8 *entry;
    u32 idx;

    entry = *(u8 **)(state[0x33b] * 40 + lbl_8031F16C + 12);
    if ((f32)*(u16 *)(state + 0x2a4) > lbl_803E27A4 * *(f32 *)(state + 0x2ac)) {
        if ((f32)*(u16 *)(state + 0x2a4) > lbl_803E27A8 * *(f32 *)(state + 0x2ac)) {
            state[0x33a] = (u8)(entry[8] + 2);
        } else {
            state[0x33a] = (u8)(entry[8] + 3);
        }
    }
    while (*(u32 *)(entry + (idx = state[0x33a]) * 16 + 4) != 0
           && (*(u32 *)(state + 0x2dc) & *(u32 *)(entry + idx * 16 + 4)) == 0) {
        (*(u8 *)(state + 0x33a))++;
        if (state[0x33a] > entry[8]) {
            state[0x33a] = 1;
        }
    }
    *(u8 *)(state + 0x2f2) = ((SeqEntry *)(entry + state[0x33a] * 16))->r;
    *(u8 *)(state + 0x2f3) = ((SeqEntry *)(entry + state[0x33a] * 16))->g;
    *(u8 *)(state + 0x2f4) = ((SeqEntry *)(entry + state[0x33a] * 16))->b;
    fn_8014D08C(obj, state, ((SeqEntry *)(entry + state[0x33a] * 16))->anim, 0, 3, *(f32 *)(entry + state[0x33a] * 16));
    ObjAnim_SetMoveProgress(obj, *(f32 *)(lbl_8031DD30 + ((SeqEntry *)(entry + state[0x33a] * 16))->anim * 4));
    (*(u8 *)(state + 0x33a))++;
    if (state[0x33a] > entry[8]) {
        state[0x33a] = 1;
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

extern int fn_8014C11C(int obj, int a, int b, u8 *tbl, f32 f);
extern int getAngle(f32 dx, f32 dz);
extern u8 lbl_803AC428[];
extern u8 lbl_803DBC88[8];
extern f32 lbl_803E27AC;

#pragma scheduling off
#pragma peephole off
void fn_801513AC(int obj, u8 *state)
{
    u8 *entry;
    u32 idx;
    s16 d;

    entry = *(u8 **)(state[0x33b] * 40 + lbl_8031F16C + 12);
    if (fn_8014C11C(obj, 1, 16, lbl_803AC428, lbl_803E27AC) >= 1) {
        if (*(u16 *)(lbl_803AC428 + 4) <= 40
            && *(u16 *)(state + 0x2a0) != 3
            && *(u16 *)(state + 0x2a0) != 4) {
            d = getAngle(*(f32 *)(obj + 0xc) - *(f32 *)(*(int *)lbl_803AC428 + 0xc),
                         *(f32 *)(obj + 0x14) - *(f32 *)(*(int *)lbl_803AC428 + 0x14))
                - (u16)*(s16 *)obj;
            if (d > 0x8000) {
                d -= 0xFFFF;
            }
            if (d < -0x8000) {
                d += 0xFFFF;
            }
            state[0x33a] = (u8)(entry[8] + lbl_803DBC88[(s16)((u32)(u16)d >> 13)]);
        } else if (*(u16 *)(lbl_803AC428 + 4) <= 70) {
            while ((*(u8 *)(entry + state[0x33a] * 16 + 10) & 1) != 0) {
                (*(u8 *)(state + 0x33a))++;
                if (state[0x33a] > entry[8]) {
                    state[0x33a] = 1;
                }
            }
        }
    }
    if ((f32)*(u16 *)(state + 0x2a4) < lbl_803E27A8 * *(f32 *)(state + 0x2ac)) {
        state[0x33a] = (u8)(entry[8] + 1);
    }
    while (*(u32 *)(entry + (idx = state[0x33a]) * 16 + 4) != 0
           && (*(u32 *)(state + 0x2dc) & *(u32 *)(entry + idx * 16 + 4)) == 0) {
        (*(u8 *)(state + 0x33a))++;
        if (state[0x33a] > entry[8]) {
            state[0x33a] = 1;
        }
    }
    *(u8 *)(state + 0x2f2) = ((SeqEntry *)(entry + state[0x33a] * 16))->r;
    *(u8 *)(state + 0x2f3) = ((SeqEntry *)(entry + state[0x33a] * 16))->g;
    *(u8 *)(state + 0x2f4) = ((SeqEntry *)(entry + state[0x33a] * 16))->b;
    fn_8014D08C(obj, state, ((SeqEntry *)(entry + state[0x33a] * 16))->anim, 0, 3, *(f32 *)(entry + state[0x33a] * 16));
    ObjAnim_SetMoveProgress(obj, *(f32 *)(lbl_8031DD30 + ((SeqEntry *)(entry + state[0x33a] * 16))->anim * 4));
    (*(u8 *)(state + 0x33a))++;
    if (state[0x33a] > entry[8]) {
        state[0x33a] = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_8001FEA8(void);
extern u8 *Obj_GetPlayerObject(void);
extern void fn_8015039C(int obj, u8 *state);
extern u8 fn_8014FFB4(int obj, u8 *state, int a);
extern uint fn_80296118(u8 *player);
extern void fn_8014CF7C(int obj, u8 *state, f32 x, f32 z, int a, int b);
extern void fn_801513AC(int obj, u8 *state);
extern void fn_801511E8(int obj, u8 *state);
extern f32 lbl_803E2740;
extern f32 timeDelta;

#pragma scheduling off
#pragma peephole off
void fn_8015165C(int obj, u8 *state)
{
    u8 *player;
    u8 *p28;
    u8 *p20;
    u8 t;
    f32 tv;
    f32 fz;

    t = state[0x33b];
    p20 = *(u8 **)(lbl_8031F16C + t * 40 + 20);
    p28 = *(u8 **)(lbl_8031F16C + t * 40 + 28);
    if (t == 5 && (*(u32 *)(state + 0x2dc) & 0x800000) != 0) {
        GameBit_Set(456, 1);
    }
    if (*(void **)(state + 0x29c) != NULL && *(s16 *)(*(int *)(state + 0x29c) + 0x44) == 1) {
        fn_8001FEA8();
    }
    fn_8015039C(obj, state);
    tv = *(f32 *)(state + 0x328);
    fz = lbl_803E2740;
    if (tv != fz && *(u16 *)(state + 0x338) != 0) {
        *(f32 *)(state + 0x328) = tv - timeDelta;
        if (*(f32 *)(state + 0x328) <= fz) {
            *(f32 *)(state + 0x328) = fz;
            *(u32 *)(state + 0x2dc) |= 0x40000000;
            *(u16 *)(state + 0x338) = *(u8 *)(p28 + *(u16 *)(state + 0x338) * 16 + 10);
        }
    }
    if ((u8)fn_8014FFB4(obj, state, 1) == 0) {
        if ((*(u32 *)(state + 0x2dc) & 0x40000000) != 0) {
            player = Obj_GetPlayerObject();
            fn_8014C11C(obj, 3, 16, lbl_803AC428, lbl_803E27AC);
            if (*(u16 *)(state + 0x338) != 0) {
                *(u8 *)(state + 0x2f2) = (u8)*(u32 *)(p28 + *(u16 *)(state + 0x338) * 16 + 12);
                fn_8014D08C(obj, state, *(u8 *)(p28 + *(u16 *)(state + 0x338) * 16 + 8), 0,
                            (u8)*(u32 *)(p28 + *(u16 *)(state + 0x338) * 16 + 4),
                            *(f32 *)(p28 + *(u16 *)(state + 0x338) * 16));
                ObjAnim_SetMoveProgress(obj, *(f32 *)(lbl_8031DD30 + *(u8 *)(p28 + *(u16 *)(state + 0x338) * 16 + 8) * 4));
                *(u16 *)(state + 0x338) = *(u8 *)(p28 + *(u16 *)(state + 0x338) * 16 + 9);
            } else {
                if (player != NULL && ((*(u32 *)(state + 0x2dc) & 0x800080) != 0 || fn_80296118(player) == 0)) {
                    fn_801511E8(obj, state);
                } else {
                    fn_801513AC(obj, state);
                }
            }
        }
        *(u8 *)(*(int *)(obj + 0x54) + 0x6e) = 0;
        *(u8 *)(*(int *)(obj + 0x54) + 0x6f) = 0;
        if (*(s16 *)(obj + 0xa0) == p20[8]) {
            *(s8 *)(*(int *)(obj + 0x54) + 0x6e) = (s8)*(int *)(p20 + 4);
            *(s8 *)(*(int *)(obj + 0x54) + 0x6f) = (s8)p20[9];
        }
        if (*(s16 *)(obj + 0xa0) == p20[0x14]) {
            *(s8 *)(*(int *)(obj + 0x54) + 0x6e) = (s8)*(int *)(p20 + 0x10);
            *(s8 *)(*(int *)(obj + 0x54) + 0x6f) = (s8)p20[0x15];
        }
        if (*(s16 *)(obj + 0xa0) == p20[0x20]) {
            *(s8 *)(*(int *)(obj + 0x54) + 0x6e) = (s8)*(int *)(p20 + 0x1c);
            *(s8 *)(*(int *)(obj + 0x54) + 0x6f) = (s8)p20[0x21];
        }
        if ((state[0x323] & 8) == 0) {
            fn_8014CF7C(obj, state, *(f32 *)(*(int *)(state + 0x29c) + 0xc),
                        *(f32 *)(*(int *)(state + 0x29c) + 0x14), 10, 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int allocModelStruct2(f32 *p, int n);
extern void tailFn_80026c38(int p, f32 a, f32 b, f32 c);
extern void fn_80026C30(int p, int n);
extern void baddieAfterUpdateBonesCb();
extern f32 lbl_803DBC98;
extern f32 lbl_803E2748;
extern f32 lbl_803E2754;
extern f32 lbl_803E27B0;
extern f32 lbl_803E27B4;
extern f32 lbl_803E27B8;
extern f32 lbl_803E27BC;
extern f32 lbl_803E27C0;
extern f32 lbl_803E27C4;
extern f32 lbl_803E27C8;
extern f32 lbl_803E27CC;
extern f32 lbl_803E27D0;

#pragma scheduling off
#pragma peephole off
void fn_80151954(int obj, u8 *state)
{
    u8 *setup = *(u8 **)(obj + 0x4c);
    f32 fz;
    int z;

    *(int *)(state + 0x2e4) = 11;
    *(u32 *)(state + 0x2e4) |= 0x402B0;
    *(u32 *)(state + 0x2e4) |= 0x3040;
    *(u32 *)(state + 0x2e4) |= 0x40300000;
    *(u32 *)(state + 0x2e4) |= 0xC00;
    *(f32 *)(state + 0x308) = lbl_803E2754;
    *(f32 *)(state + 0x300) = lbl_803E27B0;
    *(f32 *)(state + 0x304) = lbl_803E27B4;
    state[0x320] = 35;
    fz = lbl_803E2748;
    *(f32 *)(state + 0x314) = fz;
    state[0x321] = 34;
    *(f32 *)(state + 0x318) = lbl_803E27B8;
    state[0x322] = 6;
    *(f32 *)(state + 0x31c) = fz;
    *(f32 *)(state + 0x2fc) *= lbl_803E27BC;
    switch (*(s16 *)(obj + 0x46)) {
    case 314:
        if (*(s8 *)(setup + 0x27) != 0) {
            *(s16 *)(state + 0x2b6) = 51;
        }
        *(f32 *)(state + 0x2ac) = lbl_803E27C0;
        *(s16 *)(state + 0x2b0) = 40;
        state[0x33b] = 0;
        break;
    case 17:
        if (*(s8 *)(setup + 0x27) != 0) {
            *(s16 *)(state + 0x2b6) = 51;
        }
        *(f32 *)(state + 0x2ac) = lbl_803E27C0;
        *(s16 *)(state + 0x2b0) = 40;
        state[0x33b] = 1;
        break;
    case 1505:
        if (*(s8 *)(setup + 0x27) != 0) {
            *(s16 *)(state + 0x2b6) = 1529;
        }
        *(f32 *)(state + 0x2ac) = lbl_803E27C0;
        *(s16 *)(state + 0x2b0) = 50;
        state[0x33b] = 2;
        break;
    case 1463:
        if (*(s8 *)(setup + 0x27) != 0) {
            *(s16 *)(state + 0x2b6) = 1530;
        }
        *(f32 *)(state + 0x2ac) = lbl_803E27C4;
        *(s16 *)(state + 0x2b0) = 50;
        state[0x33b] = 3;
        break;
    case 1464:
        if (*(s8 *)(setup + 0x27) != 0) {
            *(s16 *)(state + 0x2b6) = 1534;
        }
        *(f32 *)(state + 0x2ac) = lbl_803E27C0;
        *(s16 *)(state + 0x2b0) = 60;
        state[0x33b] = 4;
        break;
    case 1465:
        if (*(s8 *)(setup + 0x27) != 0) {
            *(s16 *)(state + 0x2b6) = 51;
        }
        *(f32 *)(state + 0x2ac) = lbl_803E27C0;
        *(s16 *)(state + 0x2b0) = 1;
        state[0x33b] = 1;
        break;
    case 1958:
        if (*(s8 *)(setup + 0x27) != 0) {
            *(s16 *)(state + 0x2b6) = 1957;
        }
        *(f32 *)(state + 0x2ac) = lbl_803E27C0;
        *(s16 *)(state + 0x2b0) = 160;
        state[0x33b] = 5;
        z = 0;
        state[0x320] = z;
        *(f32 *)(state + 0x314) = fz;
        state[0x321] = 21;
        *(f32 *)(state + 0x318) = lbl_803E27B8;
        state[0x322] = z;
        *(f32 *)(state + 0x31c) = fz;
        *(int *)(state + 0x36c) = allocModelStruct2(&lbl_803DBC98, 1);
        tailFn_80026c38(*(int *)(state + 0x36c), lbl_803E27C8, lbl_803E27CC, lbl_803E27D0);
        *(int *)(obj + 0x108) = (int)baddieAfterUpdateBonesCb;
        fn_80026C30(*(int *)(state + 0x36c), 1);
        break;
    }
    if (*(s8 *)(setup + 0x2e) != -1) {
        *(u32 *)(state + 0x2dc) |= 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int playerGetMoney(u8 *player);
extern void playerAddMoney(u8 *player, int amount);
extern void hudFn_8011f38c(int a);
extern int *gGameUIInterface;
extern int *gObjectTriggerInterface;
extern u16 lbl_803DBCA0[4];

#pragma scheduling off
#pragma peephole off
void fn_80151C68(int obj, u8 *state)
{
    u8 *player;
    u8 *setup;

    player = Obj_GetPlayerObject();
    setup = *(u8 **)(obj + 0x4c);
    if ((**(int (**)(int))(*gGameUIInterface + 0x20))(446) != 0) {
        if (player != NULL && playerGetMoney(player) >= 25) {
            playerAddMoney(player, -25);
            GameBit_Set(*(s16 *)(setup + 0x1c), 1);
            *(u16 *)(state + 0x338) = lbl_803DBCA0[2];
            *(u8 *)(obj + 0xaf) |= 8;
            hudFn_8011f38c(2);
            (**(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(2, obj, -1);
        } else {
            hudFn_8011f38c(2);
            *(u16 *)(state + 0x338) = lbl_803DBCA0[1];
            (**(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
        }
    } else {
        hudFn_8011f38c(2);
        *(u16 *)(state + 0x338) = lbl_803DBCA0[0];
        (**(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
    }
}
#pragma peephole reset
#pragma scheduling reset
