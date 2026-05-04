#include "ghidra_import.h"
#include "main/dll/newSeqObj.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006924();
extern int FUN_80006a10();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern uint FUN_80017730();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined4 FUN_800305c4();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_8014c694();
extern undefined4 FUN_8014d3d0();
extern undefined4 FUN_8014d4c8();
extern char FUN_8014ffa8();
extern undefined8 FUN_80286830();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();

extern undefined4 DAT_8031e980;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e33f0;
extern f64 DOUBLE_803e3408;
extern f32 lbl_803DC074;
extern f32 lbl_803E33D8;
extern f32 lbl_803E33DC;
extern f32 lbl_803E33E0;
extern f32 lbl_803E33E4;
extern f32 lbl_803E33EC;
extern f32 lbl_803E33F8;
extern f32 lbl_803E33FC;
extern f32 lbl_803E3400;
extern f32 lbl_803E3404;
extern f32 lbl_803E3410;
extern f32 lbl_803E3414;
extern f32 lbl_803E3418;
extern f32 lbl_803E341C;
extern f32 lbl_803E3420;
extern f32 lbl_803E3424;
extern f32 lbl_803E3428;
extern f32 lbl_803E342C;
extern f32 lbl_803E3430;
extern f32 lbl_803E3434;
extern void* PTR_DAT_8031fdbc;
extern void* PTR_DAT_8031fdc0;
extern void* PTR_DAT_8031fdcc;
extern void* PTR_DAT_8031fdd8;
extern void* PTR_DAT_8031fddc;
extern void* PTR_DAT_8031fde0;

/*
 * --INFO--
 *
 * Function: FUN_801504f8
 * EN v1.0 Address: 0x801504F8
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x80150830
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801504f8(uint param_1,int param_2)
{
  int iVar1;
  double dVar2;
  
  if ((*(ushort *)(param_2 + 0x2f8) & 0x200) != 0) {
    FUN_80006824(param_1,899);
    iVar1 = FUN_80017a98();
    if ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) {
      dVar2 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18));
      if (dVar2 <= (double)lbl_803E33F8) {
        FUN_80006b94((double)(lbl_803E33DC *
                             (lbl_803E33E0 - (float)(dVar2 / (double)lbl_803E33F8))));
      }
      FUN_80006924((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                   (double)*(float *)(param_1 + 0x14),(double)lbl_803E33F8,(double)lbl_803E33FC)
      ;
    }
  }
  if ((*(ushort *)(param_2 + 0x2f8) & 0x40) != 0) {
    FUN_80006824(param_1,0x19);
  }
  if ((*(ushort *)(param_2 + 0x2f8) & 0x1000) != 0) {
    FUN_80006824(param_1,599);
  }
  if ((*(ushort *)(param_2 + 0x2f8) & 1) != 0) {
    FUN_80006824(param_1,0x12);
  }
  if ((*(ushort *)(param_2 + 0x2f8) & 0x80) != 0) {
    FUN_80006824(param_1,0x15);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015061c
 * EN v1.0 Address: 0x8015061C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80150950
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015061c(int param_1,char param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80150620
 * EN v1.0 Address: 0x80150620
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8015098C
 * EN v1.1 Size: 1048b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80150620(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,int param_13,
                 int param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80150624
 * EN v1.0 Address: 0x80150624
 * EN v1.0 Size: 2768b
 * EN v1.1 Address: 0x80150DA4
 * EN v1.1 Size: 1484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80150624(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  int iVar2;
  ushort *puVar3;
  char cVar4;
  undefined4 *puVar5;
  uint uVar6;
  undefined4 in_r6;
  uint in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  float *pfVar10;
  double dVar11;
  double extraout_f1;
  undefined8 extraout_f1_00;
  double dVar12;
  double dVar13;
  double dVar14;
  undefined8 uVar15;
  
  uVar15 = FUN_8028683c();
  puVar3 = (ushort *)((ulonglong)uVar15 >> 0x20);
  puVar5 = (undefined4 *)uVar15;
  pfVar10 = (float *)*puVar5;
  uVar6 = (uint)*(byte *)((int)puVar5 + 0x33b);
  puVar9 = (&PTR_DAT_8031fdc0)[uVar6 * 10];
  puVar8 = (&PTR_DAT_8031fdbc)[uVar6 * 10];
  puVar7 = (&PTR_DAT_8031fdd8)[uVar6 * 10];
  if ((uVar6 == 5) && ((puVar5[0xb7] & 0x800000) != 0)) {
    FUN_80017698(0x1c8,1);
  }
  FUN_801504f8((uint)puVar3,(int)puVar5);
  fVar1 = lbl_803E33D8;
  dVar12 = (double)(float)puVar5[0xca];
  dVar11 = (double)lbl_803E33D8;
  if (((dVar12 != dVar11) && (*(short *)(puVar5 + 0xce) != 0)) &&
     (puVar5[0xca] = (float)(dVar12 - (double)lbl_803DC074), (double)(float)puVar5[0xca] <= dVar11
     )) {
    puVar5[0xca] = fVar1;
    puVar5[0xb7] = puVar5[0xb7] | 0x40000000;
    *(ushort *)(puVar5 + 0xce) = (ushort)(byte)puVar7[(uint)*(ushort *)(puVar5 + 0xce) * 0x10 + 10];
  }
  cVar4 = FUN_8014ffa8(dVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,puVar5,0
                       ,in_r6,in_r7,in_r8,in_r9,in_r10);
  fVar1 = lbl_803E33D8;
  if (cVar4 == '\0') {
    dVar11 = extraout_f1;
    if (*(char *)((int)puVar5 + 0x33d) != '\0') {
      if ((puVar5[0xb7] & 0x40000000) != 0) {
        *(float *)(puVar3 + 0x16) = lbl_803E33D8;
        *(float *)(puVar3 + 0x14) = fVar1;
        *(float *)(puVar3 + 0x12) = fVar1;
        iVar2 = (uint)*(byte *)((int)puVar5 + 0x33d) * 0xc;
        in_r6 = 0;
        in_r7 = *(uint *)(puVar9 + iVar2 + 4) & 0xff;
        FUN_8014d4c8((double)*(float *)(puVar9 + iVar2),dVar12,param_3,param_4,param_5,param_6,
                     param_7,param_8,(int)puVar3,(int)puVar5,(uint)(byte)puVar9[iVar2 + 8],0,in_r7,
                     in_r8,in_r9,in_r10);
        dVar11 = (double)*(float *)(&DAT_8031e980 +
                                   (uint)(byte)puVar9[(uint)*(byte *)((int)puVar5 + 0x33d) * 0xc + 8
                                                     ] * 4);
        FUN_800305c4(dVar11,(int)puVar3);
        *(undefined *)((int)puVar5 + 0x33d) = puVar9[(uint)*(byte *)((int)puVar5 + 0x33d) * 0xc + 9]
        ;
        *(undefined *)((int)puVar5 + 0x33e) = 0;
      }
      if (*(char *)((int)puVar5 + 0x33e) == '\0') goto LAB_80151358;
    }
    if (((puVar5[0xb7] & 0x80000000) != 0) && (*(char *)((int)puVar5 + 0x33d) == '\0')) {
      FUN_8014c694(dVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar3);
    }
    if ((puVar5[0xb7] & 0x2000) == 0) {
      if ((*(char *)((int)puVar5 + 0x33d) == '\0') && ((puVar5[0xb7] & 0x40000000) != 0)) {
        uVar6 = FUN_80017760(1,(uint)(byte)puVar9[8]);
        if (*(ushort *)(puVar5 + 0xce) == 0) {
          iVar2 = (uVar6 & 0xff) * 0xc;
          if ((puVar3[0x50] != (ushort)(byte)puVar9[iVar2 + 8]) || ((byte)puVar9[iVar2 + 8] != 0)) {
            *(undefined *)((int)puVar5 + 0x2f2) = 0;
            *(undefined *)((int)puVar5 + 0x2f3) = 0;
            *(undefined *)(puVar5 + 0xbd) = 0;
            FUN_8014d4c8((double)*(float *)(puVar9 + iVar2),dVar12,param_3,param_4,param_5,param_6,
                         param_7,param_8,(int)puVar3,(int)puVar5,(uint)(byte)puVar9[iVar2 + 8],0,3,
                         in_r8,in_r9,in_r10);
            FUN_800305c4((double)*(float *)(&DAT_8031e980 + (uint)(byte)puVar9[iVar2 + 8] * 4),
                         (int)puVar3);
          }
        }
        else {
          *(char *)((int)puVar5 + 0x2f2) =
               (char)*(undefined4 *)(puVar7 + (uint)*(ushort *)(puVar5 + 0xce) * 0x10 + 0xc);
          iVar2 = (uint)*(ushort *)(puVar5 + 0xce) * 0x10;
          FUN_8014d4c8((double)*(float *)(puVar7 + iVar2),dVar12,param_3,param_4,param_5,param_6,
                       param_7,param_8,(int)puVar3,(int)puVar5,(uint)(byte)puVar7[iVar2 + 8],0,
                       *(uint *)(puVar7 + iVar2 + 4) & 0xff,in_r8,in_r9,in_r10);
          FUN_800305c4((double)*(float *)(&DAT_8031e980 +
                                         (uint)(byte)puVar7[(uint)*(ushort *)(puVar5 + 0xce) * 0x10
                                                            + 8] * 4),(int)puVar3);
          *(ushort *)(puVar5 + 0xce) =
               (ushort)(byte)puVar7[(uint)*(ushort *)(puVar5 + 0xce) * 0x10 + 9];
        }
      }
    }
    else {
      dVar12 = (double)(pfVar10[0x1a] - *(float *)(puVar3 + 6));
      dVar11 = FUN_80293900((double)(float)(dVar12 * dVar12 +
                                           (double)((pfVar10[0x1c] - *(float *)(puVar3 + 10)) *
                                                   (pfVar10[0x1c] - *(float *)(puVar3 + 10)))));
      if ((double)lbl_803E3410 < dVar11) {
        dVar11 = (double)lbl_803E3410;
      }
      puVar5[0xc4] = (float)((double)lbl_803E3410 - dVar11) * lbl_803E3414 * (float)puVar5[0xbf]
      ;
      if ((float)puVar5[0xc4] < lbl_803E3418) {
        puVar5[0xc4] = lbl_803E3418;
      }
      iVar2 = FUN_80006a10((double)(float)puVar5[0xc4],pfVar10);
      if (((iVar2 != 0) || (pfVar10[4] != 0.0)) &&
         (cVar4 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar10), cVar4 != '\0')) {
        FUN_8014c694(extraout_f1_00,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)puVar3);
      }
      uVar6 = FUN_80017730();
      dVar11 = (double)(float)((double)CONCAT44(0x43300000,
                                                ((uVar6 & 0xffff) + 0x8000) - (uint)*puVar3 ^
                                                0x80000000) - DOUBLE_803e33f0);
      if ((double)lbl_803E3420 < dVar11) {
        dVar11 = (double)(float)((double)lbl_803E341C + dVar11);
      }
      if (dVar11 < (double)lbl_803E3428) {
        dVar11 = (double)(float)((double)lbl_803E3424 + dVar11);
      }
      dVar14 = (double)(((float)puVar5[0xbf] - (float)puVar5[0xc4]) / lbl_803E33E4);
      dVar13 = (double)lbl_803E33E0;
      dVar12 = dVar11;
      if (dVar11 < (double)lbl_803E33D8) {
        dVar12 = -dVar11;
      }
      puVar5[0xc2] = (float)(dVar14 * (double)(float)(dVar13 - (double)(float)(dVar12 / (double)
                                                  lbl_803E3424)));
      if ((float)puVar5[0xc2] < lbl_803E33EC) {
        puVar5[0xc2] = lbl_803E33EC;
      }
      if (((puVar5[0xb7] & 0x40000000) != 0) && (*(char *)((int)puVar5 + 0x33d) == '\0')) {
        if (*(ushort *)(puVar5 + 0xce) == 0) {
          if ((float)puVar5[0xc4] <= lbl_803E342C) {
            *(undefined *)((int)puVar5 + 0x2f2) = 0;
            *(undefined *)((int)puVar5 + 0x2f3) = 0;
            *(undefined *)(puVar5 + 0xbd) = 0;
            *(undefined *)((int)puVar5 + 0x323) = 1;
            puVar5[0xc2] = lbl_803E3434;
            FUN_800305f8((double)lbl_803E33D8,dVar13,dVar14,dVar11,param_5,param_6,param_7,param_8
                         ,puVar3,(uint)(byte)puVar8[8],0,in_r6,in_r7,in_r8,in_r9,in_r10);
            puVar5[0xc4] = lbl_803E33D8;
          }
          else {
            *(undefined *)((int)puVar5 + 0x2f2) = 0;
            *(undefined *)((int)puVar5 + 0x2f3) = 0;
            *(undefined *)(puVar5 + 0xbd) = 0;
            if ((float)puVar5[0xc4] <= lbl_803E3430) {
              *(undefined *)((int)puVar5 + 0x323) = 1;
              FUN_800305f8((double)lbl_803E33D8,dVar13,dVar14,dVar11,param_5,param_6,param_7,
                           param_8,puVar3,(uint)(byte)puVar8[0x14],0,in_r6,in_r7,in_r8,in_r9,in_r10)
              ;
            }
            else {
              *(undefined *)((int)puVar5 + 0x323) = 1;
              FUN_800305f8((double)lbl_803E33D8,dVar13,dVar14,dVar11,param_5,param_6,param_7,
                           param_8,puVar3,(uint)(byte)puVar8[0x20],0,in_r6,in_r7,in_r8,in_r9,in_r10)
              ;
            }
          }
        }
        else {
          iVar2 = (uint)*(ushort *)(puVar5 + 0xce) * 0x10;
          FUN_8014d4c8((double)*(float *)(puVar7 + iVar2),dVar13,dVar14,dVar11,param_5,param_6,
                       param_7,param_8,(int)puVar3,(int)puVar5,(uint)(byte)puVar7[iVar2 + 8],0,
                       *(uint *)(puVar7 + iVar2 + 4) & 0xff,in_r8,in_r9,in_r10);
          FUN_800305c4((double)*(float *)(&DAT_8031e980 +
                                         (uint)(byte)puVar7[(uint)*(ushort *)(puVar5 + 0xce) * 0x10
                                                            + 8] * 4),(int)puVar3);
          *(ushort *)(puVar5 + 0xce) =
               (ushort)(byte)puVar7[(uint)*(ushort *)(puVar5 + 0xce) * 0x10 + 9];
        }
      }
      FUN_8014d3d0((short *)puVar3,puVar5,0xf,0);
    }
  }
LAB_80151358:
  FUN_80286888();
  return;
}
