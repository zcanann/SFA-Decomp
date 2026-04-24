#include "ghidra_import.h"
#include "main/dll/FRONT/n_options.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80003494();
extern undefined4 FUN_80070434();
extern undefined4 FUN_8007048c();
extern undefined4 FUN_801175b4();
extern undefined4 FUN_801175f8();
extern undefined4 FUN_80117708();
extern undefined4 FUN_801177b4();
extern undefined4 FUN_80119a10();
extern undefined4 FUN_802420b0();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_80243e74();
extern undefined4 FUN_80243e88();
extern undefined4 FUN_80243e9c();
extern undefined4 FUN_802446f8();
extern int FUN_80244820();
extern int FUN_80246a0c();
extern undefined4 FUN_8024fe60();
extern uint FUN_8024ff18();
extern undefined4 FUN_80258674();
extern undefined4 FUN_80258944();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025aa74();
extern undefined4 FUN_8025ace8();
extern undefined4 FUN_8025b054();
extern undefined4 FUN_8025be54();
extern undefined4 FUN_8025be80();
extern undefined4 FUN_8025c1a4();
extern undefined4 FUN_8025c224();
extern undefined4 FUN_8025c2a8();
extern undefined4 FUN_8025c368();
extern undefined4 FUN_8025c49c();
extern undefined4 FUN_8025c510();
extern undefined4 FUN_8025c584();
extern undefined4 FUN_8025c5f0();
extern undefined4 FUN_8025c65c();
extern undefined4 FUN_8025c6b4();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025c828();
extern undefined4 FUN_8025ca04();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025cdec();
extern undefined4 FUN_8025ce2c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_8031b000;
extern undefined4 DAT_803a50a8;
extern undefined4 DAT_803a50b4;
extern undefined4 DAT_803a50c0;
extern undefined4 DAT_803a50e0;
extern undefined4 DAT_803a6420;
extern undefined4 DAT_803a692c;
extern undefined4 DAT_803a6a58;
extern undefined4 DAT_803a6a5d;
extern undefined4 DAT_803a6a5f;
extern undefined4 DAT_803a6a94;
extern undefined4 DAT_803a6a98;
extern undefined4 DAT_803a6a9c;
extern undefined4 DAT_803a6aa0;
extern undefined4 DAT_803a6aa8;
extern undefined4 DAT_803a6ab0;
extern undefined4 DAT_803de2d8;
extern undefined4 DAT_803de2e0;
extern undefined4* DAT_803de2e8;
extern undefined4 DAT_803de2ec;
extern undefined4 DAT_803de2f0;
extern undefined4 DAT_803de2f4;
extern undefined4 DAT_803de2f8;
extern undefined4 DAT_803e29b0;
extern undefined4 DAT_803e29b4;
extern undefined4 DAT_803e29b8;
extern undefined4 DAT_803e29bc;
extern undefined4 DAT_803e29c0;
extern f64 DOUBLE_803e29c8;
extern f32 FLOAT_803e29c4;

/*
 * --INFO--
 *
 * Function: FUN_8011784c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8011784C
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8011784c(int param_1,int param_2)
{
  int iVar1;
  
  if (param_2 == 0) {
    iVar1 = FUN_80246a0c(-0x7fc59f00,FUN_801177b4,0,0x803a6100,0x1000,param_1,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  else {
    iVar1 = FUN_80246a0c(-0x7fc59f00,FUN_80117708,param_2,0x803a6100,0x1000,param_1,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  FUN_802446f8((undefined4 *)&DAT_803a50e0,&DAT_803a50b4,3);
  FUN_802446f8((undefined4 *)&DAT_803a50c0,&DAT_803a50a8,3);
  DAT_803de2d8 = 1;
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_80117910
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80117910
 * EN v1.1 Size: 1280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80117910(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5)
{
  uint uVar1;
  uint uVar2;
  double dVar3;
  undefined8 uVar4;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  uint auStack_84 [8];
  uint auStack_64 [8];
  uint auStack_44 [17];
  
  uVar4 = FUN_80286840();
  FUN_8007048c(1,3,1);
  FUN_8025cce8(0,1,0,0);
  FUN_8025cdec(1);
  FUN_8025ce2c(0);
  FUN_80259288(2);
  FUN_80070434(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80258944(2);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  FUN_80258674(1,1,4,0x3c,0,0x7d);
  FUN_8025ca04(4);
  FUN_8025be54(0);
  FUN_8025c828(0,1,1,0xff);
  FUN_8025be80(0);
  FUN_8025c1a4(0,0xf,8,0xe,2);
  FUN_8025c2a8(0,0,0,0,0,0);
  FUN_8025c224(0,7,4,6,1);
  FUN_8025c368(0,1,0,0,0,0);
  FUN_8025c584(0,0xc);
  FUN_8025c5f0(0,0x1c);
  FUN_8025c65c(0,0,0);
  FUN_8025c828(1,1,2,0xff);
  FUN_8025be80(1);
  FUN_8025c1a4(1,0xf,8,0xe,0);
  FUN_8025c2a8(1,0,0,1,0,0);
  FUN_8025c224(1,7,4,6,0);
  FUN_8025c368(1,1,0,0,0,0);
  FUN_8025c584(1,0xd);
  FUN_8025c5f0(1,0x1d);
  FUN_8025c65c(1,0,0);
  FUN_8025c828(2,0,0,0xff);
  FUN_8025be80(2);
  FUN_8025c1a4(2,0xf,8,0xc,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c224(2,4,7,7,0);
  FUN_8025c368(2,0,0,0,1,0);
  FUN_8025c65c(2,0,0);
  FUN_8025c828(3,0xff,0xff,0xff);
  FUN_8025be80(3);
  FUN_8025c1a4(3,1,0,0xe,0xf);
  FUN_8025c2a8(3,0,0,0,1,0);
  FUN_8025c224(3,7,7,7,7);
  FUN_8025c368(3,0,0,0,1,0);
  FUN_8025c65c(3,0,0);
  FUN_8025c584(3,0xe);
  local_8c = DAT_803e29b0;
  local_88 = DAT_803e29b4;
  FUN_8025c49c(1,(short *)&local_8c);
  local_90 = DAT_803e29b8;
  FUN_8025c510(0,(byte *)&local_90);
  local_94 = DAT_803e29bc;
  FUN_8025c510(1,(byte *)&local_94);
  local_98 = DAT_803e29c0;
  FUN_8025c510(2,(byte *)&local_98);
  FUN_8025c6b4(0,0,1,2,3);
  FUN_8025aa74(auStack_44,(uint)((ulonglong)uVar4 >> 0x20),param_4 & 0xffff,param_5 & 0xffff,1,0,0,
               '\0');
  dVar3 = (double)FLOAT_803e29c4;
  FUN_8025ace8(dVar3,dVar3,dVar3,auStack_44,0,0,0,'\0',0);
  FUN_8025b054(auStack_44,0);
  uVar1 = (int)(short)param_4 >> 1;
  uVar2 = (int)(short)param_5 >> 1;
  FUN_8025aa74(auStack_64,(uint)uVar4,uVar1 & 0xffff,uVar2 & 0xffff,1,0,0,'\0');
  dVar3 = (double)FLOAT_803e29c4;
  FUN_8025ace8(dVar3,dVar3,dVar3,auStack_64,0,0,0,'\0',0);
  FUN_8025b054(auStack_64,1);
  FUN_8025aa74(auStack_84,param_3,uVar1 & 0xffff,uVar2 & 0xffff,1,0,0,'\0');
  dVar3 = (double)FLOAT_803e29c4;
  FUN_8025ace8(dVar3,dVar3,dVar3,auStack_84,0,0,0,'\0',0);
  FUN_8025b054(auStack_84,2);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80117e10
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80117E10
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80117e10(uint param_1,int param_2)
{
  undefined4 uVar1;
  
  if ((DAT_803a6a58 == 0) || (DAT_803a6a5f == '\0')) {
    uVar1 = 0;
  }
  else {
    if (0x7f < (int)param_1) {
      param_1 = 0x7f;
    }
    if ((int)param_1 < 0) {
      param_1 = 0;
    }
    if (60000 < param_2) {
      param_2 = 60000;
    }
    if (param_2 < 0) {
      param_2 = 0;
    }
    FUN_80243e74();
    DAT_803a6a98 = (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803e29c8);
    if (param_2 == 0) {
      DAT_803a6aa0 = 0;
      DAT_803a6a94 = DAT_803a6a98;
    }
    else {
      DAT_803a6aa0 = param_2 << 5;
      DAT_803a6a9c = (DAT_803a6a98 - DAT_803a6a94) /
                     (float)((double)CONCAT44(0x43300000,DAT_803a6aa0 ^ 0x80000000) -
                            DOUBLE_803e29c8);
    }
    FUN_80243e9c();
    uVar1 = 1;
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_80117f1c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80117F1C
 * EN v1.1 Size: 932b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80117f1c(undefined2 *param_1,short *param_2,uint param_3)
{
  ushort uVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  short *psVar5;
  uint uVar6;
  
  if (param_2 == (short *)0x0) {
    if (((DAT_803a6a58 == 0) || (DAT_803a6a5d != '\x02')) || (DAT_803a6a5f == '\0')) {
      FUN_800033a8((int)param_1,0,param_3 << 2);
    }
    else {
      do {
        do {
          if (DAT_803a6ab0 == 0) {
            DAT_803a6ab0 = FUN_801175b4(0);
            if (DAT_803a6ab0 == 0) {
              FUN_800033a8((int)param_1,0,param_3 << 2);
              return;
            }
            DAT_803a6aa8 = *(undefined4 *)(DAT_803a6ab0 + 0xc);
          }
          uVar3 = *(uint *)(DAT_803a6ab0 + 8);
        } while (uVar3 == 0);
        if (param_3 <= uVar3) {
          uVar3 = param_3;
        }
        psVar5 = *(short **)(DAT_803a6ab0 + 4);
        for (uVar6 = uVar3; uVar6 != 0; uVar6 = uVar6 - 1) {
          fVar2 = DAT_803a6a98;
          if (DAT_803a6aa0 != 0) {
            DAT_803a6aa0 = DAT_803a6aa0 + -1;
            fVar2 = DAT_803a6a94 + DAT_803a6a9c;
          }
          DAT_803a6a94 = fVar2;
          uVar1 = *(ushort *)(&DAT_8031b000 + (int)DAT_803a6a94 * 2);
          iVar4 = (int)((uint)uVar1 * (int)*psVar5) >> 0xf;
          if (iVar4 < -0x8000) {
            iVar4 = -0x8000;
          }
          if (0x7fff < iVar4) {
            iVar4 = 0x7fff;
          }
          *param_1 = (short)iVar4;
          iVar4 = (int)((uint)uVar1 * (int)psVar5[1]) >> 0xf;
          if (iVar4 < -0x8000) {
            iVar4 = -0x8000;
          }
          if (0x7fff < iVar4) {
            iVar4 = 0x7fff;
          }
          param_1[1] = (short)iVar4;
          param_1 = param_1 + 2;
          psVar5 = psVar5 + 2;
        }
        param_3 = param_3 - uVar3;
        *(uint *)(DAT_803a6ab0 + 8) = *(int *)(DAT_803a6ab0 + 8) - uVar3;
        *(short **)(DAT_803a6ab0 + 4) = psVar5;
        if (*(int *)(DAT_803a6ab0 + 8) == 0) {
          FUN_801175f8(DAT_803a6ab0);
          DAT_803a6ab0 = 0;
        }
      } while (param_3 != 0);
    }
  }
  else if (((DAT_803a6a58 == 0) || (DAT_803a6a5d != '\x02')) || (DAT_803a6a5f == '\0')) {
    FUN_80003494((uint)param_1,(uint)param_2,param_3 << 2);
  }
  else {
    do {
      do {
        if (DAT_803a6ab0 == 0) {
          DAT_803a6ab0 = FUN_801175b4(0);
          if (DAT_803a6ab0 == 0) {
            FUN_80003494((uint)param_1,(uint)param_2,param_3 << 2);
            return;
          }
          DAT_803a6aa8 = *(undefined4 *)(DAT_803a6ab0 + 0xc);
        }
        uVar3 = *(uint *)(DAT_803a6ab0 + 8);
      } while (uVar3 == 0);
      if (param_3 <= uVar3) {
        uVar3 = param_3;
      }
      psVar5 = *(short **)(DAT_803a6ab0 + 4);
      for (uVar6 = uVar3; uVar6 != 0; uVar6 = uVar6 - 1) {
        fVar2 = DAT_803a6a98;
        if (DAT_803a6aa0 != 0) {
          DAT_803a6aa0 = DAT_803a6aa0 + -1;
          fVar2 = DAT_803a6a94 + DAT_803a6a9c;
        }
        DAT_803a6a94 = fVar2;
        uVar1 = *(ushort *)(&DAT_8031b000 + (int)DAT_803a6a94 * 2);
        iVar4 = (int)*param_2 + ((int)((uint)uVar1 * (int)*psVar5) >> 0xf);
        if (iVar4 < -0x8000) {
          iVar4 = -0x8000;
        }
        if (0x7fff < iVar4) {
          iVar4 = 0x7fff;
        }
        *param_1 = (short)iVar4;
        iVar4 = (int)param_2[1] + ((int)((uint)uVar1 * (int)psVar5[1]) >> 0xf);
        if (iVar4 < -0x8000) {
          iVar4 = -0x8000;
        }
        if (0x7fff < iVar4) {
          iVar4 = 0x7fff;
        }
        param_1[1] = (short)iVar4;
        param_1 = param_1 + 2;
        param_2 = param_2 + 2;
        psVar5 = psVar5 + 2;
      }
      param_3 = param_3 - uVar3;
      *(uint *)(DAT_803a6ab0 + 8) = *(int *)(DAT_803a6ab0 + 8) - uVar3;
      *(short **)(DAT_803a6ab0 + 4) = psVar5;
      if (*(int *)(DAT_803a6ab0 + 8) == 0) {
        FUN_801175f8(DAT_803a6ab0);
        DAT_803a6ab0 = 0;
      }
    } while (param_3 != 0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801182c0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801182C0
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801182c0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80118434
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80118434
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80118434(void)
{
  int iVar1;
  int iVar2;
  int local_18 [5];
  
  if (DAT_803de2e0 != 0) {
    while( true ) {
      iVar1 = FUN_80244820((int *)&DAT_803a692c,local_18,0);
      iVar2 = local_18[0];
      if (iVar1 != 1) {
        iVar2 = 0;
      }
      if (iVar2 == 0) break;
      FUN_80119a10(iVar2);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801184a0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801184A0
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_801184a0(uint param_1)
{
  bool bVar1;
  
  bVar1 = DAT_803a6a58 != 0;
  if (bVar1) {
    FUN_80003494(param_1,0x803a6a40,8);
  }
  return bVar1;
}
