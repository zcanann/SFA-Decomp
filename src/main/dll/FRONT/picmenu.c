#include "ghidra_import.h"
#include "main/dll/FRONT/picmenu.h"

extern undefined4 FUN_800033a8();
extern undefined8 FUN_80003494();
extern int FUN_80015888();
extern undefined4 FUN_801182c0();
extern undefined8 FUN_80118e30();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_80243e74();
extern undefined4 FUN_80243e9c();
extern undefined4 FUN_802446f8();
extern undefined4 FUN_80244758();
extern int FUN_80244820();
extern int FUN_80246a0c();
extern undefined4 FUN_80246c10();
extern undefined4 FUN_80246dcc();
extern undefined4 FUN_80247054();
extern int FUN_80249300();
extern undefined4 FUN_802493c8();
extern int FUN_80249700();
extern undefined4 FUN_8024fe1c();
extern undefined4 FUN_8024fe60();
extern undefined4 FUN_8024fee8();
extern undefined4 FUN_80264c10();
extern int FUN_8026c0d8();
extern undefined8 FUN_80286830();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_8028687c();
extern int FUN_80291db4();

extern undefined4 DAT_803a6420;
extern undefined4 DAT_803a6920;
extern undefined4 DAT_803a692c;
extern undefined4 DAT_803a6980;
extern undefined DAT_803a69c0;
extern undefined4 DAT_803a69fc;
extern undefined4 DAT_803a6a00;
extern undefined4 DAT_803a6a10;
extern undefined4 DAT_803a6a1c;
extern undefined4 DAT_803a6a24;
extern undefined4 DAT_803a6a2c;
extern undefined4 DAT_803a6a54;
extern undefined4 DAT_803a6a58;
extern undefined4 DAT_803a6a5c;
extern undefined4 DAT_803a6a5d;
extern undefined4 DAT_803a6a5e;
extern undefined4 DAT_803a6a5f;
extern undefined4 DAT_803a6a60;
extern undefined4 DAT_803a6a64;
extern undefined4 DAT_803a6a68;
extern undefined4 DAT_803a6a70;
extern undefined4 DAT_803a6a74;
extern undefined4 DAT_803a6a78;
extern undefined4 DAT_803a6a90;
extern undefined4 DAT_803a6a94;
extern undefined4 DAT_803a6a98;
extern undefined4 DAT_803a6aa0;
extern undefined4 DAT_803a7e78;
extern undefined4 DAT_803a7ea0;
extern undefined4 DAT_803a7ec8;
extern undefined4 DAT_803a7ef0;
extern undefined4 DAT_803a7f10;
extern undefined4 DAT_803a7f30;
extern undefined4 DAT_803a7f68;
extern undefined4 DAT_803a7f88;
extern undefined4 DAT_803dc648;
extern undefined4 DAT_803de2e0;
extern undefined4 DAT_803de2e8;
extern undefined4 DAT_803de2ec;
extern undefined4 DAT_803de2f0;
extern undefined4 DAT_803de2f4;
extern undefined4 DAT_803de2f8;
extern undefined4 DAT_803de308;
extern undefined4 DAT_803de314;
extern undefined4 DAT_803de318;
extern f32 FLOAT_803e29d4;

/*
 * --INFO--
 *
 * Function: FUN_801192a8
 * EN v1.0 Address: 0x80119000
 * EN v1.0 Size: 1084b
 * EN v1.1 Address: 0x801192A8
 * EN v1.1 Size: 748b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801192a8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar2;
  uint uVar3;
  undefined *puVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_80286830();
  if ((DAT_803de2e0 != 0) && (DAT_803a6a58 == 0)) {
    uVar5 = extraout_f1;
    FUN_800033a8(-0x7fc595c0,0,8);
    FUN_800033a8(-0x7fc595b8,0,0xc);
    iVar1 = FUN_80249300(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (char *)((ulonglong)uVar6 >> 0x20),-0x7fc59640);
    if (iVar1 != 0) {
      iVar1 = FUN_80015888(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           &DAT_803a69c0,&DAT_803a6980,0x40,0,in_r7,in_r8,in_r9,in_r10);
      if (iVar1 < 0) {
        FUN_802493c8((int *)&DAT_803a69c0);
      }
      else {
        uVar5 = FUN_80003494(0x803a69fc,0x803a6980,0x30);
        iVar1 = FUN_80291db4((uint *)&DAT_803a69fc,(uint *)&DAT_803dc648);
        uVar3 = DAT_803a6a1c;
        if (iVar1 == 0) {
          if (DAT_803a6a00 == 0x10000) {
            iVar1 = FUN_80015888(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 &DAT_803a69c0,&DAT_803a6980,0x20,DAT_803a6a1c,in_r7,in_r8,in_r9,
                                 in_r10);
            if (iVar1 < 0) {
              FUN_802493c8((int *)&DAT_803a69c0);
            }
            else {
              uVar5 = FUN_80003494(0x803a6a2c,0x803a6980,0x14);
              uVar3 = uVar3 + 0x14;
              puVar4 = &DAT_803a69c0;
              DAT_803a6a5f = 0;
              for (uVar2 = 0; uVar2 < DAT_803a6a2c; uVar2 = uVar2 + 1) {
                if (puVar4[0x70] == '\x01') {
                  iVar1 = FUN_80015888(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                       ,&DAT_803a69c0,&DAT_803a6980,0x20,uVar3,in_r7,in_r8,in_r9,
                                       in_r10);
                  if (iVar1 < 0) {
                    FUN_802493c8((int *)&DAT_803a69c0);
                    goto LAB_8011957c;
                  }
                  uVar5 = FUN_80003494(0x803a6a48,0x803a6980,0xc);
                  DAT_803a6a5f = 1;
                  uVar3 = uVar3 + 0xc;
                }
                else {
                  if (puVar4[0x70] != '\0') goto LAB_8011957c;
                  iVar1 = FUN_80015888(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                       ,&DAT_803a69c0,&DAT_803a6980,0x20,uVar3,in_r7,in_r8,in_r9,
                                       in_r10);
                  if (iVar1 < 0) {
                    FUN_802493c8((int *)&DAT_803a69c0);
                    goto LAB_8011957c;
                  }
                  uVar5 = FUN_80003494(0x803a6a40,0x803a6980,8);
                  uVar3 = uVar3 + 8;
                }
                puVar4 = puVar4 + 1;
              }
              DAT_803a6a5d = 0;
              DAT_803a6a5c = 0;
              DAT_803a6a5e = 0;
              DAT_803a6a58 = 1;
              DAT_803a6a94 = FLOAT_803e29d4;
              DAT_803a6a98 = FLOAT_803e29d4;
              DAT_803a6aa0 = 0;
              DAT_803a6a68 = (int)uVar6;
            }
          }
          else {
            FUN_802493c8((int *)&DAT_803a69c0);
          }
        }
        else {
          FUN_802493c8((int *)&DAT_803a69c0);
        }
      }
    }
  }
LAB_8011957c:
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80119594
 * EN v1.0 Address: 0x8011943C
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x80119594
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80119594(void)
{
  FUN_80243e74();
  if (DAT_803de2e8 != 0) {
    FUN_8024fe1c(DAT_803de2e8);
  }
  FUN_80243e9c();
  DAT_803de2e0 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801195e0
 * EN v1.0 Address: 0x80119478
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x801195E0
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801195e0(int param_1)
{
  int iVar1;
  undefined4 uVar2;
  
  FUN_800033a8(-0x7fc59640,0,0x1a8);
  FUN_802446f8((undefined4 *)&DAT_803a692c,&DAT_803a6920,3);
  iVar1 = FUN_8026c0d8();
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    FUN_80243e74();
    DAT_803de2f8 = 0;
    DAT_803de2f4 = 0;
    DAT_803de2f0 = 0;
    DAT_803de2ec = param_1;
    DAT_803de2e8 = FUN_8024fe1c(FUN_801182c0);
    if ((DAT_803de2e8 == 0) && (DAT_803de2ec != 0)) {
      FUN_8024fe1c(0);
      FUN_80243e9c();
      uVar2 = 0;
    }
    else {
      FUN_80243e9c();
      if (DAT_803de2ec == 0) {
        FUN_800033a8(-0x7fc59be0,0,0x500);
        FUN_802420e0(0x803a6420,0x500);
        FUN_8024fe60(&DAT_803a6420 + DAT_803de2f8 * 0x280,0x280);
        FUN_8024fee8();
      }
      DAT_803de2e0 = 1;
      uVar2 = 1;
    }
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80119700
 * EN v1.0 Address: 0x80119584
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80119700
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80119700(undefined4 param_1)
{
  FUN_80244758((int *)&DAT_803a7ef0,param_1,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80119730
 * EN v1.0 Address: 0x801195B0
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x80119730
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80119730(void)
{
  undefined4 local_8 [2];
  
  FUN_80244820((int *)&DAT_803a7ef0,local_8,1);
  return local_8[0];
}

/*
 * --INFO--
 *
 * Function: FUN_80119764
 * EN v1.0 Address: 0x801195E0
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80119764
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80119764(undefined4 param_1)
{
  FUN_80244758((int *)&DAT_803a7f30,param_1,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80119794
 * EN v1.0 Address: 0x8011960C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x80119794
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80119794(void)
{
  undefined4 local_8 [2];
  
  FUN_80244820((int *)&DAT_803a7f10,local_8,1);
  return local_8[0];
}

/*
 * --INFO--
 *
 * Function: FUN_801197c8
 * EN v1.0 Address: 0x8011963C
 * EN v1.0 Size: 420b
 * EN v1.1 Address: 0x801197C8
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801197c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  undefined4 *puVar1;
  int iVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined8 uVar7;
  undefined4 *local_28 [10];
  
  uVar7 = FUN_8028683c();
  iVar6 = 0;
  iVar3 = DAT_803a6a74;
  uVar5 = DAT_803a6a70;
  do {
    FUN_80244820((int *)&DAT_803a7f30,local_28,1);
    puVar1 = local_28[0];
    iVar2 = FUN_80249700(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (undefined4 *)&DAT_803a69c0,*local_28[0],iVar3,uVar5,2,in_r8,in_r9,in_r10);
    if (iVar2 != iVar3) {
      if (iVar2 == -1) {
        DAT_803a6a60 = 0xffffffff;
      }
      if (iVar6 == 0) {
        uVar7 = FUN_80118e30(0);
      }
      FUN_80247054(-0x7fc58498);
    }
    puVar1[1] = iVar6;
    FUN_80244758((int *)&DAT_803a7f10,puVar1,1);
    uVar4 = uVar5 + iVar3;
    iVar3 = *(int *)*puVar1;
    uVar5 = uVar4;
    if (((iVar6 + DAT_803a6a78) - ((uint)(iVar6 + DAT_803a6a78) / DAT_803a6a10) * DAT_803a6a10 ==
         DAT_803a6a10 - 1) && (uVar5 = DAT_803a6a24, (DAT_803a6a5e & 1) == 0)) {
      FUN_80247054(-0x7fc58498);
      uVar5 = uVar4;
    }
    iVar6 = iVar6 + 1;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_801198c0
 * EN v1.0 Address: 0x801197E0
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x801198C0
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801198c0(void)
{
  if (DAT_803de308 != 0) {
    FUN_80246c10(-0x7fc58498);
    DAT_803de308 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801198fc
 * EN v1.0 Address: 0x8011981C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801198FC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801198fc(void)
{
  if (DAT_803de308 != 0) {
    FUN_80246dcc(-0x7fc58498);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80119930
 * EN v1.0 Address: 0x80119850
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x80119930
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_80119930(int param_1)
{
  int iVar1;
  
  iVar1 = FUN_80246a0c(-0x7fc58498,FUN_801197c8,0,0x803a7b68,0x1000,param_1,1);
  if (iVar1 != 0) {
    FUN_802446f8((undefined4 *)&DAT_803a7f30,&DAT_803a7ec8,10);
    FUN_802446f8((undefined4 *)&DAT_803a7f10,&DAT_803a7ea0,10);
    FUN_802446f8((undefined4 *)&DAT_803a7ef0,&DAT_803a7e78,10);
    DAT_803de308 = 1;
  }
  return iVar1 != 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801199cc
 * EN v1.0 Address: 0x801198E8
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x801199CC
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801199cc(uint param_1)
{
  int iVar1;
  undefined4 local_8 [2];
  
  iVar1 = FUN_80244820((int *)&DAT_803a7f68,local_8,param_1);
  if (iVar1 != 1) {
    local_8[0] = 0;
  }
  return local_8[0];
}

/*
 * --INFO--
 *
 * Function: FUN_80119a10
 * EN v1.0 Address: 0x80119928
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80119A10
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80119a10(undefined4 param_1)
{
  FUN_80244758((int *)&DAT_803a7f88,param_1,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80119a40
 * EN v1.0 Address: 0x80119954
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x80119A40
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80119a40(void)
{
  int *piVar1;
  undefined *puVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  int *local_38 [14];
  
  piVar1 = (int *)FUN_80286830();
  piVar4 = (int *)(*piVar1 + 8);
  iVar3 = *piVar1 + DAT_803a6a2c * 4 + 8;
  FUN_80244820((int *)&DAT_803a7f88,local_38,1);
  puVar2 = &DAT_803a69c0;
  for (uVar5 = 0; uVar5 < DAT_803a6a2c; uVar5 = uVar5 + 1) {
    if (puVar2[0x70] == '\0') {
      DAT_803a6a64 = FUN_80264c10(iVar3,*local_38[0],local_38[0][1],local_38[0][2],DAT_803a6a54);
      if (DAT_803a6a64 != 0) {
        if (DAT_803de314 != 0) {
          FUN_80118e30(0);
          DAT_803de314 = 0;
        }
        FUN_80247054(-0x7fc57058);
      }
      local_38[0][3] = piVar1[1];
      FUN_80244758((int *)&DAT_803a7f68,local_38[0],1);
      FUN_80243e74();
      DAT_803a6a90 = DAT_803a6a90 + 1;
      FUN_80243e9c();
      DAT_803de318 = 0;
    }
    iVar3 = iVar3 + *piVar4;
    piVar4 = piVar4 + 1;
    puVar2 = puVar2 + 1;
  }
  if (DAT_803de314 != 0) {
    FUN_80118e30(1);
    DAT_803de314 = 0;
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80119b88
 * EN v1.0 Address: 0x80119A90
 * EN v1.0 Size: 364b
 * EN v1.1 Address: 0x80119B88
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80119b88(void)
{
  int iVar1;
  
  iVar1 = 0;
  do {
    if (DAT_803a6a5f != '\0') {
      while (DAT_803a6a90 < 0) {
        FUN_80243e74();
        DAT_803a6a90 = DAT_803a6a90 + 1;
        FUN_80243e9c();
        if (((iVar1 + DAT_803a6a78) - ((uint)(iVar1 + DAT_803a6a78) / DAT_803a6a10) * DAT_803a6a10
             == DAT_803a6a10 - 1) && ((DAT_803a6a5e & 1) == 0)) break;
        iVar1 = iVar1 + 1;
      }
    }
    FUN_80119a40();
    if (((iVar1 + DAT_803a6a78) - ((uint)(iVar1 + DAT_803a6a78) / DAT_803a6a10) * DAT_803a6a10 ==
         DAT_803a6a10 - 1) && ((DAT_803a6a5e & 1) == 0)) {
      FUN_80247054(-0x7fc57058);
    }
    iVar1 = iVar1 + 1;
  } while( true );
}
