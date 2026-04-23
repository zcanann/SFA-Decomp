#include "ghidra_import.h"
#include "main/dll/FRONT/n_filemenu.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_80014974();
extern undefined4 FUN_80014b68();
extern undefined4 FUN_80014b84();
extern undefined4 FUN_80014b94();
extern undefined4 FUN_80014ba4();
extern uint FUN_80014e9c();
extern undefined4 FUN_8001b4f8();
extern undefined4 FUN_8001ffa8();
extern undefined4 FUN_800238f8();
extern undefined4 FUN_80043938();
extern undefined4 FUN_8005cf50();
extern undefined4 FUN_8005cf74();
extern undefined4 FUN_8005d024();
extern undefined4 FUN_8007dadc();
extern undefined4 FUN_8007de80();
extern void gameplay_applyPreviewSettings();
extern int FUN_800e878c();
extern undefined4 FUN_800e88f0();
extern double FUN_80111880();
extern undefined4 FUN_801163b8();
extern undefined4 FUN_801164c0();
extern undefined4 FUN_80117e10();
extern undefined4 FUN_801307d4();
extern undefined4 FUN_801307dc();
extern undefined4 FUN_80134d50();
extern char FUN_80134f44();
extern undefined4 FUN_80134fb0();
extern undefined4 FUN_801350c8();
extern undefined4 FUN_80135ba8();
extern undefined4 FUN_80135e18();
extern undefined4 FUN_80136c2c();
extern undefined4 FUN_80136c4c();
extern undefined8 FUN_80136c5c();

extern undefined4 DAT_8031ae64;
extern undefined4 DAT_8031ae7a;
extern undefined4 DAT_8031aeb6;
extern undefined4 DAT_8031aef2;
extern undefined4 DAT_8031af2e;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc084;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd720;
extern undefined4 DAT_803de288;
extern undefined4 DAT_803de28c;
extern undefined4 DAT_803de28d;
extern undefined4 DAT_803de28e;
extern undefined4 DAT_803de28f;
extern undefined4 DAT_803de290;
extern undefined4 DAT_803de291;
extern undefined4 DAT_803de294;
extern undefined4 DAT_803de298;
extern undefined4 DAT_803de2c8;
extern undefined4 DAT_803de2cc;
extern undefined4 DAT_803de2cd;
extern undefined4 DAT_803de2ce;
extern undefined4 DAT_803de2cf;
extern undefined4 DAT_803de2d0;
extern undefined4 DAT_803de2d1;
extern undefined4 DAT_803de2d2;
extern undefined4 DAT_803de300;
extern undefined4 DAT_803de318;
extern undefined4 DAT_803de378;
extern f64 DOUBLE_803e29a0;
extern f32 FLOAT_803e2990;
extern f32 FLOAT_803e2994;
extern f32 FLOAT_803e2998;
extern f32 FLOAT_803e29a8;

/*
 * --INFO--
 *
 * Function: FUN_80116858
 * EN v1.0 Address: 0x80116858
 * EN v1.0 Size: 268b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80116858(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9)
{
  char cVar2;
  int iVar1;
  undefined8 extraout_f1;
  double dVar3;
  double dVar4;
  
  cVar2 = FUN_80134f44();
  if (cVar2 == '\0') {
    iVar1 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if (iVar1 == 0x57) {
      FUN_8001b4f8(FUN_80135e18);
      dVar4 = (double)FLOAT_803e2998;
      FUN_80135ba8((double)(FLOAT_803e2990 +
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)DAT_803de28e * 0x1a4 ^ 0x80000000) -
                                  DOUBLE_803e29a0) / FLOAT_803e2994),dVar4);
      FUN_801350c8(0,0,0);
      (**(code **)(*DAT_803dd6cc + 0x18))();
      (**(code **)(*DAT_803dd720 + 0x30))(0xff);
      (**(code **)(*DAT_803dd720 + 0x10))(param_9);
      dVar3 = (double)FUN_8001b4f8(0);
      FUN_80134fb0(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803de2cf);
    }
  }
  else {
    FUN_80134d50(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80116964
 * EN v1.0 Address: 0x80116964
 * EN v1.0 Size: 2136b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80116964(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                undefined4 param_13,undefined4 param_14,uint param_15,uint param_16)
{
  bool bVar1;
  char cVar2;
  int iVar3;
  undefined4 uVar4;
  char cVar7;
  uint uVar5;
  int iVar6;
  undefined4 extraout_r4;
  byte bVar8;
  undefined8 uVar9;
  undefined8 extraout_f1;
  double dVar10;
  char local_18;
  char local_17 [11];
  
  cVar2 = DAT_803de2d1;
  bVar8 = DAT_803dc070;
  if (DAT_803dc084 == -2) {
    iVar3 = FUN_800e878c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if ((iVar3 == 0) && (DAT_803dc084 != '\0')) {
      FUN_8007de80(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,'\x01',param_10,
                   param_11,param_12,param_13,param_14,param_15,param_16);
    }
    gameplay_applyPreviewSettings(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (DAT_803dc084 == -2) {
      DAT_803dc084 = '\x01';
    }
  }
  if ((DAT_803de298 == '\0') && (DAT_803de2c8 == 0)) {
    FUN_801163b8();
    FUN_80014974(1);
    FUN_8001ffa8();
    uVar9 = FUN_80136c5c();
    uVar4 = FUN_800238f8(0);
    FUN_80043938(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_800238f8(uVar4);
    FUN_800e88f0();
    iVar3 = 0;
  }
  else {
    FUN_8005d024(0);
    FUN_8005cf74(0);
    cVar7 = FUN_80134f44();
    if (cVar7 == '\0') {
      if (DAT_803de2c8 != 0) {
        DAT_803de2c8 = DAT_803de2c8 + -1;
      }
      if (DAT_803de291 != '\0') {
        FUN_801164c0(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      if (((DAT_803de2cd != '\0') && (DAT_803de2cd = DAT_803de2cd + -1, DAT_803de2cd == '\0')) &&
         (DAT_803de2cf != '\0')) {
        FUN_80117e10(100,1000);
      }
      if ((DAT_803de288 == 2) && (DAT_803de318 = DAT_803de318 + 1, 10 < DAT_803de318)) {
        FUN_801163b8();
      }
      if (((DAT_803de288 == 2) && (DAT_803de2cf != '\0')) && (DAT_803de2ce != '\0')) {
        uVar5 = FUN_80014e9c(0);
        FUN_80014ba4(0,local_17,&local_18);
        FUN_80014b68(0,uVar5);
        FUN_80014b94(0);
        FUN_80014b84(0);
        bVar1 = false;
        if ((DAT_803de300 == '\0') || (DAT_803de2c8 != 0)) {
          if ((uVar5 != 0) || ((local_17[0] != '\0' || (local_18 != '\0')))) {
            bVar1 = true;
          }
        }
        else {
          bVar1 = true;
        }
        if (DAT_803de300 != '\0') {
          DAT_803de300 = '\0';
        }
        if (bVar1) {
          if (((uVar5 == 0) && (local_17[0] == '\0')) && (local_18 == '\0')) {
            DAT_803de2cc = '\x01';
            DAT_803de2c8 = 0x3c;
          }
          else {
            DAT_803de2cc = '\x02';
          }
          (**(code **)(*DAT_803dd720 + 0x18))(0);
          DAT_803de2cf = '\0';
          iVar3 = *DAT_803dd6d0;
          uVar9 = (**(code **)(iVar3 + 0x60))(0,1);
          if (DAT_803dc084 == -1) {
            uVar4 = extraout_r4;
            iVar6 = FUN_800e878c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            if ((iVar6 == 0) && (DAT_803dc084 != '\0')) {
              FUN_8007de80(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,'\x01',
                           uVar4,iVar3,param_12,param_13,param_14,param_15,param_16);
            }
            gameplay_applyPreviewSettings(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,
                                          param_8);
            if (DAT_803dc084 == -1) {
              DAT_803dc084 = '\x01';
            }
          }
        }
      }
      else if ((DAT_803de2ce != '\0') && (DAT_803de2cf == '\0')) {
        uVar5 = FUN_80014e9c(0);
        FUN_80014ba4(0,local_17,&local_18);
        if ((uVar5 == 0) && ((local_17[0] == '\0' && (local_18 == '\0')))) {
          if ((DAT_803de300 != '\0') && (DAT_803de300 = '\0', DAT_803de2c8 == 0)) {
            DAT_803de2c8 = 0x3c;
            DAT_803de2cc = DAT_803de2cc + -1;
            if (DAT_803de2cc == '\0') {
              DAT_803de2cc = '\x01';
              (**(code **)(*DAT_803dd6d0 + 0x60))(4,1);
              DAT_803de2cf = '\x01';
              DAT_803de28f = -0x19;
            }
          }
        }
        else {
          DAT_803de2cc = '\x02';
        }
      }
      if (3 < bVar8) {
        bVar8 = 3;
      }
      if ('\0' < DAT_803de2d1) {
        DAT_803de2d1 = DAT_803de2d1 - bVar8;
      }
      iVar3 = (**(code **)(*DAT_803dd6d0 + 0x10))();
      if (iVar3 == 0x57) {
        DAT_803de2ce = '\x01';
        if (DAT_803de2d0 == '\0') {
          iVar3 = (**(code **)(*DAT_803dd720 + 0xc))();
          DAT_803de28c = (**(code **)(*DAT_803dd720 + 0x14))();
          dVar10 = FUN_80111880();
          if ((((double)FLOAT_803e29a8 == dVar10) && (DAT_803de28e < 0xff)) &&
             (DAT_803de2cf == '\0')) {
            DAT_803de28f = '\x19';
            if (DAT_803de28c == 0) {
              DAT_803de290 = 1;
            }
            else {
              DAT_803de290 = 0;
            }
          }
          else if (DAT_803de28d != DAT_803de28c) {
            (**(code **)(*DAT_803dd6d0 + 0x60))(DAT_803de28c,1);
            FUN_8000bb38(0,0x37b);
            DAT_803de28f = -0x19;
            DAT_803de28d = DAT_803de28c;
            FUN_801307d4(0);
          }
          if ((int)((uint)DAT_803de28e + (int)DAT_803de28f) < 0xff) {
            if ((int)((uint)DAT_803de28e + (int)DAT_803de28f) < 1) {
              if (DAT_803de28c == 0) {
                DAT_8031ae7a = DAT_8031ae7a & 0xbfff;
              }
              else {
                DAT_8031ae7a = DAT_8031ae7a | 0x4000;
              }
              if (DAT_803de28c == 1) {
                DAT_8031aeb6 = DAT_8031aeb6 & 0xbfff;
              }
              else {
                DAT_8031aeb6 = DAT_8031aeb6 | 0x4000;
              }
              if (DAT_803de28c == 2) {
                DAT_8031aef2 = DAT_8031aef2 & 0xbfff;
              }
              else {
                DAT_8031aef2 = DAT_8031aef2 | 0x4000;
              }
              if (DAT_803de28c == 3) {
                DAT_8031af2e = DAT_8031af2e & 0xbfff;
              }
              else {
                DAT_8031af2e = DAT_8031af2e | 0x4000;
              }
              (**(code **)(*DAT_803dd720 + 0x2c))(&DAT_8031ae64);
              DAT_803de28e = 0;
              DAT_803de28f = '\0';
              if (DAT_803de28c != 0) {
                DAT_803de290 = 0;
              }
            }
            else {
              DAT_803de28e = DAT_803de28e + DAT_803de28f;
            }
          }
          else {
            DAT_803de28e = 0xff;
            DAT_803de28f = '\0';
            FUN_801307d4(1);
          }
          if (DAT_803de2d2 == '\0') {
            if (iVar3 == 1) {
              (**(code **)(*DAT_803dd720 + 8))();
              (**(code **)(*DAT_803dd720 + 4))(&DAT_8031ae64,9,5,0,0,0,0x14,200,0xff,0xff,0xff,0xff)
              ;
              DAT_803de2d2 = '\x01';
            }
          }
          else {
            FUN_80136c4c(DAT_803de28c);
            if (((iVar3 == 1) || (DAT_803de294 == 1)) && (DAT_803de28e == 0xff)) {
              FUN_80136c2c('\x01');
              DAT_803de2d1 = 1;
              FUN_801307d4(1);
              FUN_8000bb38(0,0xff);
              if (DAT_803de28c == 2) {
                DAT_803de2d0 = '\a';
                DAT_803de378 = 1;
              }
              else if (DAT_803de28c < 2) {
                if (DAT_803de28c == 0) {
                  DAT_803de2d0 = '\x05';
                }
                else {
                  DAT_803de2d0 = '\a';
                  DAT_803de378 = 0;
                }
              }
              else if (DAT_803de28c < 4) {
                DAT_803de2d0 = '\a';
                DAT_803de378 = 2;
              }
              return 0;
            }
            FUN_80136c2c('\0');
          }
          iVar3 = 0;
        }
        else {
          if (((cVar2 < '\r') || ('\f' < DAT_803de2d1)) && (DAT_803de2d1 < '\x01')) {
            (**(code **)(*DAT_803dd720 + 8))();
            FUN_8005cf50(0);
            FUN_801307dc();
            FUN_80014974((int)DAT_803de2d0);
          }
          iVar3 = (uint)((uint)(int)DAT_803de2d1 < 0xd) - ((int)DAT_803de2d1 >> 0x1f);
        }
      }
      else {
        DAT_803de2ce = '\0';
        iVar3 = 0;
      }
    }
    else {
      iVar3 = 0;
    }
  }
  return iVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_801171bc
 * EN v1.0 Address: 0x801171BC
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801171bc(void)
{
  FUN_801307dc();
  FUN_801307d4(1);
  FUN_8007dadc('\x01');
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801171ec
 * EN v1.0 Address: 0x801171EC
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801171ec(undefined param_1)
{
  DAT_803de28d = 0xff;
  DAT_803de28c = param_1;
  (**(code **)(*DAT_803dd720 + 0x18))();
  return;
}
