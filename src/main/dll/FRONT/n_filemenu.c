#include "ghidra_import.h"
#include "main/dll/FRONT/n_filemenu.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b84();
extern undefined4 FUN_80006ba8();
extern undefined4 FUN_80006bac();
extern undefined4 FUN_80006bb0();
extern undefined4 FUN_80006bb4();
extern uint FUN_80006c00();
extern undefined4 FUN_800174d4();
extern undefined4 FUN_8001767c();
extern undefined4 FUN_80017818();
extern undefined4 FUN_80043030();
extern undefined4 FUN_8005d090();
extern undefined4 FUN_8005d0ac();
extern undefined4 FUN_8005d144();
extern undefined4 FUN_800723ac();
extern undefined4 FUN_80072744();
extern void gameplay_applyPreviewSettings();
extern int gameplay_loadPreviewSettings();
extern void gameplay_capturePreviewSettings();
extern double FUN_80110b8c();
extern undefined4 FUN_80116460();
extern undefined4 FUN_8011656c();
extern undefined4 FUN_80117c30();
extern undefined4 FUN_80130728();
extern undefined4 FUN_80130734();
extern undefined4 FUN_80133790();
extern char FUN_801339f8();
extern undefined4 FUN_80133a68();
extern undefined4 FUN_80133c3c();
extern undefined4 FUN_80134830();
extern undefined4 FUN_801348c0();
extern undefined4 FUN_80134b94();
extern undefined4 FUN_80134bb0();
extern undefined8 FUN_80134bc4();

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
 * Function: FUN_801166c8
 * EN v1.0 Address: 0x801166C8
 * EN v1.0 Size: 500b
 * EN v1.1 Address: 0x80116858
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801166c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9)
{
  char cVar2;
  int iVar1;
  undefined8 extraout_f1;
  double dVar3;
  double dVar4;
  
  cVar2 = FUN_801339f8();
  if (cVar2 == '\0') {
    iVar1 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if (iVar1 == 0x57) {
      FUN_800174d4(FUN_801348c0);
      dVar4 = (double)FLOAT_803e2998;
      FUN_80134830((double)(FLOAT_803e2990 +
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)DAT_803de28e * 0x1a4 ^ 0x80000000) -
                                  DOUBLE_803e29a0) / FLOAT_803e2994),dVar4);
      FUN_80133c3c(0,0,0);
      (**(code **)(*DAT_803dd6cc + 0x18))();
      (**(code **)(*DAT_803dd720 + 0x30))(0xff);
      (**(code **)(*DAT_803dd720 + 0x10))(param_9);
      dVar3 = (double)FUN_800174d4(0);
      FUN_80133a68(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803de2cf);
    }
  }
  else {
    FUN_80133790(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801168bc
 * EN v1.0 Address: 0x801168BC
 * EN v1.0 Size: 2604b
 * EN v1.1 Address: 0x80116964
 * EN v1.1 Size: 2136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_801168bc(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
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
    iVar3 = gameplay_loadPreviewSettings(param_1,param_2,param_3,param_4,param_5,param_6,param_7,
                                         param_8);
    if ((iVar3 == 0) && (DAT_803dc084 != '\0')) {
      FUN_80072744(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,'\x01',param_10,
                   param_11,param_12,param_13,param_14,param_15,param_16);
    }
    gameplay_applyPreviewSettings(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (DAT_803dc084 == -2) {
      DAT_803dc084 = '\x01';
    }
  }
  if ((DAT_803de298 == '\0') && (DAT_803de2c8 == 0)) {
    FUN_80116460();
    FUN_80006b84(1);
    FUN_8001767c();
    uVar9 = FUN_80134bc4();
    uVar4 = FUN_80017818(0);
    FUN_80043030(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80017818(uVar4);
    gameplay_capturePreviewSettings();
    iVar3 = 0;
  }
  else {
    FUN_8005d144(0);
    FUN_8005d0ac(0);
    cVar7 = FUN_801339f8();
    if (cVar7 == '\0') {
      if (DAT_803de2c8 != 0) {
        DAT_803de2c8 = DAT_803de2c8 + -1;
      }
      if (DAT_803de291 != '\0') {
        FUN_8011656c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      if (((DAT_803de2cd != '\0') && (DAT_803de2cd = DAT_803de2cd + -1, DAT_803de2cd == '\0')) &&
         (DAT_803de2cf != '\0')) {
        FUN_80117c30(100,1000);
      }
      if ((DAT_803de288 == 2) && (DAT_803de318 = DAT_803de318 + 1, 10 < DAT_803de318)) {
        FUN_80116460();
      }
      if (((DAT_803de288 == 2) && (DAT_803de2cf != '\0')) && (DAT_803de2ce != '\0')) {
        uVar5 = FUN_80006c00(0);
        FUN_80006bb4(0,local_17,&local_18);
        FUN_80006ba8(0,uVar5);
        FUN_80006bb0(0);
        FUN_80006bac(0);
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
            iVar6 = gameplay_loadPreviewSettings(uVar9,param_2,param_3,param_4,param_5,param_6,
                                                 param_7,param_8);
            if ((iVar6 == 0) && (DAT_803dc084 != '\0')) {
              FUN_80072744(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,'\x01',
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
        uVar5 = FUN_80006c00(0);
        FUN_80006bb4(0,local_17,&local_18);
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
          dVar10 = FUN_80110b8c();
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
            FUN_80006824(0,0x37b);
            DAT_803de28f = -0x19;
            DAT_803de28d = DAT_803de28c;
            FUN_80130728(0);
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
            FUN_80130728(1);
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
            FUN_80134bb0(DAT_803de28c);
            if (((iVar3 == 1) || (DAT_803de294 == 1)) && (DAT_803de28e == 0xff)) {
              FUN_80134b94('\x01');
              DAT_803de2d1 = 1;
              FUN_80130728(1);
              FUN_80006824(0,0xff);
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
            FUN_80134b94('\0');
          }
          iVar3 = 0;
        }
        else {
          if (((cVar2 < '\r') || ('\f' < DAT_803de2d1)) && (DAT_803de2d1 < '\x01')) {
            (**(code **)(*DAT_803dd720 + 8))();
            FUN_8005d090(0);
            FUN_80130734();
            FUN_80006b84((int)DAT_803de2d0);
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
 * Function: FUN_801172e8
 * EN v1.0 Address: 0x801172E8
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x801171BC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801172e8(void)
{
  FUN_80130734();
  FUN_80130728(1);
  FUN_800723ac('\x01');
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80117318
 * EN v1.0 Address: 0x80117318
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801171EC
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80117318(undefined param_1)
{
  DAT_803de28d = 0xff;
  DAT_803de28c = param_1;
  (**(code **)(*DAT_803dd720 + 0x18))();
  return;
}

extern void fn_8013046C(void);
extern void fn_80130464(int);
extern void fn_8007D960(int);
#pragma scheduling off
#pragma peephole off
void fn_80116F14(void) {
    fn_8013046C();
    fn_80130464(1);
    fn_8007D960(1);
}
#pragma peephole reset
#pragma scheduling reset

extern u8 lbl_803DD614, lbl_803DD615;
extern undefined4* lbl_803DCAA0;
#pragma scheduling off
#pragma peephole off
void fn_80116F44(int a) {
    u8 v = (u8)a;
    lbl_803DD614 = v;
    lbl_803DD615 = 0xff;
    (*(code *)(*lbl_803DCAA0 + 0x18))(v);
}
#pragma peephole reset
#pragma scheduling reset
