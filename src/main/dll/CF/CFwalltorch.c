#include "ghidra_import.h"
#include "main/dll/CF/CFwalltorch.h"

extern undefined8 FUN_80008b74();
extern undefined8 FUN_8000bb38();
extern undefined8 FUN_800201ac();
extern undefined4 FUN_80043070();
extern undefined8 FUN_8004312c();
extern undefined8 FUN_8004316c();
extern undefined4 FUN_80043604();
extern undefined4 FUN_80043658();
extern int FUN_8004832c();
extern undefined4 FUN_8005517c();
extern undefined8 FUN_80055464();
extern undefined8 FUN_8005d06c();
extern undefined4 FUN_80088f20();
extern undefined8 FUN_800890e0();
extern undefined4 FUN_801909a8();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4* DAT_803dd72c;
extern f32 FLOAT_803e4b30;

/*
 * --INFO--
 *
 * Function: FUN_80191150
 * EN v1.0 Address: 0x80190BD4
 * EN v1.0 Size: 4684b
 * EN v1.1 Address: 0x80191150
 * EN v1.1 Size: 2252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80191150(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  
  uVar1 = FUN_80286840();
  iVar6 = *(int *)(uVar1 + 0x4c);
  iVar5 = *(int *)(uVar1 + 0xb8);
  iVar7 = 0;
  iVar4 = param_11;
  uVar8 = extraout_f1;
  do {
    if ((int)(uint)*(byte *)(param_11 + 0x8b) <= iVar7) {
      FUN_801909a8(uVar1);
      FUN_8028688c();
      return;
    }
    switch(*(undefined *)(param_11 + iVar7 + 0x81)) {
    case 1:
      if (*(int *)(iVar6 + 0x14) == 0x47064) {
        uVar8 = FUN_8004312c();
      }
      uVar8 = FUN_80055464(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (int)*(char *)(iVar6 + 0x1a),'\0',iVar4,param_12,param_13,param_14,
                           param_15,param_16);
      break;
    case 2:
      iVar4 = *(int *)(iVar6 + 0x14);
      if (iVar4 == 0x48018) {
        iVar4 = FUN_8004832c(0x22);
        FUN_80043604(iVar4,1,0);
        FUN_800201ac(0x36a,0);
        (**(code **)(*DAT_803dd72c + 0x50))(0xd,0,1);
        (**(code **)(*DAT_803dd72c + 0x50))(0xd,1,1);
        (**(code **)(*DAT_803dd72c + 0x50))(0xd,5,1);
        (**(code **)(*DAT_803dd72c + 0x50))(0xd,10,1);
        iVar4 = 1;
        param_12 = *DAT_803dd72c;
        (**(code **)(param_12 + 0x50))(0xd,0xb);
        uVar8 = FUN_800201ac(0xe05,0);
      }
      else if (iVar4 < 0x48018) {
        if (iVar4 == 0x45dd6) {
          iVar4 = 1;
          FUN_80043604(0,0,1);
          uVar2 = FUN_8004832c(4);
          FUN_80043658(uVar2,0);
        }
        else if (iVar4 < 0x45dd6) {
          if (iVar4 == 0x2ba7) {
            iVar4 = 1;
            FUN_80043604(0,0,1);
            uVar2 = FUN_8004832c(0x12);
            FUN_80043658(uVar2,0);
            uVar2 = FUN_8004832c(0x1f);
            FUN_80043658(uVar2,1);
            FUN_80043070(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1f);
          }
          else if (iVar4 < 0x2ba7) {
            if (iVar4 == 0xc5d) {
              iVar3 = FUN_8004832c(0x21);
              iVar4 = 0;
              FUN_80043604(iVar3,1,0);
            }
          }
          else if (iVar4 == 0x43f83) {
            FUN_80043070(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x21);
            uVar2 = FUN_8004832c(0x21);
            FUN_80043658(uVar2,1);
          }
        }
        else if (iVar4 == 0x47064) {
          FUN_80043070(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1c);
          uVar2 = FUN_8004832c(0x1c);
          FUN_80043658(uVar2,1);
          uVar2 = FUN_8004832c(0x1b);
          FUN_80043658(uVar2,0);
        }
        else if (iVar4 < 0x47064) {
          if (iVar4 == 0x46a40) {
            iVar4 = 1;
            FUN_80043604(0,0,1);
            uVar2 = FUN_8004832c(0xe);
            FUN_80043658(uVar2,0);
            uVar2 = FUN_8004832c(0x20);
            FUN_80043658(uVar2,1);
            FUN_80043070(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x20);
          }
        }
        else if (iVar4 == 0x4800c) {
          FUN_80043070(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x22);
          uVar2 = FUN_8004832c(0xd);
          FUN_80043658(uVar2,0);
          uVar2 = FUN_8004832c(0x22);
          FUN_80043658(uVar2,1);
        }
      }
      else if (iVar4 == 0x49c33) {
        FUN_800201ac(0x884,1);
        (**(code **)(*DAT_803dd72c + 0x50))(7,0,1);
        (**(code **)(*DAT_803dd72c + 0x50))(7,2,1);
        (**(code **)(*DAT_803dd72c + 0x50))(7,3,1);
        (**(code **)(*DAT_803dd72c + 0x50))(7,7,1);
        (**(code **)(*DAT_803dd72c + 0x50))(7,10,1);
        param_12 = *DAT_803dd72c;
        uVar8 = (**(code **)(param_12 + 0x50))(10,7,0);
LAB_80191384:
        FUN_80043070(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,7);
        iVar4 = 1;
        FUN_80043604(0,0,1);
        uVar2 = FUN_8004832c(7);
        FUN_80043658(uVar2,1);
      }
      else if (iVar4 < 0x49c33) {
        if (iVar4 == 0x4977d) goto LAB_80191384;
        if (iVar4 < 0x4977d) {
          if (iVar4 == 0x48506) goto LAB_80191384;
        }
        else if (iVar4 == 0x497f4) {
          iVar4 = 1;
          FUN_80043604(0,0,1);
          uVar2 = FUN_8004832c(10);
          FUN_80043658(uVar2,0);
          uVar2 = FUN_8004832c(0x27);
          FUN_80043658(uVar2,1);
          FUN_80043070(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x27);
        }
      }
      else if (iVar4 == 0x4b666) {
        iVar4 = 1;
        FUN_80043604(0,0,1);
        uVar2 = FUN_8004832c(0x32);
        FUN_80043658(uVar2,0);
        uVar2 = FUN_8004832c(0x15);
        FUN_80043658(uVar2,1);
        FUN_80043070(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x15);
      }
      else if (iVar4 < 0x4b666) {
        if (iVar4 == 0x4a533) {
          FUN_80043070(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x28);
          uVar2 = FUN_8004832c(0x28);
          FUN_80043658(uVar2,1);
        }
      }
      else if (iVar4 == 0x4cde6) {
        iVar4 = 1;
        FUN_80043604(0,0,1);
        uVar2 = FUN_8004832c(10);
        FUN_80043658(uVar2,0);
      }
      break;
    case 3:
      if (*(int *)(iVar6 + 0x14) == 0x47064) {
        iVar4 = 1;
        FUN_80043604(0,0,1);
      }
      break;
    case 5:
      if (*(int *)(iVar6 + 0x14) == 0x47064) {
        uVar8 = FUN_8004316c();
      }
      break;
    case 6:
      if (*(int *)(iVar6 + 0x14) == 0x47064) {
        uVar8 = FUN_8004312c();
      }
      break;
    case 7:
      *(byte *)(iVar5 + 0xe) = *(byte *)(iVar5 + 0xe) | 4;
      uVar8 = FUN_8000bb38(uVar1,0x420);
      break;
    case 8:
      iVar3 = *(int *)(iVar6 + 0x14);
      if (iVar3 == 0x4977d) {
LAB_801917b8:
        uVar8 = FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                             uVar1,0x224,0,param_13,param_14,param_15,param_16);
        uVar8 = FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                             uVar1,0x223,0,param_13,param_14,param_15,param_16);
        uVar8 = FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                             uVar1,0x22e,0,param_13,param_14,param_15,param_16);
        iVar4 = 0x218;
        param_12 = 0;
        FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1,0x218
                     ,0,param_13,param_14,param_15,param_16);
        FUN_8005d06c(0);
        FUN_80088f20(1,'\x01');
        uVar8 = FUN_800890e0((double)FLOAT_803e4b30,0);
      }
      else if (iVar3 < 0x4977d) {
        if (iVar3 == 0x4827e) {
LAB_80191960:
          uVar8 = FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                               uVar1,0x247,0,param_13,param_14,param_15,param_16);
          iVar4 = 0x248;
          param_12 = 0;
          FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1,
                       0x248,0,param_13,param_14,param_15,param_16);
          FUN_8005517c();
          uVar8 = FUN_800201ac(0xef6,1);
        }
        else if (iVar3 < 0x4827e) {
          if (iVar3 == 0x4670d) goto LAB_80191960;
          if ((iVar3 < 0x4670d) && (iVar3 == 0x43f83)) goto LAB_801917b8;
        }
        else {
          if (iVar3 == 0x49267) goto LAB_80191960;
          if ((iVar3 < 0x49267) && (iVar3 == 0x48506)) goto LAB_8019182c;
        }
      }
      else if (iVar3 == 0x4b667) {
        uVar8 = FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                             uVar1,0x23a,0,param_13,param_14,param_15,param_16);
        FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1,0x23b
                     ,0,param_13,param_14,param_15,param_16);
        uVar8 = (**(code **)(*DAT_803dd72c + 0x50))(0x15,2,1);
        iVar4 = 0x23e;
        param_12 = 0;
        FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x23e,0,
                     param_13,param_14,param_15,param_16);
        uVar8 = FUN_800890e0((double)FLOAT_803e4b30,1);
      }
      else if (iVar3 < 0x4b667) {
        if (iVar3 == 0x4a533) {
LAB_8019182c:
          uVar8 = FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                               uVar1,0x217,0,param_13,param_14,param_15,param_16);
          uVar8 = FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                               uVar1,0x216,0,param_13,param_14,param_15,param_16);
          uVar8 = FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                               uVar1,0x22e,0,param_13,param_14,param_15,param_16);
          FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1,
                       0x218,0,param_13,param_14,param_15,param_16);
          uVar8 = FUN_8005d06c(1);
          uVar8 = FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                               uVar1,0x84,0,param_13,param_14,param_15,param_16);
          iVar4 = 0x8a;
          param_12 = 0;
          FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1,
                       0x8a,0,param_13,param_14,param_15,param_16);
          FUN_80088f20(1,'\0');
          uVar8 = FUN_800890e0((double)FLOAT_803e4b30,0);
        }
        else if ((0x4a532 < iVar3) && (0x4b665 < iVar3)) {
          uVar8 = FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                               uVar1,0x23a,0,param_13,param_14,param_15,param_16);
          iVar4 = 0x23b;
          param_12 = 0;
          uVar8 = FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                               uVar1,0x23b,0,param_13,param_14,param_15,param_16);
        }
      }
      else {
        if (iVar3 != 0x4cb84) {
          if ((0x4cb83 < iVar3) || (iVar3 != 0x4cb6a)) break;
          uVar8 = FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                               uVar1,0x238,0,param_13,param_14,param_15,param_16);
          iVar4 = 0x239;
          param_12 = 0;
          FUN_80008b74(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1,
                       0x239,0,param_13,param_14,param_15,param_16);
          FUN_80088f20(1,'\x01');
          FUN_800890e0((double)FLOAT_803e4b30,0);
        }
        uVar8 = FUN_800201ac(0xef6,0);
      }
    }
    iVar7 = iVar7 + 1;
  } while( true );
}
