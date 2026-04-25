#include "ghidra_import.h"
#include "main/dll/CF/laser.h"

extern undefined4 FUN_800067bc();
extern undefined8 FUN_800068c4();
extern undefined8 FUN_80006b84();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_80017814();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern undefined8 FUN_80040da0();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined8 FUN_80043030();
extern undefined4 FUN_80044404();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_80080f14();

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd72c;

/*
 * --INFO--
 *
 * Function: laser_update
 * EN v1.0 Address: 0x80209564
 * EN v1.0 Size: 1928b
 * EN v1.1 Address: 0x80209944
 * EN v1.1 Size: 1032b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
laser_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
             undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
             undefined4 param_10,int param_11,int param_12,undefined4 param_13,
             undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  LaserObject *obj;
  char cVar1;
  byte bVar4;
  undefined4 uVar2;
  uint uVar3;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  obj = (LaserObject *)param_9;
  iVar5 = param_11;
  bVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)obj->modeIndex);
  uVar7 = FUN_800068c4(0,0x48b);
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar6 = iVar6 + 1) {
    cVar1 = *(char *)(param_11 + iVar6 + 0x81);
    if (cVar1 == '\x01') {
      uVar7 = FUN_80040da0();
      if (bVar4 == 2) {
        FUN_80041ff8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
        uVar2 = FUN_80044404(0xb);
        FUN_80042bec(uVar2,0);
      }
      else if (bVar4 < 2) {
        (**(code **)(*DAT_803dd72c + 0x50))(7,0,0);
        (**(code **)(*DAT_803dd72c + 0x50))(7,2,0);
        (**(code **)(*DAT_803dd72c + 0x50))(7,3,0);
        (**(code **)(*DAT_803dd72c + 0x50))(7,7,0);
        (**(code **)(*DAT_803dd72c + 0x50))(7,10,0);
        iVar5 = 0;
        param_12 = *DAT_803dd72c;
        (**(code **)(param_12 + 0x50))(10,7);
        uVar7 = FUN_80017698(0x1ed,1);
        FUN_80041ff8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x17);
        uVar2 = FUN_80044404(0x17);
        FUN_80042bec(uVar2,0);
      }
      else if (bVar4 < 4) {
        FUN_80041ff8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,7);
        uVar2 = FUN_80044404(7);
        FUN_80042bec(uVar2,0);
      }
    }
    else if (cVar1 == '\x02') {
      if (bVar4 == 2) {
        FUN_80017698(0x405,0);
        uVar3 = FUN_80017690(0xff);
        if (uVar3 == 0) {
          uVar3 = FUN_80017690(0xbfd);
          if (uVar3 == 0) {
            uVar3 = FUN_80017690(0xc6e);
            if (uVar3 != 0) {
              (**(code **)(*DAT_803dd72c + 0x44))(0xb,4);
              (**(code **)(*DAT_803dd72c + 0x50))(0xb,8,1);
              iVar5 = 1;
              param_12 = *DAT_803dd72c;
              uVar7 = (**(code **)(param_12 + 0x50))(0xb,9);
              FUN_80053c98(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x22,'\0',
                           iVar5,param_12,param_13,param_14,param_15,param_16);
            }
          }
          else {
            (**(code **)(*DAT_803dd72c + 0x44))(0xb,2);
            (**(code **)(*DAT_803dd72c + 0x50))(0xb,5,1);
            iVar5 = 1;
            param_12 = *DAT_803dd72c;
            uVar7 = (**(code **)(param_12 + 0x50))(0xb,6);
            FUN_80053c98(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x20,'\0',
                         iVar5,param_12,param_13,param_14,param_15,param_16);
          }
        }
        else {
          (**(code **)(*DAT_803dd72c + 0x44))(0xb,3);
          (**(code **)(*DAT_803dd72c + 0x50))(0xb,8,1);
          iVar5 = 1;
          param_12 = *DAT_803dd72c;
          uVar7 = (**(code **)(param_12 + 0x50))(0xb,9);
          FUN_80053c98(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x22,'\0',iVar5
                       ,param_12,param_13,param_14,param_15,param_16);
        }
      }
      else if (bVar4 < 2) {
        FUN_80053c98(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,2,'\0',iVar5,
                     param_12,param_13,param_14,param_15,param_16);
      }
      else if (bVar4 < 4) {
        FUN_80053c98(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xf,'\0',iVar5,
                     param_12,param_13,param_14,param_15,param_16);
      }
      uVar7 = FUN_80006b84(1);
    }
    else if (cVar1 == '\x03') {
      if (bVar4 == 3) {
        FUN_80044404(0xb);
        uVar7 = FUN_80043030(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      else if (bVar4 < 3) {
        FUN_80044404(7);
        uVar7 = FUN_80043030(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: laser_render
 * EN v1.0 Address: 0x80209CEC
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80209D4C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void laser_render(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: laser_release
 * EN v1.0 Address: 0x80209D0C
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80209D74
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void laser_release(undefined4 param_1)
{
  (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
  return;
}

/*
 * --INFO--
 *
 * Function: laser_hitDetect
 * EN v1.0 Address: 0x80209D4C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80209DB0
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void laser_hitDetect(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                     undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                     int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80209d50
 * EN v1.0 Address: 0x80209D50
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80209E58
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209d50(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80209d70
 * EN v1.0 Address: 0x80209D70
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80209E8C
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209d70(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80209d90
 * EN v1.0 Address: 0x80209D90
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80209EB8
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209d90(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80209db0
 * EN v1.0 Address: 0x80209DB0
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80209F00
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209db0(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80209dd0
 * EN v1.0 Address: 0x80209DD0
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80209F30
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209dd0(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80209df0
 * EN v1.0 Address: 0x80209DF0
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80209F5C
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209df0(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: laser_free
 * EN v1.0 Address: 0x80209E10
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80209F98
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void laser_free(int param_1)
{
  LaserObject *obj;
  LaserState *state;
  uint uVar1;
  
  if (param_1 != 0) {
    obj = (LaserObject *)param_1;
    state = obj->state;
    uVar1 = *(uint *)&state->primarySequenceId;
    if (uVar1 != 0) {
      FUN_80017814(uVar1);
      *(uint *)&state->primarySequenceId = 0;
    }
  }
  return;
}
