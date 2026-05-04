#include "ghidra_import.h"
#include "main/dll/CAM/camlockon.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_800068f8();
extern undefined4 FUN_80006a10();
extern double FUN_80006a30();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern undefined8 FUN_802860cc();
extern void FUN_80286118();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_8028688c();

extern undefined4* DAT_803dd6d0;
extern undefined4 gCamcontrolModeSettings;
extern undefined4 gCamcontrolPathState;
extern f32 lbl_803E23C0;
extern f32 lbl_803E23C4;
extern f32 lbl_803E23C8;

/*
 * --INFO--
 *
 * Function: camcontrol_releaseModeSettings
 * EN v1.0 Address: 0x8010684C
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80106888
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_releaseModeSettings(void)
{
  FUN_80017814(gCamcontrolModeSettings);
  gCamcontrolModeSettings = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: camcontrol_initialiseModeSettings
 * EN v1.0 Address: 0x80106878
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801068B4
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_initialiseModeSettings(void)
{
  gCamcontrolModeSettings = FUN_80017830(0xcc,0xf);
  FUN_800033a8(gCamcontrolModeSettings,0,0xcc);
  return;
}

/*
 * --INFO--
 *
 * Function: camcontrol_samplePathState
 * EN v1.0 Address: 0x801068B0
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x801068F0
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_samplePathState(undefined4 param_1,undefined4 param_2,undefined4 *param_3,
                                undefined4 param_4,int param_5)
{
  int iVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  undefined8 uVar5;
  undefined auStack_168 [12];
  float local_15c;
  float local_158;
  float local_154;
  float fStack_150;
  float fStack_14c;
  float afStack_148 [4];
  int local_138;
  undefined4 local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float fStack_b0;
  float fStack_ac;
  float afStack_a8 [42];
  
  uVar5 = FUN_80286840();
  FUN_800033a8((int)auStack_168,0,0x144);
  local_138 = *(int *)(param_5 + 0x30);
  iVar1 = gCamcontrolPathState + *(int *)(gCamcontrolPathState + 0x1b0) * 4;
  local_15c = *(float *)(iVar1 + 0x14);
  local_158 = *(float *)uVar5;
  local_154 = *(float *)(iVar1 + 0xb4);
  local_c0 = local_15c;
  local_bc = local_158;
  local_b8 = local_154;
  FUN_800068f8((double)local_15c,(double)local_158,(double)local_154,&fStack_b0,&fStack_ac,
               afStack_a8,local_138);
  local_c4 = param_4;
  iVar1 = (**(code **)(*DAT_803dd6d0 + 0x18))();
  (**(code **)(**(int **)(iVar1 + 4) + 0x14))(auStack_168,param_4);
  FUN_800068f8((double)local_15c,(double)local_158,(double)local_154,&fStack_150,&fStack_14c,
               afStack_148,local_138);
  (**(code **)(**(int **)(iVar1 + 4) + 0x24))
            (auStack_168,1,3,gCamcontrolPathState + 0x14,gCamcontrolPathState + 0x18);
  iVar2 = *(int *)(gCamcontrolPathState + 0x1b0) + -3;
  iVar1 = iVar2 * 4;
  for (; iVar2 < *(int *)(gCamcontrolPathState + 0x1b0); iVar2 = iVar2 + 1) {
    *(float *)(gCamcontrolPathState + iVar1 + 0x1c) = local_15c;
    *(float *)(gCamcontrolPathState + iVar1 + 0xbc) = local_154;
    iVar1 = iVar1 + 4;
  }
  dVar3 = (double)lbl_803E23C0;
  if (dVar3 != (double)*(float *)(gCamcontrolPathState + 300)) {
    dVar3 = (double)(float)((double)*(float *)(gCamcontrolPathState + 0x128) /
                           (double)*(float *)(gCamcontrolPathState + 300));
  }
  dVar4 = (double)lbl_803E23C4;
  if ((dVar3 <= dVar4) && (dVar4 = dVar3, dVar3 < (double)lbl_803E23C0)) {
    dVar4 = (double)lbl_803E23C0;
  }
  dVar3 = FUN_80006a30(dVar4,(float *)(gCamcontrolPathState + 0x10c),(float *)0x0);
  if (dVar3 < (double)lbl_803E23C8) {
    dVar3 = (double)lbl_803E23C8;
  }
  FUN_80006a10(dVar3,(float *)(gCamcontrolPathState + 0x120));
  *(undefined4 *)((ulonglong)uVar5 >> 0x20) = *(undefined4 *)(gCamcontrolPathState + 0x188);
  *param_3 = *(undefined4 *)(gCamcontrolPathState + 400);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: camcontrol_buildPathAngles
 * EN v1.0 Address: 0x80106AC4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80106AE8
 * EN v1.1 Size: 1336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_buildPathAngles(undefined4 param_1,undefined4 param_2,short param_3,short param_4,
                                undefined4 param_5)
{
  ushort uVar1;
  int iVar2;
  ushort *puVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  short sVar7;
  short sVar8;
  undefined8 uVar9;

  uVar9 = FUN_802860cc();
  iVar2 = (int)((ulonglong)uVar9 >> 0x20);
  puVar3 = (ushort *)uVar9;
  sVar5 = (short)param_5;
  if (param_4 < sVar5) {
    uVar1 = *puVar3;
    *puVar3 = uVar1 + 1;
    *(short *)(iVar2 + (uint)uVar1 * 2) = param_3;
  }
  else {
    sVar8 = param_4 >> 1;
    sVar7 = param_4 >> 2;
    sVar6 = param_4 >> 3;
    param_4 = param_4 >> 4;
    if (sVar8 < sVar5) {
      uVar1 = *puVar3;
      *puVar3 = uVar1 + 1;
      *(short *)(iVar2 + (uint)uVar1 * 2) = param_3;
    }
    else {
      if (sVar7 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3;
      }
      else if (sVar6 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3;
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar6;
      }
      else {
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,param_3,param_4,param_5);
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)(short)(param_3 + param_4),
                                   (int)param_4,param_5);
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)(short)(param_3 + sVar6),
                                   (int)param_4,param_5);
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)(short)(param_3 + sVar6 + param_4),
                                   (int)param_4,param_5);
      }
      if (sVar7 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar7;
      }
      else if (sVar6 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar7;
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar7 + sVar6;
      }
      else {
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)(short)(param_3 + sVar7),
                                   (int)param_4,param_5);
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)(short)(param_3 + sVar7 + param_4),
                                   (int)param_4,param_5);
        sVar4 = param_3 + sVar7 + sVar6;
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)sVar4,(int)param_4,param_5);
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)(short)(sVar4 + param_4),
                                   (int)param_4,param_5);
      }
    }
    if (sVar8 < sVar5) {
      uVar1 = *puVar3;
      *puVar3 = uVar1 + 1;
      *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8;
    }
    else {
      if (sVar7 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8;
      }
      else if (sVar6 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8;
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8 + sVar6;
      }
      else {
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)(short)(param_3 + sVar8),
                                   (int)param_4,param_5);
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)(short)(param_3 + sVar8 + param_4),
                                   (int)param_4,param_5);
        sVar4 = param_3 + sVar8 + sVar6;
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)sVar4,(int)param_4,param_5);
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)(short)(sVar4 + param_4),
                                   (int)param_4,param_5);
      }
      if (sVar7 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8 + sVar7;
      }
      else if (sVar6 < sVar5) {
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8 + sVar7;
        uVar1 = *puVar3;
        *puVar3 = uVar1 + 1;
        *(short *)(iVar2 + (uint)uVar1 * 2) = param_3 + sVar8 + sVar7 + sVar6;
      }
      else {
        sVar5 = param_3 + sVar8 + sVar7;
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)sVar5,(int)param_4,param_5);
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)(short)(sVar5 + param_4),
                                   (int)param_4,param_5);
        sVar6 = param_3 + sVar8 + sVar7 + sVar6;
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)sVar6,(int)param_4,param_5);
        camcontrol_buildPathAngles(iVar2,(undefined4)puVar3,(int)(short)(sVar6 + param_4),
                                   (int)param_4,param_5);
      }
    }
  }
  FUN_80286118();
  return;
}
