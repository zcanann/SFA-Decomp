#include "ghidra_import.h"
#include "main/dll/dll_13C.h"

extern undefined4 FUN_800067e8();
extern undefined8 FUN_8000680c();
extern undefined4 FUN_80006814();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006920();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_8001753c();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_80017588();
extern undefined4 FUN_80017594();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175ec();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern int FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined8 ObjHits_EnableObject();
extern void ObjHits_SetTargetMask(int obj,undefined mask);
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8005fe14();
extern uint FUN_8007f6c8();
extern undefined4 FUN_8007f718();
extern int FUN_8007f764();
extern int FUN_8007f7c0();
extern undefined4 FUN_80081110();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_80169a44();
extern undefined4 FUN_8020a4ac();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern undefined4 FUN_80247f54();
extern int FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern int Sfx_PlayFromObjectLimited(int obj,int sfxId,int maxCount);
extern void s16toFloat(void *timer,int duration);
extern void storeZeroToFloatParam(void *timer);

extern undefined4 DAT_803dc070;
extern undefined4 *pDll_expgfx;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4 lbl_8032059C[];
extern f64 DOUBLE_803e3d80;
extern f64 DOUBLE_803e3d98;
extern f64 DOUBLE_803e3dc8;
extern f64 DOUBLE_803e3de8;
extern f64 DOUBLE_803e3e20;
extern f64 DOUBLE_803e3e28;
extern f32 lbl_803DC074;
extern f32 lbl_803DC9B0;
extern f32 lbl_803DC9B4;
extern f32 lbl_803E3D78;
extern f32 lbl_803E3D88;
extern f32 lbl_803E3D8C;
extern f32 lbl_803E3D90;
extern f32 lbl_803E3D94;
extern f32 lbl_803E3DA0;
extern f32 lbl_803E3DA4;
extern f32 lbl_803E3DA8;
extern f32 lbl_803E3DAC;
extern f32 lbl_803E3DB0;
extern f32 lbl_803E3DB4;
extern f32 lbl_803E3DB8;
extern f32 lbl_803E3DBC;
extern f32 lbl_803E3DC0;
extern f32 lbl_803E3DC4;
extern f32 lbl_803E3DD0;
extern f32 lbl_803E3DD4;
extern f32 lbl_803E3DD8;
extern f32 lbl_803E3DDC;
extern f32 lbl_803E3DE0;
extern f32 lbl_803E3DF0;
extern f32 lbl_803E3DF4;
extern f32 lbl_803E3DF8;
extern f32 lbl_803E3DFC;
extern f32 lbl_803E3E00;
extern f32 lbl_803E3E04;
extern f32 lbl_803E3E08;
extern f32 lbl_803E3E0C;
extern f32 lbl_803E3E10;
extern f32 lbl_803E3E14;
extern f32 lbl_803E3E18;
extern f64 lbl_803E3190;
extern f32 lbl_803E3198;
extern f32 lbl_803E319C;

/*
 * --INFO--
 *
 * Function: kaldachompspit_render
 * EN v1.0 Address: 0x8016984C
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x80169CF8
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void kaldachompspit_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,
                           undefined4 param_4,undefined4 param_5,char visible)
{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_8028683c();
  iVar2 = **(int **)(iVar1 + 0xb8);
  if (((iVar2 != 0) && (*(char *)(iVar2 + 0x2f8) != '\0')) && (*(char *)(iVar2 + 0x4c) != '\0')) {
    FUN_8005fe14(iVar2);
  }
  if (visible != '\0') {
    FUN_8003b818(iVar1);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80169d38
 * EN v1.0 Address: 0x80169D38
 * EN v1.0 Size: 1300b
 * EN v1.1 Address: 0x80169D94
 * EN v1.1 Size: 988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80169d38(undefined8 param_1,undefined8 param_2,undefined8 param_3,double param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  short sVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  undefined8 uVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 local_48;
  undefined8 local_40;
  
  piVar4 = *(int **)(param_9 + 0x5c);
  local_48 = (double)CONCAT44(0x43300000,*(uint *)(param_9 + 0x7a) ^ 0x80000000);
  *(int *)(param_9 + 0x7a) = (int)((float)(local_48 - DOUBLE_803e3d80) - lbl_803DC074);
  if (*(int *)(param_9 + 0x7a) < 0) {
    uVar5 = FUN_8000680c((int)param_9,0x7f);
    FUN_80017ac8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  else if (*(char *)(param_9 + 0x1b) != '\0') {
    if (*(int *)(param_9 + 0x7a) < 0x11b) {
      *(float *)(param_9 + 0x14) = -(lbl_803E3D88 * lbl_803DC074 - *(float *)(param_9 + 0x14));
      local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_9 + 0x1b));
      param_4 = (double)(lbl_803E3D8C * lbl_803DC074);
      if ((float)((double)(float)(local_40 - DOUBLE_803e3d98) - param_4) <= lbl_803E3D90) {
        FUN_8000680c((int)param_9,0x7f);
        *(undefined *)(param_9 + 0x1b) = 0;
      }
      else {
        local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_9 + 0x1b));
        *(char *)(param_9 + 0x1b) =
             (char)(int)((double)(float)(local_40 - DOUBLE_803e3d98) - param_4);
      }
      FUN_80006814((double)lbl_803E3D94,(int)param_9,0x40,
                   (byte)((int)(uint)*(byte *)(param_9 + 0x1b) >> 1));
    }
    dVar10 = (double)(*(float *)(param_9 + 0x12) * lbl_803DC074);
    dVar8 = (double)(*(float *)(param_9 + 0x14) * lbl_803DC074);
    dVar6 = (double)(*(float *)(param_9 + 0x16) * lbl_803DC074);
    dVar7 = dVar6;
    dVar9 = dVar8;
    FUN_80017a88(dVar10,dVar8,dVar6,(int)param_9);
    if (param_9[0x23] == 0x869) {
      ObjHits_SetHitVolumeSlot((int)param_9,0x1f,1,0);
      *param_9 = *param_9 + 0x100;
      param_9[1] = param_9[1] + 0x800;
    }
    else {
      ObjHits_SetHitVolumeSlot((int)param_9,10,1,0);
      iVar2 = FUN_80017730();
      *param_9 = (short)iVar2 + -0x8000;
      dVar8 = dVar9;
      FUN_80293900((double)(float)(dVar10 * dVar10 + (double)(float)(dVar7 * dVar7)));
      iVar2 = FUN_80017730();
      param_9[1] = 0x4000 - (short)iVar2;
    }
    uVar5 = ObjHits_EnableObject((int)param_9);
    if (*(int *)(*(int *)(param_9 + 0x2a) + 0x50) != 0) {
      if (*(int *)(param_9 + 0x7a) < 0x17c) {
        FUN_80169a44(uVar5,dVar8,dVar6,param_4,param_5,param_6,param_7,param_8,(uint)param_9);
        return;
      }
      iVar2 = FUN_80017a98();
      if ((*(int *)(*(int *)(param_9 + 0x2a) + 0x50) == iVar2) ||
         (iVar2 = FUN_80017a90(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) == iVar2)) {
        FUN_80169a44(uVar5,dVar8,dVar6,param_4,param_5,param_6,param_7,param_8,(uint)param_9);
        return;
      }
    }
    if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) == '\0') {
      if (param_9[0x23] == 0x869) {
        FUN_80081110(param_9,1,0,0,(undefined4 *)0x0);
      }
      else {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x714,0,2,0xffffffff,param_9 + 0x1b);
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x715,0,1,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x715,0,1,0xffffffff,0);
      }
      iVar2 = *piVar4;
      if (((iVar2 != 0) && (*(char *)(iVar2 + 0x2f8) != '\0')) && (*(char *)(iVar2 + 0x4c) != '\0'))
      {
        uVar3 = randomGetRange(0xffffffe7,0x19);
        iVar2 = *piVar4;
        sVar1 = (ushort)*(byte *)(iVar2 + 0x2f9) + (short)*(char *)(iVar2 + 0x2fa) + (short)uVar3;
        if (sVar1 < 0) {
          sVar1 = 0;
          *(undefined *)(iVar2 + 0x2fa) = 0;
        }
        else if (0xff < sVar1) {
          sVar1 = 0xff;
          *(undefined *)(iVar2 + 0x2fa) = 0;
        }
        *(char *)(*piVar4 + 0x2f9) = (char)sVar1;
      }
    }
    else {
      FUN_80169a44(uVar5,dVar8,dVar6,param_4,param_5,param_6,param_7,param_8,(uint)param_9);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: kaldachompspit_init
 * EN v1.0 Address: 0x80169CC4
 * EN v1.0 Size: 552b
 * EN v1.1 Address: 0x8016A170
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void kaldachompspit_init(uint param_1)
{
  uint uVar1;
  int *piVar2;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  *(undefined4 *)(param_1 + 0xf4) = 400;
  ObjHits_DisableObject(param_1);
  *(undefined *)(param_1 + 0x36) = 0xff;
  FUN_80006824(param_1,0x278);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  if (*piVar3 == 0) {
    piVar2 = FUN_80017624(param_1,'\x01');
    *piVar3 = (int)piVar2;
    if (*piVar3 != 0) {
      FUN_800175b0(*piVar3,2);
    }
  }
  if ((int *)*piVar3 != (int *)0x0) {
    dVar4 = (double)lbl_803E3D90;
    dVar5 = dVar4;
    FUN_800175ec(dVar4,dVar4,dVar4,(int *)*piVar3);
    if (*(short *)(param_1 + 0x46) == 0x869) {
      FUN_8001759c(*piVar3,0xff,0xc0,0,0xff);
      FUN_80017588(*piVar3,0xff,0xc0,0,0xff);
      FUN_8001754c((double)(float)((double)lbl_803E3DA0 *
                                  (double)(lbl_803E3DA4 * *(float *)(param_1 + 8))),
                   (double)lbl_803E3DA0,dVar5,in_f4,in_f5,in_f6,in_f7,in_f8,*piVar3,0,0xff,0xc0,0,
                   0x7f,in_r9,in_r10);
      FUN_80017594(*piVar3,0xff,0xd2,0,0xff);
    }
    else {
      FUN_8001759c(*piVar3,0,0xff,0,0xff);
      FUN_80017588(*piVar3,0,0xff,0,0xff);
      FUN_8001754c((double)(lbl_803E3DA4 * *(float *)(param_1 + 8)),dVar4,dVar5,in_f4,in_f5,in_f6,
                   in_f7,in_f8,*piVar3,0,0,0xff,0,0x28,in_r9,in_r10);
      FUN_80017594(*piVar3,0,0xff,0,0xff);
    }
    uVar1 = (uint)(lbl_803E3DA4 * *(float *)(param_1 + 8));
    FUN_800175d0((double)(float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e3d80),
                 (double)(float)((double)CONCAT44(0x43300000,uVar1 + 0x28 ^ 0x80000000) -
                                DOUBLE_803e3d80),*piVar3);
    FUN_800175bc(*piVar3,1);
    FUN_800175cc((double)lbl_803E3D78,*piVar3,'\x01');
    FUN_8001753c(*piVar3,1,3);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016a534
 * EN v1.0 Address: 0x8016A534
 * EN v1.0 Size: 416b
 * EN v1.1 Address: 0x8016A3A0
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8016a534(double param_1,double param_2,float *param_3,float *param_4,char param_5)
{
  int iVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  dVar2 = FUN_80293900((double)((*param_3 - *param_4) * (*param_3 - *param_4) +
                               (param_3[2] - param_4[2]) * (param_3[2] - param_4[2])));
  dVar3 = (double)(param_3[1] - param_4[1]);
  dVar5 = (double)(float)(dVar2 * (double)lbl_803E3DA8);
  dVar2 = (double)(float)((double)(float)((double)lbl_803E3DAC * param_2) * param_2);
  dVar6 = (double)(float)(param_1 * param_1);
  dVar4 = (double)(float)(-(double)(float)(param_2 * dVar3) - dVar6);
  dVar3 = (double)(float)(dVar4 * dVar4 -
                         (double)((float)((double)lbl_803E3DB0 * dVar2) *
                                 (float)(dVar3 * dVar3 + (double)(float)(dVar5 * dVar5))));
  if (dVar3 < (double)lbl_803E3DB4) {
    iVar1 = 0x2000;
  }
  else {
    if (param_5 == '\0') {
      dVar3 = FUN_80293900(dVar3);
      dVar2 = (double)(lbl_803E3DB8 * (float)(-dVar4 - dVar3)) / dVar2;
    }
    else {
      dVar3 = FUN_80293900(dVar3);
      dVar2 = (double)(lbl_803E3DB8 * (float)(-dVar4 + dVar3)) / dVar2;
    }
    dVar2 = FUN_80293900((double)(float)dVar2);
    FUN_80293900(-(double)(float)((double)(float)(dVar5 / dVar2) * (double)(float)(dVar5 / dVar2) -
                                 dVar6));
    iVar1 = FUN_80017730();
  }
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_8016a6d4
 * EN v1.0 Address: 0x8016A6D4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8016A514
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016a6d4(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016a708
 * EN v1.0 Address: 0x8016A708
 * EN v1.0 Size: 904b
 * EN v1.1 Address: 0x8016A54C
 * EN v1.1 Size: 712b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016a708(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  int iVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  int local_58;
  int local_54 [3];
  longlong local_48;
  
  if (0 < (int)*(uint *)(param_9 + 0x7a)) {
    local_54[2] = *(uint *)(param_9 + 0x7a) ^ 0x80000000;
    local_54[1] = 0x43300000;
    dVar2 = (double)(float)((double)CONCAT44(0x43300000,local_54[2]) - DOUBLE_803e3dc8);
    iVar1 = (int)(dVar2 - (double)lbl_803DC074);
    local_48 = (longlong)iVar1;
    *(int *)(param_9 + 0x7a) = iVar1;
    if (*(int *)(param_9 + 0x7a) < 1) {
      FUN_80017ac8(dVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      return;
    }
  }
  if (*(char *)(param_9 + 0x1b) != '\0') {
    dVar5 = (double)(*(float *)(param_9 + 0x12) * lbl_803DC074);
    dVar4 = (double)(*(float *)(param_9 + 0x14) * lbl_803DC074);
    dVar3 = (double)(*(float *)(param_9 + 0x16) * lbl_803DC074);
    dVar2 = dVar3;
    FUN_80017a88(dVar5,dVar4,dVar3,(int)param_9);
    *(float *)(param_9 + 0x14) = lbl_803E3DBC * lbl_803DC074 + *(float *)(param_9 + 0x14);
    if (*(float *)(param_9 + 0x14) < lbl_803E3DC0) {
      *(float *)(param_9 + 0x14) = lbl_803E3DC0;
    }
    iVar1 = FUN_80017730();
    *param_9 = (short)iVar1 + -0x8000;
    FUN_80293900((double)(float)(dVar5 * dVar5 + (double)(float)(dVar2 * dVar2)));
    iVar1 = FUN_80017730();
    param_9[1] = 0x4000 - (short)iVar1;
    ObjHits_SetHitVolumeSlot((int)param_9,10,1,0);
    ObjHits_EnableObject((int)param_9);
    if ((*(int *)(*(int *)(param_9 + 0x2a) + 0x50) == 0) ||
       ((iVar1 = FUN_80017a98(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) != iVar1 &&
        (iVar1 = FUN_80017a90(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) != iVar1)))) {
      if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) == '\0') {
        if ((double)*(float *)(param_9 + 8) < (double)lbl_803E3DC4) {
          FUN_80017ac8((double)*(float *)(param_9 + 8),dVar4,dVar3,param_4,param_5,param_6,param_7,
                       param_8,(int)param_9);
        }
      }
      else {
        *(undefined *)(param_9 + 0x1b) = 0;
        param_9[0x7a] = 0;
        param_9[0x7b] = 0x78;
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
        for (local_58 = 0; local_58 < 0x19; local_58 = local_58 + 1) {
          (**(code **)(*DAT_803dd708 + 8))(param_9,0x715,0,1,0xffffffff,&local_58);
        }
        FUN_80006824((uint)param_9,0x279);
      }
    }
    else {
      *(undefined *)(param_9 + 0x1b) = 0;
      param_9[0x7a] = 0;
      param_9[0x7b] = 0x78;
      *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
      for (local_54[0] = 0; local_54[0] < 0x19; local_54[0] = local_54[0] + 1) {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x715,0,1,0xffffffff,local_54);
      }
      FUN_80006824((uint)param_9,0x279);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016aa90
 * EN v1.0 Address: 0x8016AA90
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x8016A814
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016aa90(uint param_1)
{
  *(undefined4 *)(param_1 + 0xf4) = 0;
  ObjHits_DisableObject(param_1);
  *(undefined *)(param_1 + 0x36) = 0xff;
  FUN_80006824(param_1,0x278);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016aae4
 * EN v1.0 Address: 0x8016AAE4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8016A884
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016aae4(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016ab18
 * EN v1.0 Address: 0x8016AB18
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8016A8B4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016ab18(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016ab40
 * EN v1.0 Address: 0x8016AB40
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x8016A8E4
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016ab40(int param_1)
{
  float fVar1;
  
  if (*(char *)(*(int *)(param_1 + 0x54) + 0xad) != '\0') {
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x3c);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x40);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x44);
    fVar1 = lbl_803E3DD4;
    *(float *)(param_1 + 0x24) = lbl_803E3DD4;
    *(float *)(param_1 + 0x28) = fVar1;
    *(float *)(param_1 + 0x2c) = fVar1;
    *(undefined *)(param_1 + 0x36) = 0;
    ObjHits_DisableObject(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016aba8
 * EN v1.0 Address: 0x8016ABA8
 * EN v1.0 Size: 700b
 * EN v1.1 Address: 0x8016A950
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016aba8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  if (*(short *)(iVar3 + 0x12) == 0) {
    dVar5 = (double)*(float *)(param_9 + 0x28);
    *(float *)(param_9 + 0x28) = -(float)((double)lbl_803E3DD8 * (double)lbl_803DC074 - dVar5);
    dVar4 = (double)lbl_803E3DD4;
    if ((dVar4 <= dVar5) && ((double)*(float *)(param_9 + 0x28) <= dVar4)) {
      FUN_8016ae64(dVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      FUN_80006824(param_9,0xb7);
      *(undefined *)(param_9 + 0x36) = 0;
    }
    param_2 = (double)(*(float *)(param_9 + 0x28) * lbl_803DC074);
    param_3 = (double)(*(float *)(param_9 + 0x2c) * lbl_803DC074);
    FUN_80017a88((double)(*(float *)(param_9 + 0x24) * lbl_803DC074),param_2,param_3,param_9);
    ObjHits_SetHitVolumeSlot(param_9,0x16,1,0);
    ObjHitbox_SetSphereRadius(param_9,7);
    param_1 = ObjHits_EnableObject(param_9);
    if ((*(int *)(*(int *)(param_9 + 0x54) + 0x50) != 0) &&
       ((iVar2 = FUN_80017a98(), *(int *)(*(int *)(param_9 + 0x54) + 0x50) == iVar2 ||
        (iVar2 = FUN_80017a90(), *(int *)(*(int *)(param_9 + 0x54) + 0x50) == iVar2)))) {
      FUN_800069bc();
      FUN_80006920((double)lbl_803E3DD0);
      FUN_80006824(param_9,0xb6);
      *(undefined *)(param_9 + 0x36) = 0;
      *(undefined2 *)(iVar3 + 0x12) = 0x3c;
      param_1 = ObjHits_DisableObject(param_9);
    }
    if (*(char *)(param_9 + 0x36) == -1) {
      iVar2 = 2;
      do {
        param_1 = (**(code **)(*DAT_803dd708 + 8))(param_9,0x4ba,0,1,0xffffffff,0);
        bVar1 = iVar2 != 0;
        iVar2 = iVar2 + -1;
      } while (bVar1);
    }
  }
  else {
    *(short *)(iVar3 + 0x12) = *(short *)(iVar3 + 0x12) + -1;
  }
  if ((*(char *)(param_9 + 0x36) == '\0') && (*(short *)(iVar3 + 0x12) == 0)) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016ae64
 * EN v1.0 Address: 0x8016AE64
 * EN v1.0 Size: 576b
 * EN v1.1 Address: 0x8016AB0C
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016ae64(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)
{
  bool bVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  int iVar5;
  double extraout_f1;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  uVar2 = FUN_80017ae8();
  if ((uVar2 & 0xff) != 0) {
    iVar5 = 5;
    do {
      puVar3 = FUN_80017aa4(0x24,0x482);
      *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
      *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_9 + 0x10);
      *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
      *(undefined *)(puVar3 + 2) = 1;
      *(undefined *)((int)puVar3 + 5) = 1;
      *(undefined *)(puVar3 + 3) = 0xff;
      *(undefined *)((int)puVar3 + 7) = 0xff;
      puVar3 = (undefined2 *)
               FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5
                            ,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
      param_1 = extraout_f1;
      if (puVar3 != (undefined2 *)0x0) {
        puVar3[1] = 0;
        uVar2 = randomGetRange(0,0xffff);
        *puVar3 = (short)uVar2;
        uVar2 = randomGetRange(0xffffffce,0x32);
        *(float *)(puVar3 + 0x12) =
             lbl_803E3DDC *
             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3de8) +
             *(float *)(param_9 + 0x24);
        uVar2 = randomGetRange(0xffffffce,0x32);
        *(float *)(puVar3 + 0x14) =
             lbl_803E3DE0 *
             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3de8) +
             *(float *)(param_9 + 0x28);
        uVar2 = randomGetRange(0xffffffce,0x32);
        param_2 = (double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3de8)
        ;
        param_1 = (double)lbl_803E3DDC;
        *(float *)(puVar3 + 0x16) = (float)(param_1 * param_2 + (double)*(float *)(param_9 + 0x2c));
        *(int *)(puVar3 + 0x62) = param_9;
      }
      bVar1 = iVar5 != 0;
      iVar5 = iVar5 + -1;
    } while (bVar1);
    *(undefined2 *)(iVar4 + 0x12) = 0x3c;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: pollenfragment_init
 * EN v1.0 Address: 0x8016B0A4
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x8016ACA4
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void pollenfragment_init(int obj,int config)
{
  bool keepSpawning;
  byte pollenType;
  uint randomValue;
  int spawnCount;
  undefined4 *state;
  
  state = *(undefined4 **)(obj + 0xb8);
  if (*(char *)(config + 0x19) == '\x01') {
    *(float *)(state + 2) = lbl_803E3198;
  }
  else {
    randomValue = randomGetRange(0xb4,300);
    *(float *)(state + 2) =
        (float)((double)CONCAT44(0x43300000,randomValue ^ 0x80000000) - lbl_803E3190);
  }
  pollenType = *(byte *)(config + 0x19);
  if ((char)pollenType < '\0') {
    pollenType = 0;
  }
  else if (5 < pollenType) {
    pollenType = 5;
  }
  *(byte *)(config + 0x19) = pollenType;
  state[7] = lbl_8032059C[*(char *)(config + 0x19)];
  if ((int)*(short *)state[7] != 0) {
    Sfx_PlayFromObjectLimited(obj,(int)*(short *)state[7] & 0xffff,3);
  }
  spawnCount = 4;
  do {
    (*(code *)(*pDll_expgfx + 8))(obj,(int)*(short *)(state[7] + 6),0,1,0xffffffff,0);
    keepSpawning = spawnCount != 0;
    spawnCount = spawnCount + -1;
  } while (keepSpawning);
  if ((*(byte *)(state[7] + 0x12) >> 6 & 1) == 0) {
    *(float *)(state + 2) = lbl_803E319C;
  }
  ObjHits_SetTargetMask(obj,4);
  state[6] = 0;
  state[1] = *(undefined4 *)(state[7] + 0xc);
  *state = 0;
  s16toFloat(state + 9,0xe10);
  storeZeroToFloatParam(state + 8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016b174
 * EN v1.0 Address: 0x8016B174
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x8016AD9C
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b174(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = *(uint *)(iVar2 + 0x18);
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
    *(undefined4 *)(iVar2 + 0x18) = 0;
  }
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016b1dc
 * EN v1.0 Address: 0x8016B1DC
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8016AE00
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b1dc(void)
{
  int iVar1;
  uint uVar2;
  
  iVar1 = FUN_80286840();
  uVar2 = FUN_8007f6c8((float *)(*(int *)(iVar1 + 0xb8) + 0x20));
  if (uVar2 == 0) {
    FUN_8003b818(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016b228
 * EN v1.0 Address: 0x8016B228
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x8016AE70
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b228(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 auStack_18 [4];
  
  iVar3 = *(int *)(param_9 + 0xb8);
  uVar1 = FUN_8007f6c8((float *)(iVar3 + 0x20));
  if (uVar1 == 0) {
    iVar2 = ObjHits_GetPriorityHit(param_9,auStack_18,(int *)0x0,(uint *)0x0);
    if ((iVar2 == 0xe) || (iVar2 == 0xf)) {
      if (*(short *)(*(int *)(iVar3 + 0x1c) + 4) != -1) {
        FUN_8008112c((double)lbl_803E3DF4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0,1,0,1,0,1,0);
        FUN_800067e8(param_9,*(ushort *)(*(int *)(iVar3 + 0x1c) + 4),3);
      }
      ObjHits_DisableObject(param_9);
      FUN_8007f718((float *)(iVar3 + 0x20),0x78);
    }
    if (*(char *)(*(int *)(param_9 + 0x54) + 0xad) != '\0') {
      ObjHits_DisableObject(param_9);
      *(float *)(iVar3 + 8) = lbl_803E3DF8;
      if (*(short *)(*(int *)(iVar3 + 0x1c) + 4) != -1) {
        FUN_8008112c((double)lbl_803E3DF4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0,1,0,1,0,1,0);
        FUN_800067e8(param_9,*(ushort *)(*(int *)(iVar3 + 0x1c) + 4),3);
      }
      FUN_8007f718((float *)(iVar3 + 0x20),0x78);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016b428
 * EN v1.0 Address: 0x8016B428
 * EN v1.0 Size: 2092b
 * EN v1.1 Address: 0x8016AFBC
 * EN v1.1 Size: 1428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016b428(undefined8 param_1,undefined8 param_2,undefined8 param_3,double param_4,
                 double param_5,double param_6,undefined8 param_7,undefined8 param_8,ushort *param_9
                 )
{
  bool bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  double dVar7;
  double dVar8;
  float local_68;
  float local_64;
  float local_60;
  float afStack_5c [3];
  float local_50;
  float local_4c;
  float local_48;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  piVar5 = *(int **)(param_9 + 0x5c);
  iVar3 = FUN_8007f7c0();
  if (iVar3 == 0) {
    uVar6 = extraout_f1;
    uVar4 = FUN_8007f6c8((float *)(piVar5 + 8));
    if (uVar4 == 0) {
      iVar3 = FUN_8007f764((float *)(piVar5 + 9));
      if (iVar3 != 0) {
        FUN_8007f718((float *)(piVar5 + 8),0x78);
      }
      if (*(int *)(param_9 + 0x62) != 0) {
        *piVar5 = *(int *)(param_9 + 0x62);
        param_9[0x62] = 0;
        param_9[99] = 0;
      }
      if ((*(byte *)(piVar5[7] + 0x12) >> 6 & 1) != 0) {
        piVar5[2] = (int)((float)piVar5[2] - lbl_803DC074);
        dVar7 = (double)(float)piVar5[2];
        if (dVar7 <= (double)lbl_803E3DF8) {
          if (*(char *)(param_9 + 0x1b) == -1) {
            iVar3 = 2;
            do {
              dVar7 = (double)(**(code **)(*DAT_803dd708 + 8))
                                        (param_9,(int)*(short *)(piVar5[7] + 8),0,1,0xffffffff,0);
              bVar1 = iVar3 != 0;
              iVar3 = iVar3 + -1;
            } while (bVar1);
          }
          piVar5[2] = (int)lbl_803E3DF8;
          if ((uint)*(byte *)(param_9 + 0x1b) < (uint)DAT_803dc070 << 3) {
            *(undefined *)(param_9 + 0x1b) = 0;
            FUN_80017ac8(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9)
            ;
            return;
          }
          *(byte *)(param_9 + 0x1b) = *(byte *)(param_9 + 0x1b) - (char)((uint)DAT_803dc070 << 3);
        }
      }
      if (*(short *)(piVar5[7] + 10) != -1) {
        (**(code **)(*DAT_803dd708 + 8))(param_9,(int)*(short *)(piVar5[7] + 10),0,1,0xffffffff,0);
      }
      iVar3 = ObjGroup_FindNearestObject((int)*(short *)(piVar5[7] + 0x10),param_9,(float *)0x0);
      if ((iVar3 != 0) &&
         (((*(byte *)(piVar5[7] + 0x12) >> 6 & 1) == 0 || ((float)piVar5[2] < lbl_803E3DFC)))) {
        if ((*(byte *)(piVar5[7] + 0x12) >> 4 & 1) == 0) {
          local_68 = *(float *)(iVar3 + 0x18);
          local_64 = *(float *)(iVar3 + 0xa8) * *(float *)(iVar3 + 8) * lbl_803E3E00 +
                     *(float *)(iVar3 + 0x1c);
          local_60 = *(float *)(iVar3 + 0x20);
        }
        else {
          ObjPath_GetPointWorldPosition(iVar3,0,&local_68,&local_64,&local_60,0);
        }
        FUN_80247eb8(&local_68,(float *)(param_9 + 0xc),&local_50);
        FUN_80247f54(&local_50);
        FUN_80247ef8(&local_50,&local_50);
        FUN_80247eb8(&local_50,(float *)(piVar5 + 3),afStack_5c);
        piVar5[3] = (int)local_50;
        piVar5[4] = (int)local_4c;
        piVar5[5] = (int)local_48;
        FUN_80247edc((double)lbl_803E3DF4,afStack_5c,afStack_5c);
        FUN_80247e94(&local_50,afStack_5c,&local_50);
        param_6 = (double)lbl_803E3DF4;
        param_5 = (double)lbl_803E3DFC;
        *(float *)(param_9 + 0x12) =
             *(float *)(param_9 + 0x12) +
             (float)((double)((float)(param_6 + (double)(float)piVar5[2]) *
                             local_50 * (float)piVar5[1]) / param_5);
        *(float *)(param_9 + 0x16) =
             *(float *)(param_9 + 0x16) +
             (float)((double)((float)(param_6 + (double)(float)piVar5[2]) *
                             local_48 * (float)piVar5[1]) / param_5);
        if (-1 < *(char *)(piVar5[7] + 0x12)) {
          param_4 = (double)*(float *)(param_9 + 0x14);
          *(float *)(param_9 + 0x14) =
               (float)(param_4 +
                      (double)(float)((double)((float)(param_6 + (double)(float)piVar5[2]) *
                                              lbl_803E3E04 * local_4c * (float)piVar5[1]) /
                                     param_5));
        }
      }
      fVar2 = lbl_803E3E08;
      *(float *)(param_9 + 0x12) = *(float *)(param_9 + 0x12) * lbl_803E3E08;
      *(float *)(param_9 + 0x16) = *(float *)(param_9 + 0x16) * fVar2;
      *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) * lbl_803E3E0C;
      if (*(char *)(piVar5[7] + 0x12) < '\0') {
        *(float *)(param_9 + 0x14) =
             *(float *)(param_9 + 0x14) -
             (lbl_803E3E10 * lbl_803DC074 * (float)piVar5[2]) / lbl_803E3E14;
      }
      dVar8 = DOUBLE_803e3e28;
      dVar7 = DOUBLE_803e3e20;
      if ((*(byte *)(piVar5[7] + 0x12) >> 5 & 1) == 0) {
        if (param_9[0x23] == 0x482) {
          uStack_3c = (uint)DAT_803dc070;
          local_40 = 0x43300000;
          uStack_34 = (int)(short)*param_9 ^ 0x80000000;
          local_38 = 0x43300000;
          iVar3 = (int)(lbl_803E3E18 * lbl_803DC9B0 *
                        (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e3e20) +
                       (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e3e28));
          local_30 = (longlong)iVar3;
          *param_9 = (ushort)iVar3;
          uStack_24 = (uint)DAT_803dc070;
          local_28 = 0x43300000;
          uStack_1c = (int)(short)param_9[1] ^ 0x80000000;
          local_20 = 0x43300000;
          iVar3 = (int)(lbl_803DC9B4 * (float)((double)CONCAT44(0x43300000,uStack_24) - dVar7) +
                       (float)((double)CONCAT44(0x43300000,uStack_1c) - dVar8));
          local_18 = (longlong)iVar3;
          param_9[1] = (ushort)iVar3;
          param_4 = dVar7;
        }
      }
      else {
        FUN_8020a4ac((double)lbl_803E3DF8,(double)lbl_803E3DF0,param_9,(float *)(param_9 + 0x12)
                     ,10);
        param_9[2] = param_9[2] + (ushort)DAT_803dc070 * 0x500;
      }
      FUN_800068c4((uint)param_9,*(ushort *)(piVar5[7] + 2));
      dVar7 = (double)(*(float *)(param_9 + 0x14) * lbl_803DC074);
      dVar8 = (double)(*(float *)(param_9 + 0x16) * lbl_803DC074);
      FUN_80017a88((double)(*(float *)(param_9 + 0x12) * lbl_803DC074),dVar7,dVar8,(int)param_9);
      ObjHits_SetHitVolumeSlot((int)param_9,0x16,1,0);
      ObjHits_EnableObject((int)param_9);
      iVar3 = *(int *)(*(int *)(param_9 + 0x2a) + 0x50);
      if (((iVar3 != 0) && (*(ushort *)(iVar3 + 0x46) != param_9[0x23])) && (iVar3 != *piVar5)) {
        piVar5[2] = (int)lbl_803E3DF8;
        ObjHits_DisableObject((int)param_9);
        if (*(short *)(piVar5[7] + 4) != -1) {
          FUN_8008112c((double)lbl_803E3DF4,dVar7,dVar8,param_4,param_5,param_6,param_7,param_8,
                       param_9,0,1,0,1,0,1,0);
          FUN_800067e8((uint)param_9,*(ushort *)(piVar5[7] + 4),3);
        }
        FUN_8007f718((float *)(piVar5 + 8),0x78);
      }
    }
    else {
      iVar3 = FUN_8007f764((float *)(piVar5 + 8));
      if (iVar3 != 0) {
        FUN_80017ac8(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      }
    }
  }
  else {
    FUN_80017ac8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void kaldachompspit_release(void) {}
void kaldachompspit_initialise(void) {}
void pinponspike_render(void) {}
void pinponspike_hitDetect(void) {}
void pinponspike_release(void) {}
void pinponspike_initialise(void) {}
void pollen_release(void) {}
void pollen_initialise(void) {}
void pollenfragment_release(void) {}
void pollenfragment_initialise(void) {}
void mikabomb_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int pinponspike_getExtraSize(void) { return 0x0; }
int pinponspike_func08(void) { return 0x0; }
int pollen_getExtraSize(void) { return 0x14; }
int pollen_func08(void) { return 0x0; }
int pollenfragment_getExtraSize(void) { return 0x28; }
int pollenfragment_func08(void) { return 0x0; }
int mikabomb_getExtraSize(void) { return 0x10; }
int mikabomb_func08(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3138;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E31C0;
#pragma peephole off
void pollen_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3138); }
void mikabomb_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E31C0); }
#pragma peephole reset

extern void kaldachompspit_free(void);
extern void kaldachompspit_hitDetect(void);
extern void kaldachompspit_update(void);
extern int kaldachompspit_func08(void);
extern int kaldachompspit_getExtraSize(void);
extern void pinponspike_free(void);
extern void pinponspike_update(void);
extern void pinponspike_init(void);
extern void pollen_free(void);
extern void pollen_hitDetect(void);
extern void pollen_update(void);
extern void pollen_init(void);

u32 gKaldaChompSpitObjDescriptor[] = {
    0,
    0,
    0,
    0x00090000,
    (u32)kaldachompspit_initialise,
    (u32)kaldachompspit_release,
    0,
    (u32)kaldachompspit_init,
    (u32)kaldachompspit_update,
    (u32)kaldachompspit_hitDetect,
    (u32)kaldachompspit_render,
    (u32)kaldachompspit_free,
    (u32)kaldachompspit_func08,
    (u32)kaldachompspit_getExtraSize,
};

u32 gPinPonSpikeObjDescriptor[] = {
    0,
    0,
    0,
    0x00090000,
    (u32)pinponspike_initialise,
    (u32)pinponspike_release,
    0,
    (u32)pinponspike_init,
    (u32)pinponspike_update,
    (u32)pinponspike_hitDetect,
    (u32)pinponspike_render,
    (u32)pinponspike_free,
    (u32)pinponspike_func08,
    (u32)pinponspike_getExtraSize,
};

u32 gPollenObjDescriptor[] = {
    0,
    0,
    0,
    0x00090000,
    (u32)pollen_initialise,
    (u32)pollen_release,
    0,
    (u32)pollen_init,
    (u32)pollen_update,
    (u32)pollen_hitDetect,
    (u32)pollen_render,
    (u32)pollen_free,
    (u32)pollen_func08,
    (u32)pollen_getExtraSize,
};
