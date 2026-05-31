#include "ghidra_import.h"
#include "main/dll/dll_10A.h"

#define SFXdoor_unlocked 0x232
#define SFXdoor_creak 0x233
#define SFXfox_healthgasp2 0x25d
#define SFXfox_healthgasp3 0x25e
#define SFXfox_healthgasp4 0x25f

extern undefined4 FUN_80006820();
extern undefined4 FUN_80006824();
extern int FUN_80006a10();
extern undefined4 FUN_80017754();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017778();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 FUN_8014d3d0();
extern undefined4 FUN_8014d4c8();
extern double FUN_80293900();

extern undefined4 DAT_803dc930;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e35d0;
extern f64 DOUBLE_803e35f8;
extern f64 DOUBLE_803e3640;
extern f32 lbl_803DC074;
extern f32 lbl_803E358C;
extern f32 lbl_803E35A4;
extern f32 lbl_803E35A8;
extern f32 lbl_803E35BC;
extern f32 lbl_803E35C0;
extern f32 lbl_803E35C4;
extern f32 lbl_803E35C8;
extern f32 lbl_803E35D8;
extern f32 lbl_803E35DC;
extern f32 lbl_803E35E0;
extern f32 lbl_803E35E4;
extern f32 lbl_803E35E8;
extern f32 lbl_803E35EC;
extern f32 lbl_803E35F0;
extern f32 lbl_803E3600;
extern f32 lbl_803E3604;
extern f32 lbl_803E3608;
extern f32 lbl_803E360C;
extern f32 lbl_803E3610;
extern f32 lbl_803E3614;
extern f32 lbl_803E3618;
extern f32 lbl_803E361C;
extern f32 lbl_803E3620;
extern f32 lbl_803E3624;
extern f32 lbl_803E3628;
extern f32 lbl_803E362C;
extern f32 lbl_803E3630;
extern f32 lbl_803E3634;
extern f32 lbl_803E3638;
extern f32 lbl_803E363C;

/*
 * --INFO--
 *
 * Function: FUN_801540a0
 * EN v1.0 Address: 0x801540A0
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x8015413C
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801540a0(undefined4 param_1,int param_2)
{
  float fVar1;
  float fVar2;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E35BC;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(float *)(param_2 + 0x308) = lbl_803E358C;
  *(float *)(param_2 + 0x300) = lbl_803E35C0;
  *(float *)(param_2 + 0x304) = lbl_803E35C4;
  *(undefined *)(param_2 + 800) = 0;
  fVar2 = lbl_803E35A8;
  *(float *)(param_2 + 0x314) = lbl_803E35A8;
  *(undefined *)(param_2 + 0x321) = 7;
  fVar1 = lbl_803E35A4;
  *(float *)(param_2 + 0x318) = lbl_803E35A4;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar2;
  *(undefined *)(param_2 + 0x33a) = 0;
  *(undefined *)(param_2 + 0x33b) = 0;
  *(float *)(param_2 + 0x324) = lbl_803E35C8;
  *(float *)(param_2 + 0x2fc) = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80154108
 * EN v1.0 Address: 0x80154108
 * EN v1.0 Size: 392b
 * EN v1.1 Address: 0x801541A4
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80154108(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  bool bVar2;
  
  bVar2 = false;
  sVar1 = *(short *)(param_9 + 0xa0);
  if ((((sVar1 == 5) || (sVar1 == 4)) ||
      ((sVar1 == 6 && ((double)*(float *)(param_9 + 0x98) < DOUBLE_803e35d0)))) && (param_12 != 0xe)
     ) {
    bVar2 = true;
  }
  if (param_12 == 0x10) {
    if (bVar2) {
      *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x20;
    }
  }
  else if (bVar2) {
    if (*(char *)(param_10 + 0x33b) == '\0') {
      *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 8;
      *(undefined2 *)(param_10 + 0x2b0) = 0;
      FUN_80006824(param_9,SFXfox_healthgasp4);
    }
  }
  else if (param_12 == 0x11) {
    *(float *)(param_10 + 0x32c) = lbl_803E35D8;
    *(float *)(param_10 + 0x324) = lbl_803E35DC;
    FUN_8014d4c8((double)lbl_803E35E0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,4,0,3,param_14,param_15,param_16);
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
    *(undefined *)(param_10 + 0x33b) = 0x3c;
  }
  else {
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x10;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80154290
 * EN v1.0 Address: 0x80154290
 * EN v1.0 Size: 1172b
 * EN v1.1 Address: 0x801542B8
 * EN v1.1 Size: 660b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80154290(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 *param_10)
{
  float fVar1;
  int iVar2;
  char cVar4;
  uint uVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar5;
  double dVar6;
  double dVar7;
  
  pfVar5 = (float *)*param_10;
  *(undefined *)((int)param_10 + 0x33a) = 0;
  param_10[0xca] = lbl_803E35E4;
  if ((param_10[0xb7] & 0x2000) != 0) {
    iVar2 = FUN_80006a10((double)(float)param_10[0xbf],pfVar5);
    if ((((iVar2 != 0) || (pfVar5[4] != 0.0)) &&
        (cVar4 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar5), cVar4 != '\0')) &&
       (cVar4 = (**(code **)(*DAT_803dd71c + 0x8c))
                          ((double)lbl_803E35E8,*param_10,param_9,&DAT_803dc930,0xffffffff),
       cVar4 != '\0')) {
      param_10[0xb7] = param_10[0xb7] & 0xffffdfff;
    }
    if (lbl_803E35E4 == (float)param_10[0xcb]) {
      if (param_9[0x50] == 0) {
        FUN_8014d3d0(param_9,param_10,0x3c,0);
      }
      fVar1 = lbl_803E35E4;
      if (lbl_803E35E4 < (float)param_10[0xc9]) {
        param_10[0xc9] = (float)param_10[0xc9] - lbl_803DC074;
        if ((float)param_10[0xc9] <= fVar1) {
          param_10[0xb9] = param_10[0xb9] & 0xfffeffff;
          param_10[0xc9] = fVar1;
        }
      }
    }
  }
  dVar7 = (double)(float)param_10[0xcb];
  dVar6 = (double)lbl_803E35E4;
  if (dVar7 <= dVar6) {
    if ((param_10[0xb7] & 0x40000000) != 0) {
      FUN_8014d4c8((double)lbl_803E35F0,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,(int)param_10,0,0,3,in_r8,in_r9,in_r10);
    }
  }
  else {
    param_10[0xcb] = (float)(dVar7 - (double)lbl_803DC074);
    if (dVar6 < (double)(float)param_10[0xcb]) {
      if ((param_10[0xb7] & 0x40000000) != 0) {
        FUN_8014d4c8((double)lbl_803E35EC,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)param_9,(int)param_10,5,0,3,in_r8,in_r9,in_r10);
      }
    }
    else {
      FUN_8014d4c8((double)lbl_803E35E0,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,(int)param_10,6,0,3,in_r8,in_r9,in_r10);
      param_10[0xcb] = lbl_803E35E4;
    }
  }
  param_9[1] = *(short *)(param_10 + 0x67);
  param_9[2] = *(short *)((int)param_10 + 0x19e);
  param_10[0xcc] = (float)param_10[0xcc] - lbl_803DC074;
  if ((float)param_10[0xcc] <= lbl_803E35E4) {
    uVar3 = randomGetRange(0x3c,0x78);
    param_10[0xcc] = (f32)(s32)(uVar3);
    FUN_80006824((uint)param_9,SFXfox_healthgasp3);
  }
  if (*(char *)((int)param_10 + 0x33b) != '\0') {
    *(char *)((int)param_10 + 0x33b) = *(char *)((int)param_10 + 0x33b) + -1;
  }
  return;
}

#pragma scheduling off
#pragma peephole off
void fn_80154328(int obj, int p)
{
  extern u32 randomGetRange(int min, int max);
  extern void setMatrixFromObjectPos(void *mtx, s16 *args);
  extern void Matrix_TransformPoint(void *mtx, f32 *in, f32 *out_x, f32 *out_z);
  extern void Sfx_PlayAtPositionFromObject(int obj, int sfx, f32 x, f32 y, f32 z);
  extern int *gWaterfxInterface;
  extern f32 timeDelta;
  extern f32 lbl_803E2990;
  extern f32 lbl_803E2994;
  extern f32 lbl_803E2998;
  extern f32 lbl_803E299C;
  extern f32 lbl_803E29A0;
  extern f32 lbl_803E29A4;
  s16 stk_in[7];
  f32 stk_pos[3];
  f32 stk_tx;
  f32 stk_tz;
  char stk_mtx[80];

  *(f32 *)(p + 0x330) -= timeDelta;
  if (*(f32 *)(p + 0x330) <= lbl_803E2990) {
    *(f32 *)(p + 0x330) = (f32)(s32)randomGetRange(30, 60);
    stk_pos[0] = *(f32 *)(obj + 0xc);
    stk_pos[1] = lbl_803E2990;
    stk_pos[2] = *(f32 *)(obj + 0x14);
    stk_in[0] = *(s16 *)(obj + 0);
    stk_in[1] = 0;
    stk_in[2] = 0;
    *(f32 *)(stk_in + 4) = lbl_803E2994;
    setMatrixFromObjectPos(stk_mtx, stk_in);
    stk_tx = (f32)(s32)randomGetRange(-20, 20) / lbl_803E299C + lbl_803E2998;
    stk_tz = (f32)(s32)randomGetRange(-20, 20) / lbl_803E299C + lbl_803E29A0;
    {
      f32 ox, oz;
      Matrix_TransformPoint(stk_mtx, &stk_tx, &ox, &oz);
      (**(void (**)(int, int, f32, f32, f32, f32))(*(int *)(*gWaterfxInterface) + 0x14))(
          0, 3, stk_tx, *(f32 *)(p + 0x32c), stk_tz, lbl_803E2990);
    }
    if ((f32)sqrtf(*(f32 *)(obj + 0x24) * *(f32 *)(obj + 0x24) + *(f32 *)(obj + 0x2c) * *(f32 *)(obj + 0x2c)) > lbl_803E29A4) {
      Sfx_PlayAtPositionFromObject(obj, 565, stk_pos[0], stk_pos[1], stk_pos[2]);
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80154724
 * EN v1.0 Address: 0x80154724
 * EN v1.0 Size: 852b
 * EN v1.1 Address: 0x8015454C
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80154724(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)
{
  bool bVar1;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  *(float *)(param_10 + 0x32c) = lbl_803E35E4;
  bVar1 = false;
  ObjHits_SetHitVolumeSlot((int)param_9,0x18,1,-1);
  if (*(int *)(param_10 + 0x340) != 0) {
    bVar1 = true;
    *(float *)(param_10 + 0x324) = lbl_803E3600;
    *(float *)(param_10 + 0x32c) = lbl_803E35E4;
    if (param_9[0x50] != 0) {
      FUN_8014d4c8((double)lbl_803E35F0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,param_10,2,0,3,in_r8,in_r9,in_r10);
    }
  }
  if (param_9[0x50] == 3) {
    *(float *)(param_10 + 0x328) = *(float *)(param_10 + 0x328) - lbl_803DC074;
    if (*(float *)(param_10 + 0x328) <= lbl_803E35E4) {
      bVar1 = true;
      *(float *)(param_10 + 0x32c) = lbl_803E35D8;
      *(float *)(param_10 + 0x324) = lbl_803E35DC;
      FUN_8014d4c8((double)lbl_803E35E0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,param_10,4,0,3,in_r8,in_r9,in_r10);
    }
  }
  else {
    param_2 = (double)*(float *)(*(int *)(param_10 + 0x29c) + 0x14);
    FUN_8014d3d0(param_9,param_10,0x3c,0);
  }
  if (bVar1) {
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
  }
  else if (*(char *)(param_10 + 0x33a) == '\0') {
    *(undefined *)(param_10 + 0x33a) = 1;
    FUN_8014d4c8((double)lbl_803E3604,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)param_9,param_10,1,0,3,in_r8,in_r9,in_r10);
  }
  else if (((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) &&
          (FUN_8014d4c8((double)lbl_803E3608,param_2,param_3,param_4,param_5,param_6,param_7,
                        param_8,(int)param_9,param_10,3,0,3,in_r8,in_r9,in_r10),
          lbl_803E35E4 == *(float *)(param_10 + 0x328))) {
    *(float *)(param_10 + 0x328) = lbl_803E360C;
    FUN_8014d3d0(param_9,param_10,1,0);
    FUN_80006824((uint)param_9,SFXfox_healthgasp2);
  }
  param_9[1] = *(short *)(param_10 + 0x19c);
  param_9[2] = *(short *)(param_10 + 0x19e);
  if (*(char *)(param_10 + 0x33b) != '\0') {
    *(char *)(param_10 + 0x33b) = *(char *)(param_10 + 0x33b) + -1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80154a78
 * EN v1.0 Address: 0x80154A78
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x80154758
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80154a78(undefined4 param_1,int param_2)
{
  float fVar1;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E3610;
  *(undefined4 *)(param_2 + 0x2e4) = 0xad;
  *(float *)(param_2 + 0x308) = lbl_803E3614;
  *(float *)(param_2 + 0x300) = lbl_803E35EC;
  *(float *)(param_2 + 0x304) = lbl_803E3618;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = lbl_803E361C;
  *(float *)(param_2 + 0x314) = lbl_803E361C;
  *(undefined *)(param_2 + 0x321) = 7;
  *(float *)(param_2 + 0x318) = lbl_803E3620;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  fVar1 = lbl_803E35E4;
  *(float *)(param_2 + 0x324) = lbl_803E35E4;
  *(float *)(param_2 + 0x328) = fVar1;
  *(float *)(param_2 + 0x32c) = fVar1;
  *(undefined *)(param_2 + 0x33a) = 0;
  *(undefined *)(param_2 + 0x33b) = 0;
  *(float *)(param_2 + 0x330) = lbl_803E3624;
  *(float *)(param_2 + 0x2fc) = lbl_803E35F0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80154af4
 * EN v1.0 Address: 0x80154AF4
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x801547D4
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80154af4(ushort *param_1,int param_2)
{
  double dVar1;
  float local_88;
  float fStack_84;
  float local_80;
  ushort local_7c [4];
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float afStack_64 [17];
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;
  
  *(float *)(param_2 + 0x330) = *(float *)(param_2 + 0x330) - lbl_803DC074;
  if (*(float *)(param_2 + 0x330) <= lbl_803E3628) {
    uStack_1c = randomGetRange(0x1e,0x3c);
    *(float *)(param_2 + 0x330) = (f32)(s32)uStack_1c;
    local_70 = *(float *)(param_1 + 6);
    local_6c = lbl_803E3628;
    local_68 = *(float *)(param_1 + 10);
    local_7c[0] = *param_1;
    local_7c[1] = 0;
    local_7c[2] = 0;
    local_74 = lbl_803E362C;
    FUN_80017754(afStack_64,local_7c);
    uStack_14 = randomGetRange(0xffffffec,0x14);
    local_80 = lbl_803E3630 +
               (f32)(s32)uStack_14 / lbl_803E3634;
    uStack_c = randomGetRange(0xffffffec,0x14);
    local_88 = lbl_803E3638 +
               (f32)(s32)uStack_c / lbl_803E3634;
    FUN_80017778((double)local_80,(double)lbl_803E3628,(double)local_88,afStack_64,&local_80,
                 &fStack_84,&local_88);
    (**(code **)(*DAT_803dd718 + 0x14))
              ((double)local_80,(double)*(float *)(param_2 + 0x32c),(double)local_88,
               (double)lbl_803E3628,0,3);
    dVar1 = FUN_80293900((double)(*(float *)(param_1 + 0x12) * *(float *)(param_1 + 0x12) +
                                 *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16)));
    if ((double)lbl_803E363C < dVar1) {
      FUN_80006820((double)local_70,(double)local_6c,(double)local_68,(uint)param_1,0x235);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80154cc8
 * EN v1.0 Address: 0x80154CC8
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x80154994
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80154cc8(uint param_1,int param_2,undefined4 param_3,int param_4)
{
  if ((param_4 != 0x11) && (param_4 != 0x10)) {
    if (*(float *)(param_1 + 0x98) <= lbl_803E363C) {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x10;
    }
    else {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
      FUN_80006824(param_1,SFXdoor_unlocked);
      FUN_80006824(param_1,SFXdoor_creak);
      *(undefined2 *)(param_2 + 0x2b0) = 0;
      *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x20;
    }
  }
  return;
}

extern f32 lbl_803E2978;
extern f32 lbl_803E297C;
extern f32 lbl_803E2954;
extern f32 lbl_803E2980;
extern f32 lbl_803E2984;
extern f32 lbl_803E2988;
extern f32 lbl_803E294C;
extern f32 lbl_803E298C;
extern f32 lbl_803E2958;

extern f32 lbl_803E29A4;

#pragma scheduling off
#pragma peephole off
void fn_801544E8(int* obj, u8* state, int p3, int p4) {
    if (p4 == 17 || p4 == 16) return;
    if (*(f32*)((char*)obj + 152) > lbl_803E29A4) {
        *(int*)((char*)state + 744) |= 8;
        Sfx_PlayFromObject(obj, SFXdoor_unlocked);
        Sfx_PlayFromObject(obj, SFXdoor_creak);
        *(s16*)((char*)state + 688) = 0;
        *(int*)((char*)state + 740) |= 32;
    } else {
        *(int*)((char*)state + 744) |= 16;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_801542AC(int unused, u8* state) {
    f32 fz;
    f32 fc;
    *(f32*)((char*)state + 684) = lbl_803E2978;
    *(int*)((char*)state + 740) = 173;
    *(f32*)((char*)state + 776) = lbl_803E297C;
    *(f32*)((char*)state + 768) = lbl_803E2954;
    *(f32*)((char*)state + 772) = lbl_803E2980;
    state[800] = 0;
    fz = lbl_803E2984;
    *(f32*)((char*)state + 788) = fz;
    state[801] = 7;
    *(f32*)((char*)state + 792) = lbl_803E2988;
    state[802] = 0;
    *(f32*)((char*)state + 796) = fz;
    fc = lbl_803E294C;
    *(f32*)((char*)state + 804) = fc;
    *(f32*)((char*)state + 808) = fc;
    *(f32*)((char*)state + 812) = fc;
    state[826] = 0;
    state[827] = 0;
    *(f32*)((char*)state + 816) = lbl_803E298C;
    *(f32*)((char*)state + 764) = lbl_803E2958;
}
#pragma peephole reset
#pragma scheduling reset
