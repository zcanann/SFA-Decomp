#include "ghidra_import.h"
#include "main/dll/seqObj.h"

#define SFXfox_swimstroke122 571

extern undefined4 FUN_800033a8();
extern void *mmAlloc(int size,int tag,int flags);
extern void *memset(void *dst,int value,uint size);
extern undefined4 FUN_80006820();
extern undefined4 FUN_80006824();
extern int FUN_80006a10();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined4 FUN_800305c4();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern int Obj_GetPlayerObject(void);
extern undefined8 ObjGroup_RemoveObject();
extern void Sfx_PlayAtPositionFromObject(int obj, f32 x, f32 y, f32 z, int sfxId);
extern void Sfx_PlayFromObject(int obj,int sfxId);
extern f32 Vec_distance(f32 *a, f32 *b);
extern void doRumble(f32 duration);
extern void CameraShake_ApplyRadial(f32 x, f32 y, f32 z, f32 radius, f32 magnitude);
extern undefined4 FUN_8014d3d0();
extern undefined4 FUN_8014d4c8();
extern undefined4 FUN_80151844();
extern void fn_801513AC(int obj, int state);
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_8031e980;
extern undefined4 DAT_8031feac;
extern undefined4 DAT_8031fead;
extern undefined4 DAT_803dc8e8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern undefined4 DAT_803de6e8;
extern f64 DOUBLE_803e3398;
extern f64 lbl_803E2700;
extern f64 DOUBLE_803e33f0;
extern f32 lbl_803DC074;
extern f32 lbl_803E3368;
extern f32 lbl_803E336C;
extern f32 lbl_803E3370;
extern f32 lbl_803E337C;
extern f32 lbl_803E3380;
extern f32 lbl_803E3384;
extern f32 lbl_803E3388;
extern f32 lbl_803E338C;
extern f32 lbl_803E3390;
extern f32 lbl_803E3394;
extern f32 lbl_803E33A0;
extern f32 lbl_803E33A4;
extern f32 lbl_803E33A8;
extern f32 lbl_803E33AC;
extern f32 lbl_803E33B0;
extern f32 lbl_803E33B4;
extern f32 lbl_803E33B8;
extern f32 lbl_803E33C0;
extern f32 lbl_803E33C4;
extern f32 lbl_803E33C8;
extern f32 lbl_803E33CC;
extern f32 lbl_803E33D0;
extern f32 lbl_803E33D4;
extern f32 lbl_803E33D8;
extern f32 lbl_803E33DC;
extern f32 lbl_803E33E0;
extern f32 lbl_803E33E4;
extern f32 lbl_803E33E8;
extern f32 lbl_803E33EC;
extern f32 lbl_803E2708;
extern f32 lbl_803E270C;
extern f32 lbl_803E2710;
extern f32 lbl_803E2714;
extern f32 lbl_803E2718;
extern f32 lbl_803E271C;
extern f32 lbl_803E2720;
extern f32 lbl_803E2740;
extern f32 lbl_803E2744;
extern f32 lbl_803E2748;
extern f32 lbl_803E274C;
extern f32 lbl_803E2750;
extern f32 lbl_803E2754;
extern f32 lbl_803E2760;
extern f32 lbl_803E2764;
extern f32 timeDelta;
extern int *gPartfxInterface;
extern int *gRomCurveInterface;
extern int lbl_803DBC80;
extern void* PTR_DAT_8031fdc4;
extern f32 sqrtf(f32 x);
extern void fn_8014F620(int obj,WispBaddieState *state);

extern void wispbaddie_free(void);
extern void wispbaddie_render(void);
extern void wispbaddie_hitDetect(void);
extern void wispbaddie_init(int obj,int setup,int initialised);
extern int wispbaddie_getObjectTypeId(void);
extern int wispbaddie_getExtraSize(void);

#pragma peephole off
#pragma scheduling off
void wispbaddie_update(int obj)
{
  WispBaddieState *state;
  int curve;
  int hit;
  f32 dx;
  f32 hitZ;
  f32 dy;
  f32 dz;
  f32 hitX;
  f32 hitY;
  f32 d[3];
  int particleParam;
  u8 f;
  void *dAlias = (void *)d;

  state = *(WispBaddieState **)(obj + 0xb8);
  curve = state->curve;
  hit = ObjHits_GetPriorityHitWithPosition(obj,&dx,&hitX,&hitY,&hitZ,&dy,&dz);
  if (hit != 0) {
    state->hitRadius = lbl_803E2708;
    f = state->flags;
    if ((f & 2) != 0) {
      state->flags = (u8)(f & ~2);
      state->flags = (u8)(state->flags | 4);
    }
    Sfx_PlayAtPositionFromObject(obj,hitZ,dy,dz,0x23c);
  }

  particleParam = 4;
  (*(void (**)(int,int,int,int,int,int *))(*gPartfxInterface + 8))
      (obj,state->particleId,0,1,-1,&particleParam);
  particleParam = 3;
  (*(void (**)(int,int,int,int,int,int *))(*gPartfxInterface + 8))
      (obj,state->particleId,0,2,-1,&particleParam);

  if (state->hitRadius < state->maxHitRadius) {
    state->hitRadius += lbl_803E270C;
    ObjHits_DisableObject(obj);
  } else {
    state->hitRadius = state->maxHitRadius;
    particleParam = 2;
    (*(void (**)(int,int,int,int,int,int *))(*gPartfxInterface + 8))
        (obj,state->particleId,0,2,-1,&particleParam);
    particleParam = 0;
    (*(void (**)(int,int,int,int,int,int *))(*gPartfxInterface + 8))
        (obj,state->particleId,0,2,-1,&particleParam);
    ObjHits_SetHitVolumeSlot(obj,10,1,0);
    ObjHits_EnableObject(obj);
  }

  particleParam = 1;
  (*(void (**)(int,int,int,int,int,int *))(*gPartfxInterface + 8))
      (obj,state->particleId,0,2,-1,&particleParam);
  state->playerObj = Obj_GetPlayerObject();
  if (state->playerObj != 0) {
    d[0] = *(f32 *)(state->playerObj + 0x18) - *(f32 *)(obj + 0x18);
    d[1] = *(f32 *)(state->playerObj + 0x1c) - *(f32 *)(obj + 0x1c);
    d[2] = *(f32 *)(state->playerObj + 0x20) - *(f32 *)(obj + 0x20);
    state->playerDistance = sqrtf(d[2] * d[2] + (d[0] * d[0] + d[1] * d[1]));
  }
  if (curve != 0) {
    d[0] = *(f32 *)(curve + 0x68) - *(f32 *)(obj + 0x18);
    d[1] = *(f32 *)(curve + 0x6c) - *(f32 *)(obj + 0x1c);
    d[2] = *(f32 *)(curve + 0x70) - *(f32 *)(obj + 0x20);
    state->curveDistance = sqrtf(d[2] * d[2] + (d[0] * d[0] + d[1] * d[1]));
  }

  f = state->flags;
  if ((f & 2) != 0) {
    if (state->curveDistance > lbl_803E2710) {
      state->flags = (u8)(f & ~2);
      state->flags = (u8)(state->flags | 4);
    }
    state->cryTimer -= timeDelta;
    if (state->cryTimer < lbl_803E2714) {
      Sfx_PlayFromObject(obj,0x23d);
      state->cryTimer = (f32)randomGetRange(0x3c,0x78);
    }
    state->particleId = 0x338;
  }
  f = state->flags;
  if ((f & 4) != 0) {
    if (state->curveDistance < lbl_803E2718) {
      state->flags = (u8)(f & ~4);
    }
    state->particleId = 0x337;
  }
  if ((state->flags & 6) == 0) {
    if ((state->maxHitRadius <= state->hitRadius) && (state->playerObj != 0) &&
        (state->playerDistance < state->triggerDistance)) {
      state->flags = (u8)(state->flags | 2);
    }
    state->particleId = 0x337;
  }
  fn_8014F620(obj,state);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wispbaddie_init(int obj,int setup,int initialised)
{
  WispBaddieState *state;
  f32 value;

  state = *(WispBaddieState **)(obj + 0xb8);
  value = (f32)*(s16 *)(setup + 0x1a) / lbl_803E271C;
  state->maxHitRadius = value;
  state->hitRadius = value;
  state->triggerDistance = lbl_803E2720 * (f32)*(s8 *)(setup + 0x19);
  state->particleId = 0x337;

  if (initialised == 0) {
    state->curve = (int)mmAlloc(0x108,0x1a,0);
    if ((void *)state->curve != NULL) {
      memset((void *)state->curve,0,0x108);
    }
    if ((*(u8 (**)(int,int,f32,int *,int))(*gRomCurveInterface + 0x8c))
            (state->curve,obj,state->triggerDistance,&lbl_803DBC80,-1) == 0) {
      state->flags = (u8)(state->flags | 1);
    }
    Sfx_PlayFromObject(obj,0x23b);
  }
  *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) | 0x2000);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_8014fd38
 * EN v1.0 Address: 0x8014FD38
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x8014FE24
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014fd38(int param_1)
{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  ObjGroup_RemoveObject(param_1,3);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_80017814(uVar1);
    *puVar2 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014fd80
 * EN v1.0 Address: 0x8014FD80
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8014FE7C
 * EN v1.1 Size: 992b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014fd80(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8014fd84
 * EN v1.0 Address: 0x8014FD84
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x8015025C
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014fd84(uint param_1,int param_2,int param_3)
{
  float fVar1;
  double dVar2;
  int iVar3;
  char cVar4;
  int *piVar5;
  
  dVar2 = DOUBLE_803e3398;
  piVar5 = *(int **)(param_1 + 0xb8);
  fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                 DOUBLE_803e3398) / lbl_803E33B4;
  piVar5[3] = (int)fVar1;
  piVar5[2] = (int)fVar1;
  piVar5[6] = (int)(lbl_803E33B8 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000)
                          - dVar2));
  piVar5[8] = 0x337;
  if (param_3 == 0) {
    iVar3 = FUN_80017830(0x108,0x1a);
    *piVar5 = iVar3;
    if (*piVar5 != 0) {
      FUN_800033a8(*piVar5,0,0x108);
    }
    cVar4 = (**(code **)(*DAT_803dd71c + 0x8c))
                      ((double)(float)piVar5[6],*piVar5,param_1,&DAT_803dc8e8,0xffffffff);
    if (cVar4 == '\0') {
      *(byte *)(piVar5 + 9) = *(byte *)(piVar5 + 9) | 1;
    }
    FUN_80006824(param_1,SFXfox_swimstroke122);
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014fef8
 * EN v1.0 Address: 0x8014FEF8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8015038C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014fef8(undefined4 param_1,int param_2,undefined4 param_3,int param_4)
{
  if (param_4 == 0x10) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
    return;
  }
  *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ff20
 * EN v1.0 Address: 0x8014FF20
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801503B4
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ff20(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ff24
 * EN v1.0 Address: 0x8014FF24
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801503B8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ff24(short *param_1,undefined4 param_2)
{
  FUN_8014d3d0(param_1,param_2,0xf,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ff4c
 * EN v1.0 Address: 0x8014FF4C
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801503EC
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ff4c(undefined4 param_1,int param_2)
{
  float fVar1;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E33C0;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x80;
  *(float *)(param_2 + 0x308) = lbl_803E33C4;
  *(float *)(param_2 + 0x300) = lbl_803E33C8;
  *(float *)(param_2 + 0x304) = lbl_803E33CC;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = lbl_803E33D0;
  *(float *)(param_2 + 0x314) = lbl_803E33D0;
  *(undefined *)(param_2 + 0x321) = 0;
  *(float *)(param_2 + 0x318) = lbl_803E33D4;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ffa8
 * EN v1.0 Address: 0x8014FFA8
 * EN v1.0 Size: 1176b
 * EN v1.1 Address: 0x80150448
 * EN v1.1 Size: 1000b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ffa8(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  short *psVar5;
  uint uVar6;
  int iVar7;
  undefined *puVar8;
  float *pfVar9;
  double dVar10;
  double dVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_80286840();
  fVar3 = lbl_803E33D8;
  psVar5 = (short *)((ulonglong)uVar12 >> 0x20);
  iVar7 = (int)uVar12;
  puVar8 = (&PTR_DAT_8031fdc4)[(uint)*(byte *)(iVar7 + 0x33b) * 10];
  if (((*(uint *)(iVar7 + 0x2dc) & 0x4000) != 0) ||
     ((dVar10 = (double)*(float *)(iVar7 + 0x328), dVar10 != (double)lbl_803E33D8 &&
      (*(short *)(iVar7 + 0x338) != 0)))) goto LAB_80150818;
  bVar1 = *(byte *)(iVar7 + 0x2f1);
  uVar6 = bVar1 & 0x1f;
  if ((bVar1 & 0x10) != 0) {
    uVar6 = bVar1 & 0x17;
  }
  if (0x18 < uVar6) {
    uVar6 = 0;
  }
  fVar2 = lbl_803E33E0;
  if ((bVar1 & 0x20) != 0) {
    uVar6 = 0;
    fVar2 = lbl_803E33DC;
  }
  dVar11 = (double)fVar2;
  if (((param_11 & 0xff) != 0) &&
     ((((bVar1 != 0 ||
        (dVar10 = (double)*(float *)(iVar7 + 0x324), dVar10 != (double)lbl_803E33D8)) &&
       ((*(uint *)(iVar7 + 0x2dc) & 0x40) == 0)) && ((bVar1 & 0x20) == 0)))) {
    param_2 = (double)*(float *)(iVar7 + 0x324);
    dVar10 = (double)lbl_803E33D8;
    if (param_2 == dVar10) {
      iVar4 = (uint)*(byte *)(iVar7 + 0x33b) * 2;
      uVar6 = randomGetRange((uint)(byte)(&DAT_8031feac)[iVar4],(uint)(byte)(&DAT_8031fead)[iVar4]);
      *(float *)(iVar7 + 0x324) =
           *(float *)(iVar7 + 0x334) +
           (f32)(s32)(uVar6);
      *(float *)(iVar7 + 0x334) = lbl_803E33D8;
      goto LAB_80150818;
    }
    *(float *)(iVar7 + 0x324) = (float)(param_2 - (double)lbl_803DC074);
    if (dVar10 < (double)*(float *)(iVar7 + 0x324)) goto LAB_80150818;
    *(float *)(iVar7 + 0x324) = fVar3;
  }
  if ((((((param_11 & 0xff) == 0) || (*(char *)(iVar7 + 0x2f1) == '\0')) ||
       (puVar8[uVar6 * 0xc + 8] == '\0')) && ((*(byte *)(iVar7 + 0x2f1) & 0x20) == 0)) ||
     ((*(byte *)(iVar7 + 0x33c) == uVar6 &&
      (dVar10 = (double)lbl_803E33D8, dVar10 != (double)*(float *)(iVar7 + 0x32c))))) {
    if (*(float *)(iVar7 + 0x32c) != lbl_803E33D8) {
      dVar10 = (double)*(float *)(*(int *)(iVar7 + 0x29c) + 0x14);
      FUN_8014d3d0(psVar5,iVar7,0xf,0);
      if (lbl_803E33E8 < *(float *)(iVar7 + 0x308)) {
        *(float *)(iVar7 + 0x308) = *(float *)(iVar7 + 0x308) - lbl_803E33EC;
      }
      if ((*(uint *)(iVar7 + 0x2dc) & 0x40000000) != 0) {
        iVar4 = (uint)*(byte *)(iVar7 + 0x33c) * 0xc;
        FUN_8014d4c8((double)*(float *)(puVar8 + iVar4),dVar10,dVar11,param_4,param_5,param_6,
                     param_7,param_8,(int)psVar5,iVar7,(uint)(byte)puVar8[iVar4 + 8],0,
                     *(uint *)(puVar8 + iVar4 + 4) & 0xff,param_14,param_15,param_16);
        FUN_800305c4((double)*(float *)(&DAT_8031e980 +
                                       (uint)(byte)puVar8[(uint)*(byte *)(iVar7 + 0x33c) * 0xc + 8]
                                       * 4),(int)psVar5);
      }
      *(float *)(iVar7 + 0x32c) = *(float *)(iVar7 + 0x32c) - lbl_803DC074;
      if (*(float *)(iVar7 + 0x32c) <= lbl_803E33D8) {
        *(float *)(iVar7 + 0x32c) = lbl_803E33D8;
        *(uint *)(iVar7 + 0x2dc) = *(uint *)(iVar7 + 0x2dc) & 0xffffffbf;
        *(uint *)(iVar7 + 0x2dc) = *(uint *)(iVar7 + 0x2dc) | 0x40000000;
        *(byte *)(iVar7 + 0x2f2) = *(byte *)(iVar7 + 0x2f2) & 0x7f;
        *(undefined *)(iVar7 + 0x33c) = 0;
      }
    }
  }
  else if (((*(uint *)(iVar7 + 0x2dc) & 0x800080) == 0) && ((*(byte *)(iVar7 + 0x2f1) & 0x20) == 0))
  {
    if ((*(uint *)(iVar7 + 0x2dc) & 0x40000000) != 0) {
      FUN_80151844(dVar10,param_2,dVar11,param_4,param_5,param_6,param_7,param_8,psVar5,iVar7);
    }
  }
  else {
    pfVar9 = (float *)(puVar8 + uVar6 * 0xc);
    fVar3 = lbl_803E33E4 * (float)(dVar11 * (double)*pfVar9);
    *(float *)(iVar7 + 0x330) = fVar3;
    *(float *)(iVar7 + 0x32c) = fVar3;
    *(uint *)(iVar7 + 0x2dc) = *(uint *)(iVar7 + 0x2dc) | 0x40;
    *(byte *)(iVar7 + 0x2f2) = *(byte *)(iVar7 + 0x2f2) | 0x80;
    *(undefined *)(iVar7 + 0x2f3) = 0;
    *(undefined *)(iVar7 + 0x2f4) = 0;
    FUN_8014d4c8((double)(float)(dVar11 * (double)*pfVar9),param_2,dVar11,param_4,param_5,param_6,
                 param_7,param_8,(int)psVar5,iVar7,(uint)*(byte *)(pfVar9 + 2),0,
                 (uint)pfVar9[1] & 0xff,param_14,param_15,param_16);
    FUN_800305c4((double)*(float *)(&DAT_8031e980 + (uint)*(byte *)(pfVar9 + 2) * 4),(int)psVar5);
    *(char *)(iVar7 + 0x33c) = (char)uVar6;
  }
LAB_80150818:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: wispbaddie_release
 * EN v1.0 Address: 0x8014FEF0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wispbaddie_release(void)
{
}

/*
 * --INFO--
 *
 * Function: wispbaddie_initialise
 * EN v1.0 Address: 0x8014FEF4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wispbaddie_initialise(void)
{
}

ObjectDescriptor gWispBaddieObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wispbaddie_initialise,
    (ObjectDescriptorCallback)wispbaddie_release,
    0,
    (ObjectDescriptorCallback)wispbaddie_init,
    (ObjectDescriptorCallback)wispbaddie_update,
    (ObjectDescriptorCallback)wispbaddie_hitDetect,
    (ObjectDescriptorCallback)wispbaddie_render,
    (ObjectDescriptorCallback)wispbaddie_free,
    (ObjectDescriptorCallback)wispbaddie_getObjectTypeId,
    wispbaddie_getExtraSize,
};


/* Trivial 4b 0-arg blr leaves. */
void fn_8014FF20(void) {}

#pragma scheduling off
#pragma peephole off
void fn_8014FEF8(int p1, int *p2, int p3, int code) {
    if (code == 0x10) {
        *(u32 *)((char *)p2 + 0x2e8) |= 0x20;
    } else {
        *(u32 *)((char *)p2 + 0x2e8) |= 0x8;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_8014CF7C(int a, int b, f32 e, f32 f, int c, int d);
#pragma scheduling off
#pragma peephole off
void fn_8014FF24(int a, int b) {
    f32 *p = *(f32 **)((char *)b + 0x29c);
    fn_8014CF7C(a, b, p[3], p[5], 0xf, 0);
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E2728;
extern f32 lbl_803E272C;
extern f32 lbl_803E2730;
extern f32 lbl_803E2734;
extern f32 lbl_803E2738;
extern f32 lbl_803E273C;
#pragma scheduling off
#pragma peephole off
void fn_8014FF58(int unused, char *p) {
    f32 v1c;
    *(f32 *)(p + 0x2ac) = lbl_803E2728;
    *(u32 *)(p + 0x2e4) = 1;
    *(u32 *)(p + 0x2e4) |= 0x80;
    *(f32 *)(p + 0x308) = lbl_803E272C;
    *(f32 *)(p + 0x300) = lbl_803E2730;
    *(f32 *)(p + 0x304) = lbl_803E2734;
    *(u8 *)(p + 0x320) = 0;
    v1c = lbl_803E2738;
    *(f32 *)(p + 0x314) = v1c;
    *(u8 *)(p + 0x321) = 0;
    *(f32 *)(p + 0x318) = lbl_803E273C;
    *(u8 *)(p + 0x322) = 0;
    *(f32 *)(p + 0x31c) = v1c;
}
#pragma peephole reset
#pragma scheduling reset

extern char lbl_8031F16C[];
extern u8 lbl_8031DD30[];

#pragma scheduling off
#pragma peephole off
extern void fn_8014D08C(int obj, int state, int moveId, f32 speed, int p5, int flags);
extern void ObjAnim_SetMoveProgress(int obj, f32 progress);
extern void fn_801513AC(int obj, int state);
extern f32 lbl_803E2740;
extern f32 lbl_803E2744;
extern f32 lbl_803E2748;
extern f32 lbl_803E274C;
extern f32 lbl_803E2750;
extern f32 lbl_803E2754;

u32 fn_8014FFB4(int obj, int state, u32 allowNewEvent) {
    u8 *base = lbl_8031DD30;
    u8 *eventRows;
    u8 eventIndex;
    int ei;
    int flag20;
    u8 sequenceIndex;
    u32 stateFlags;
    u8 eventFlags;
    f32 blendScale;
    f32 blendTimer;
    int eventTableIndex;
    u8 *row;
    u32 sf2;

    sequenceIndex = *(u8 *)(state + 0x33b);
    eventRows = *(u8 **)(base + sequenceIndex * 0x28 + 0x1444);
    stateFlags = *(u32 *)(state + 0x2dc);
    if ((stateFlags & 0x4000) != 0) {
        return 0;
    }
    if (*(f32 *)(state + 0x328) != lbl_803E2740 && *(u16 *)(state + 0x338) != 0) {
        return 0;
    }
    eventFlags = *(u8 *)(state + 0x2f1);
    ei = eventFlags & 0x1f;
    eventIndex = ei;
    if ((ei & 0x10) != 0) {
        eventIndex = ei & ~0x8;
    }
    if (eventIndex > 0x18) {
        eventIndex = 0;
    }
    flag20 = eventFlags & 0x20;
    if (flag20 != 0) {
        blendScale = lbl_803E2744;
        eventIndex = 0;
    } else {
        blendScale = lbl_803E2748;
    }
    if ((u8)allowNewEvent != 0) {
        if ((eventFlags != 0 || *(f32 *)(state + 0x324) != lbl_803E2740) &&
            (stateFlags & 0x40) == 0 && flag20 == 0) {
            if (*(f32 *)(state + 0x324) != lbl_803E2740) {
                *(f32 *)(state + 0x324) = *(f32 *)(state + 0x324) - timeDelta;
                if (*(f32 *)(state + 0x324) <= lbl_803E2740) {
                    *(f32 *)(state + 0x324) = lbl_803E2740;
                } else {
                    return 0;
                }
            } else {
                eventTableIndex = sequenceIndex * 2;
                *(f32 *)(state + 0x324) = *(f32 *)(state + 0x334) +
                    (f32)(int)randomGetRange(base[eventTableIndex + 0x152c],
                                             base[eventTableIndex + 0x152d]);
                *(f32 *)(state + 0x334) = lbl_803E2740;
                return 0;
            }
        }
    }
    if ((((u8)allowNewEvent != 0 && *(u8 *)(state + 0x2f1) != 0 &&
          eventRows[eventIndex * 0xc + 8] != 0) ||
         (*(u8 *)(state + 0x2f1) & 0x20) != 0) &&
        !(*(u8 *)(state + 0x33c) == eventIndex && lbl_803E2740 != *(f32 *)(state + 0x32c))) {
        sf2 = *(u32 *)(state + 0x2dc);
        if ((sf2 & 0x800080) != 0 || (*(u8 *)(state + 0x2f1) & 0x20) != 0) {
            row = eventRows + eventIndex * 0xc;
            blendTimer = lbl_803E274C * (blendScale * *(f32 *)row);
            *(f32 *)(state + 0x330) = blendTimer;
            *(f32 *)(state + 0x32c) = blendTimer;
            *(u32 *)(state + 0x2dc) = *(u32 *)(state + 0x2dc) | 0x40;
            *(u8 *)(state + 0x2f2) = *(u8 *)(state + 0x2f2) | 0x80;
            *(u8 *)(state + 0x2f3) = 0;
            *(u8 *)(state + 0x2f4) = 0;
            fn_8014D08C(obj, state, row[8], blendScale * *(f32 *)row, 0, *(u32 *)(row + 4) & 0xff);
            ObjAnim_SetMoveProgress(obj, *(f32 *)(base + row[8] * 4));
            *(u8 *)(state + 0x33c) = eventIndex;
            return 1;
        }
        if ((sf2 & 0x40000000) != 0) {
            fn_801513AC(obj, state);
        }
        return 0;
    }
    if (*(f32 *)(state + 0x32c) != lbl_803E2740) {
        int pos = *(int *)(state + 0x29c);
        fn_8014CF7C(obj, state, *(f32 *)(pos + 0xc), *(f32 *)(pos + 0x14), 0xf, 0);
        if (*(f32 *)(state + 0x308) > lbl_803E2750) {
            *(f32 *)(state + 0x308) = *(f32 *)(state + 0x308) - lbl_803E2754;
        }
        if ((*(u32 *)(state + 0x2dc) & 0x40000000) != 0) {
            eventTableIndex = *(u8 *)(state + 0x33c) * 0xc;
            row = eventRows + eventTableIndex;
            fn_8014D08C(obj, state, row[8], *(f32 *)(eventRows + eventTableIndex), 0,
                        *(u32 *)(row + 4) & 0xff);
            ObjAnim_SetMoveProgress(obj,
                *(f32 *)(base + eventRows[*(u8 *)(state + 0x33c) * 0xc + 8] * 4));
        }
        *(f32 *)(state + 0x32c) = *(f32 *)(state + 0x32c) - timeDelta;
        if (*(f32 *)(state + 0x32c) <= lbl_803E2740) {
            *(f32 *)(state + 0x32c) = lbl_803E2740;
            {
                register u32 m;
                register u32 v;
                register int pReg = state;
                asm {
                    lwz v, 0x2dc(pReg)
                    li m, -65
                    and m, v, m
                    stw m, 0x2dc(pReg)
                    lwz v, 0x2dc(pReg)
                    lis m, 16384
                    or m, v, m
                    stw m, 0x2dc(pReg)
                }
            }
            *(u8 *)(state + 0x2f2) = *(u8 *)(state + 0x2f2) & 0x7f;
            *(u8 *)(state + 0x33c) = 0;
            return 0;
        } else {
            return 1;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8015039C(int obj, int animState) {
    int player;
    f32 distance;
    f32 rumbleFalloff;

    if ((*(u16 *)(animState + 0x2f8) & 0x200) != 0) {
        Sfx_PlayFromObject(obj, 0x383);
        player = Obj_GetPlayerObject();
        if ((*(u16 *)(player + 0xb0) & 0x1000) == 0) {
            distance = Vec_distance((f32 *)(obj + 0x18), (f32 *)(player + 0x18));
            if (distance <= lbl_803E2760) {
                rumbleFalloff = lbl_803E2748 - distance / lbl_803E2760;
                rumbleFalloff = lbl_803E2744 * rumbleFalloff;
                doRumble(rumbleFalloff);
            }
            CameraShake_ApplyRadial(*(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10),
                                    *(f32 *)(obj + 0x14), lbl_803E2760,
                                    lbl_803E2764);
        }
    }
    if ((*(u16 *)(animState + 0x2f8) & 0x40) != 0) {
        Sfx_PlayFromObject(obj, 0x19);
    }
    if ((*(u16 *)(animState + 0x2f8) & 0x1000) != 0) {
        Sfx_PlayFromObject(obj, 0x257);
    }
    if ((*(u16 *)(animState + 0x2f8) & 1) != 0) {
        Sfx_PlayFromObject(obj, 0x12);
    }
    if ((*(u16 *)(animState + 0x2f8) & 0x80) != 0) {
        Sfx_PlayFromObject(obj, 0x15);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
void fn_801504BC(int obj, int delta) {
    u8 *inner = *(u8 **)(obj + 0xb8);
    u8 *ptr = *(u8 **)(lbl_8031F16C + inner[0x33b] * 0x28 + 4);
    inner[0x33d] = (u8)(delta + (u32)ptr[8] + 1);
    inner[0x33e] = 1;
}
#pragma peephole reset
#pragma scheduling reset
