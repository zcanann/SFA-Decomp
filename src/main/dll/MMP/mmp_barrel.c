#include "main/dll/MMP/mmp_barrel.h"
#include "main/game_object.h"
#include "global.h"

/* waveanimator_getExtraSize == 0x3c (also the shared wave-grid config fed
 * to fn_801923F8; the grid/color/phase tables live in the lbl_803DDAEC/F0/F4
 * globals). */
typedef struct WaveAnimatorState {
    int originX;   /* 0x00 */
    int originY;   /* 0x04 */
    int spanX;     /* 0x08 */
    int spanY;     /* 0x0c */
    f32 ampX;      /* 0x10 */
    f32 ampY;      /* 0x14 */
    int unk18;     /* 0x18 */
    int period;    /* 0x1c */
    int gridN;     /* 0x20 */
    f32 minHeight; /* 0x24 */
    f32 maxHeight; /* 0x28 */
    f32 scaleA;    /* 0x2c */
    f32 scaleB;    /* 0x30 */
    u8 flags;      /* 0x34: 1 = scale pending, 2 = func0B latch */
    u8 pad35[7];
} WaveAnimatorState;
STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);

/* alphaanimator_getExtraSize == 0x1c. */
typedef struct AlphaAnimatorState {
    int vertCount;  /* 0x00 */
    f32 fadeA;      /* 0x04 */
    f32 fadeB;      /* 0x08 */
    f32 fadeMax;    /* 0x0c */
    void *buf;      /* 0x10: mode-3 per-vertex alpha buffer */
    s16 alphaLevel; /* 0x14 */
    u8 active;      /* 0x16 */
    u8 gateVal;     /* 0x17 */
    u8 doneCount;   /* 0x18 */
    u8 prevGate;    /* 0x19 */
    u8 pad1A[2];
} AlphaAnimatorState;
STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);

/* groundanimator_getExtraSize == 0x30. */
typedef struct GroundAnimatorState {
    int falloffBuf;       /* 0x00: f32 per-vertex weights */
    int heightBuf;        /* 0x04: s16 per-vertex base heights */
    int linkedObj;        /* 0x08: nearest group-4 object */
    f32 sinkDepth;        /* 0x0c */
    f32 lastDepth;        /* 0x10 */
    f32 radius;           /* 0x14 */
    f32 yOffset;          /* 0x18 */
    s16 blockEntries[6];  /* 0x1c: matching map-block entry indices */
    s16 vertCount;        /* 0x28 */
    u8 entryCount;        /* 0x2a */
    u8 modelVariant;      /* 0x2b */
    u8 dirtyFrames;       /* 0x2c */
    u8 flags;             /* 0x2d: 1 = on-map, 2 = done, 4 = pressed */
    u8 pad2E[2];
} GroundAnimatorState;
STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);

/* visanimator_getExtraSize == 0x5. */
typedef struct VisAnimatorState {
    u8 flags;    /* 0x00: 1 = refresh pending */
    s8 visBit;   /* 0x01 */
    u8 gateNow;  /* 0x02 */
    u8 gatePrev; /* 0x03 */
    u8 gateMask; /* 0x04 */
} VisAnimatorState;
STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

extern undefined4 FUN_80006824();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern int FUN_80017a90();
extern undefined4 FUN_80017a98();
extern int FUN_80017af0();
extern int ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern int FUN_800480a0();
extern int FUN_8005337c();
extern undefined4 FUN_80056418();
extern int FUN_80056448();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern undefined4 FUN_8005ff38();
extern undefined4 FUN_8005ff90();
extern uint FUN_80060058();
extern int FUN_80060064();
extern undefined4 FUN_800600b4();
extern int FUN_800600c4();
extern int FUN_800600e4();
extern undefined4 FUN_800631d4();
extern int FUN_80063298();
extern undefined4 FUN_801a8ae8();
extern undefined4 FUN_801a8b20();
extern undefined4 FUN_80242178();
extern uint FUN_80286810();
extern undefined8 FUN_8028681c();
extern undefined8 FUN_80286820();
extern undefined8 FUN_8028682c();
extern uint FUN_80286840();
extern undefined4 TRKNubMainLoop();
extern undefined4 FUN_80286868();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802924c4();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803de768;
extern undefined4 DAT_803de76c;
extern undefined4 DAT_803de770;
extern undefined4 DAT_803de774;
extern f64 DOUBLE_803e4c00;
extern f64 DOUBLE_803e4c20;
extern f64 DOUBLE_803e4c28;
extern f64 DOUBLE_803e4c38;
extern f64 DOUBLE_803e4c60;
extern f32 lbl_803DC074;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E4BDC;
extern f32 lbl_803E4BE8;
extern f32 lbl_803E4BEC;
extern f32 lbl_803E4BF0;
extern f32 lbl_803E4BF4;
extern f32 lbl_803E4BF8;
extern f32 lbl_803E4BFC;
extern f32 lbl_803E4C08;
extern f32 lbl_803E4C10;
extern f32 lbl_803E4C14;
extern f32 lbl_803E4C18;
extern f32 lbl_803E4C1C;
extern f32 lbl_803E4C30;
extern f32 lbl_803E4C40;
extern f32 lbl_803E4C44;
extern f32 lbl_803E4C48;
extern f32 lbl_803E4C4C;
extern f32 lbl_803E4C50;
extern f32 lbl_803E4C54;
extern f32 lbl_803E4C58;
extern f32 lbl_803E4C5C;

/*
 * --INFO--
 *
 * Function: waveanimator_func0B
 * EN v1.0 Address: 0x801923C4
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x801923CC
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void waveanimator_func0B(int *obj)
{
    WaveAnimatorState *p = (WaveAnimatorState *)((int **)obj)[0xb8 / 4];
    p->flags |= 2;
}

u8 wallanimator_func0B(int *obj)
{
    int *p = ((int **)obj)[0xb8 / 4];
    return *p >= WALLANIMATOR_DONE_TIMER;
}

extern void mm_free(void *p);
void alphaanimator_free(int *obj)
{
    AlphaAnimatorState *o = (AlphaAnimatorState *)((int **)obj)[0xb8 / 4];
    void *p = o->buf;
    if (p != NULL) mm_free(p);
}

/*
 * --INFO--
 *
 * Function: FUN_80192488
 * EN v1.0 Address: 0x80192488
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x801924D0
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80192488(void)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_8028682c();
  iVar2 = (int)((ulonglong)uVar13 >> 0x20);
  iVar8 = (int)uVar13;
  iVar10 = *(int *)(iVar2 + 0x4c);
  iVar3 = FUN_8005b398((double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x10));
  iVar3 = FUN_8005af70(iVar3);
  if (iVar3 == 0) {
    *(undefined *)(iVar8 + 0x10) = 1;
  }
  else {
    iVar4 = FUN_80017af0(0xe);
    if ((iVar4 != 0) &&
       (iVar10 = FUN_8005337c(-*(int *)(iVar4 + *(short *)(iVar10 + 0x18) * 4)), iVar10 != 0)) {
      for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar3 + 0xa2); iVar4 = iVar4 + 1) {
        iVar5 = FUN_800600e4(iVar3,iVar4);
        iVar12 = iVar5;
        for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)(iVar5 + 0x41); iVar11 = iVar11 + 1) {
          if (*(int *)(iVar12 + 0x24) == iVar10) {
            iVar7 = (uint)*(ushort *)(iVar10 + 10) << 6;
            iVar1 = (uint)*(ushort *)(iVar10 + 0xc) << 6;
            if (*(byte *)(iVar12 + 0x2a) == 0xff) {
              iVar7 = FUN_80056448((int)*(char *)(iVar8 + 0x11),(int)*(char *)(iVar8 + 0x12),iVar7,
                                   iVar1);
              *(char *)(iVar12 + 0x2a) = (char)iVar7;
            }
            else {
              iVar9 = *(int *)(*(int *)(iVar2 + 0x4c) + 0x14);
              if ((iVar9 == 0x49b2f) || (iVar9 == 0x49b67)) {
                uVar6 = GameBit_Get(*(uint *)(iVar8 + 8));
                if (uVar6 != 0) {
                  FUN_80056418((uint)*(byte *)(iVar12 + 0x2a),(int)*(char *)(iVar8 + 0x11),
                               (int)*(char *)(iVar8 + 0x12),iVar7,iVar1);
                }
              }
              else {
                FUN_80056418((uint)*(byte *)(iVar12 + 0x2a),(int)*(char *)(iVar8 + 0x11),
                             (int)*(char *)(iVar8 + 0x12),iVar7,iVar1);
              }
            }
          }
          iVar12 = iVar12 + 8;
        }
      }
    }
  }
  FUN_80286878();
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80192618
 * EN v1.0 Address: 0x80192618
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801926C4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80192618(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80192640
 * EN v1.0 Address: 0x80192640
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x801926F8
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80192640(int param_1)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)&((GameObject *)param_1)->extra;
  iVar1 = FUN_8005b398((double)((GameObject *)param_1)->anim.localPosX,(double)((GameObject *)param_1)->anim.localPosY);
  iVar1 = FUN_8005af70(iVar1);
  iVar2 = *(int *)(*(int *)&((GameObject *)param_1)->anim.placementData + 0x14);
  if ((((iVar2 == 0x49b2f) || (iVar2 == 0x49b67)) && (iVar1 != 0)) &&
     ((uVar3 = GameBit_Get(*(uint *)(iVar4 + 8)), *(uint *)(iVar4 + 0xc) != uVar3 &&
      (*(char *)(iVar4 + 0x10) == '\0')))) {
    FUN_80192488();
    *(undefined *)(iVar4 + 0x10) = 0;
  }
  uVar3 = GameBit_Get(*(uint *)(iVar4 + 8));
  *(uint *)(iVar4 + 0xc) = uVar3;
  if (iVar1 == 0) {
    *(undefined *)(iVar4 + 0x10) = 1;
  }
  else if (*(char *)(iVar4 + 0x10) != '\0') {
    FUN_80192488();
    *(undefined *)(iVar4 + 0x10) = 0;
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80192720
 * EN v1.0 Address: 0x80192720
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x801927E4
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80192720(int param_1,int param_2,int param_3)
{
  int iVar1;
  
  iVar1 = *(int *)&((GameObject *)param_1)->extra;
  *(undefined *)(iVar1 + 0x11) = *(undefined *)(param_2 + 0x1e);
  *(undefined *)(iVar1 + 0x12) = *(undefined *)(param_2 + 0x1f);
  *(undefined *)(iVar1 + 0x13) = *(undefined *)(param_2 + 0x1c);
  *(undefined *)(iVar1 + 0x14) = *(undefined *)(param_2 + 0x1d);
  if (param_3 == 0) {
    FUN_80192488();
  }
  *(int *)(iVar1 + 8) = (int)*(short *)(param_2 + 0x1a);
  *(undefined4 *)(iVar1 + 0xc) = 0xffffffff;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80192790
 * EN v1.0 Address: 0x80192790
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80192874
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80192790(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801927b8
 * EN v1.0 Address: 0x801927B8
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x80192974
 * EN v1.1 Size: 988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_801927b8(void)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  short sVar5;
  int iVar6;
  int iVar7;
  short sVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  double dVar13;
  double dVar14;
  
  iVar4 = FUN_8028682c();
  DAT_803de774 = FUN_80017830(*(int *)(iVar4 + 0x1c) * *(int *)(iVar4 + 0x1c) * 4,0xffffff);
  DAT_803de76c = FUN_80017830(*(int *)(iVar4 + 0x1c) * *(int *)(iVar4 + 0x1c) * 3,0xffffff);
  fVar3 = lbl_803E4BDC;
  *(float *)(iVar4 + 0x28) = lbl_803E4BDC;
  *(float *)(iVar4 + 0x24) = fVar3;
  iVar12 = 0;
  for (iVar11 = 0; fVar3 = lbl_803E4BDC, iVar11 < *(int *)(iVar4 + 0x1c); iVar11 = iVar11 + 1) {
    iVar7 = iVar12;
    for (iVar10 = 0; iVar10 < *(int *)(iVar4 + 0x1c); iVar10 = iVar10 + 1) {
      dVar13 = (double)FUN_80293f90();
      dVar14 = (double)(float)((double)*(float *)(iVar4 + 0x14) * dVar13);
      dVar13 = (double)FUN_80293f90();
      *(float *)(DAT_803de774 + iVar7) = (float)((double)*(float *)(iVar4 + 0x10) * dVar13 + dVar14)
      ;
      if (*(float *)(DAT_803de774 + iVar7) < *(float *)(iVar4 + 0x24)) {
        *(float *)(iVar4 + 0x24) = *(float *)(DAT_803de774 + iVar7);
      }
      if (*(float *)(iVar4 + 0x28) < *(float *)(DAT_803de774 + iVar7)) {
        *(float *)(iVar4 + 0x28) = *(float *)(DAT_803de774 + iVar7);
      }
      iVar7 = iVar7 + 4;
      iVar12 = iVar12 + 4;
    }
  }
  fVar1 = *(float *)(iVar4 + 0x24);
  iVar11 = 0;
  iVar12 = 0;
  for (iVar7 = 0; iVar7 < *(int *)(iVar4 + 0x1c); iVar7 = iVar7 + 1) {
    iVar10 = iVar11;
    iVar6 = iVar12;
    for (iVar9 = 0; iVar9 < *(int *)(iVar4 + 0x1c); iVar9 = iVar9 + 1) {
      if (fVar3 <= *(float *)(DAT_803de774 + iVar11)) {
        *(undefined *)(DAT_803de76c + iVar12) = 0xff;
        *(undefined *)(DAT_803de76c + iVar12 + 1) = 0xff;
        *(undefined *)(DAT_803de76c + iVar12 + 2) = 0xff;
      }
      else {
        fVar2 = (*(float *)(DAT_803de774 + iVar11) - *(float *)(iVar4 + 0x24)) / -fVar1;
        *(char *)(DAT_803de76c + iVar12) = (char)(int)(lbl_803E4BEC * fVar2 + lbl_803E4BE8);
        *(char *)(DAT_803de76c + iVar12 + 1) = (char)(int)(lbl_803E4BF4 * fVar2 + lbl_803E4BF0);
        *(char *)(DAT_803de76c + iVar12 + 2) = (char)(int)(lbl_803E4BFC * fVar2 + lbl_803E4BF8);
      }
      iVar11 = iVar11 + 4;
      iVar12 = iVar12 + 3;
      iVar10 = iVar10 + 4;
      iVar6 = iVar6 + 3;
    }
    iVar11 = iVar10;
    iVar12 = iVar6;
  }
  DAT_803de770 = FUN_80017830(*(int *)(iVar4 + 0x20) * *(int *)(iVar4 + 0x20) * 4,0xffffff);
  sVar8 = 0;
  iVar11 = 0;
  for (iVar12 = 0; iVar12 < *(int *)(iVar4 + 0x20); iVar12 = iVar12 + 1) {
    sVar5 = 0;
    iVar7 = iVar11;
    for (iVar10 = 0; iVar10 < *(int *)(iVar4 + 0x20); iVar10 = iVar10 + 1) {
      *(short *)(DAT_803de770 + iVar11) = sVar8;
      *(short *)(DAT_803de770 + iVar11 + 2) = sVar5;
      iVar11 = iVar11 + 4;
      iVar7 = iVar7 + 4;
      sVar5 = sVar5 + 10;
    }
    sVar8 = sVar8 + 10;
    iVar11 = iVar7;
  }
  FUN_80286878();
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80192ab4
 * EN v1.0 Address: 0x80192AB4
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x80192D50
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80192ab4(int param_1)
{
  DAT_803de768 = DAT_803de768 + -1;
  if (DAT_803de768 == '\0') {
    if (DAT_803de774 != 0) {
      FUN_80017814(DAT_803de774);
    }
    if (DAT_803de770 != 0) {
      FUN_80017814(DAT_803de770);
    }
    if (DAT_803de76c != 0) {
      FUN_80017814(DAT_803de76c);
    }
  }
  ObjGroup_RemoveObject(param_1,0x1b);
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80192b28
 * EN v1.0 Address: 0x80192B28
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80192DCC
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80192b28(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80192b50
 * EN v1.0 Address: 0x80192B50
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x80192EE8
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80192b50(int param_1,int param_2)
{
  double dVar1;
  float fVar2;
  int *piVar3;
  
  piVar3 = ((GameObject *)param_1)->extra;
  piVar3[6] = (int)*(char *)(param_2 + 0x20);
  *piVar3 = (int)*(short *)(param_2 + 0x18);
  piVar3[1] = (int)*(short *)(param_2 + 0x1a);
  piVar3[2] = (int)*(char *)(param_2 + 0x1c);
  piVar3[3] = (int)*(char *)(param_2 + 0x1d);
  dVar1 = DOUBLE_803e4c00;
  piVar3[4] = (int)(float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x1e) ^ 0x80000000)
                          - DOUBLE_803e4c00);
  piVar3[5] = (int)(float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x1f) ^ 0x80000000)
                          - dVar1);
  piVar3[7] = (int)*(char *)(param_2 + 0x21);
  piVar3[8] = (int)*(char *)(param_2 + 0x22);
  fVar2 = lbl_803E4C08;
  piVar3[0xb] = (int)lbl_803E4C08;
  piVar3[0xc] = (int)fVar2;
  if (DAT_803de768 == '\0') {
    FUN_801927b8();
  }
  ObjGroup_AddObject(param_1,0x1b);
  DAT_803de768 = DAT_803de768 + '\x01';
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80192c90
 * EN v1.0 Address: 0x80192C90
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x80192FF4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192c90(int param_1)
{
  uint uVar1;
  
  uVar1 = *(uint *)(*(int *)&((GameObject *)param_1)->extra + 0x10);
  if (uVar1 != 0) {
    FUN_80017814(uVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80192cc0
 * EN v1.0 Address: 0x80192CC0
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80193024
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80192cc0(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80192ce8
 * EN v1.0 Address: 0x80192CE8
 * EN v1.0 Size: 1680b
 * EN v1.1 Address: 0x80193058
 * EN v1.1 Size: 1584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80192ce8(void)
{
  byte bVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  byte bVar7;
  int *piVar8;
  int iVar9;
  
  uVar3 = FUN_80286840();
  iVar9 = *(int *)(uVar3 + 0x4c);
  piVar8 = *(int **)(uVar3 + 0xb8);
  bVar1 = *(byte *)(iVar9 + 0x20);
  bVar7 = bVar1 & 3;
  iVar4 = FUN_8005b398((double)*(float *)(uVar3 + 0xc),(double)*(float *)(uVar3 + 0x10));
  iVar4 = FUN_8005af70(iVar4);
  if (iVar4 == 0) {
    *(undefined *)(piVar8 + 6) = 0;
  }
  else if ((*(ushort *)(iVar4 + 4) & 8) != 0) {
    if (*piVar8 == 0) {
      *(undefined *)((int)piVar8 + 0x16) = *(undefined *)(iVar9 + 0x1e);
      if (*piVar8 == 0) {
        *(undefined *)((int)piVar8 + 0x16) = 0;
      }
      fVar2 = lbl_803E4C14;
      if (*(char *)((int)piVar8 + 0x16) == '\0') goto LAB_8019364c;
      piVar8[1] = (int)lbl_803E4C14;
      piVar8[2] = (int)fVar2;
      piVar8[3] = (int)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar9 + 0x22)) -
                              DOUBLE_803e4c20);
      if ((int)*(short *)(iVar9 + 0x18) == 0xffffffff) {
        *(undefined *)((int)piVar8 + 0x17) = 1;
      }
      else {
        uVar5 = GameBit_Get((int)*(short *)(iVar9 + 0x18));
        *(char *)((int)piVar8 + 0x17) = (char)uVar5;
      }
      *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1c);
      if (((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) &&
         (uVar5 = GameBit_Get((int)*(short *)(iVar9 + 0x1a)), uVar5 != 0)) {
        *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
        piVar8[1] = (int)(lbl_803E4C10 + (float)piVar8[3]);
        *(undefined *)((int)piVar8 + 0x17) = 1;
      }
      if (bVar7 == 3) {
        iVar6 = FUN_80017830(*piVar8 << 2,5);
        piVar8[4] = iVar6;
      }
      *(ushort *)(iVar4 + 4) = *(ushort *)(iVar4 + 4) ^ 1;
      *(ushort *)(iVar4 + 4) = *(ushort *)(iVar4 + 4) ^ 1;
    }
    if (*(char *)((int)piVar8 + 0x16) != '\0') {
      if (bVar7 == 2) {
        uVar5 = GameBit_Get((int)*(short *)(iVar9 + 0x18));
        *(char *)((int)piVar8 + 0x17) = (char)uVar5;
        if (('\x02' < *(char *)(piVar8 + 6)) &&
           (*(char *)((int)piVar8 + 0x17) != *(char *)((int)piVar8 + 0x19))) {
          if ((int)(uint)*(byte *)(iVar9 + 0x20) >> 2 != 0) {
            FUN_80006824(uVar3,*(ushort *)(iVar9 + 0x24));
          }
          *(undefined *)(piVar8 + 6) = 0;
          *(undefined *)((int)piVar8 + 0x19) = *(undefined *)((int)piVar8 + 0x17);
        }
        if ('\x02' < *(char *)(piVar8 + 6)) goto LAB_8019364c;
      }
      else {
        if ('\x02' < *(char *)(piVar8 + 6)) goto LAB_8019364c;
        if (*(char *)((int)piVar8 + 0x17) == '\0') {
          uVar5 = GameBit_Get((int)*(short *)(iVar9 + 0x18));
          *(char *)((int)piVar8 + 0x17) = (char)uVar5;
          if (*(char *)((int)piVar8 + 0x17) == '\0') goto LAB_8019364c;
          if ((int)(uint)*(byte *)(iVar9 + 0x20) >> 2 != 0) {
            FUN_80006824(uVar3,*(ushort *)(iVar9 + 0x24));
          }
        }
      }
      if (bVar7 == 2) {
        if (*(char *)((int)piVar8 + 0x17) == '\0') {
          if (*(byte *)(iVar9 + 0x1d) < *(byte *)(iVar9 + 0x1c)) {
            *(ushort *)(piVar8 + 5) =
                 *(short *)(piVar8 + 5) + (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
            if ((short)(ushort)*(byte *)(iVar9 + 0x1c) <= *(short *)(piVar8 + 5)) {
              *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1c);
              if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
                GameBit_Set((int)*(short *)(iVar9 + 0x1a),0);
              }
              *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
            }
          }
          else {
            *(ushort *)(piVar8 + 5) =
                 *(short *)(piVar8 + 5) - (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
            if (*(short *)(piVar8 + 5) <= (short)(ushort)*(byte *)(iVar9 + 0x1c)) {
              *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1c);
              if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
                GameBit_Set((int)*(short *)(iVar9 + 0x1a),0);
              }
              *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
            }
          }
        }
        else if (*(byte *)(iVar9 + 0x1d) < *(byte *)(iVar9 + 0x1c)) {
          *(ushort *)(piVar8 + 5) =
               *(short *)(piVar8 + 5) - (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
          if (*(short *)(piVar8 + 5) <= (short)(ushort)*(byte *)(iVar9 + 0x1d)) {
            *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
            if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
              GameBit_Set((int)*(short *)(iVar9 + 0x1a),1);
            }
            *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
          }
        }
        else {
          *(ushort *)(piVar8 + 5) =
               *(short *)(piVar8 + 5) + (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
          if ((short)(ushort)*(byte *)(iVar9 + 0x1d) <= *(short *)(piVar8 + 5)) {
            *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
            if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
              GameBit_Set((int)*(short *)(iVar9 + 0x1a),1);
            }
            *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
          }
        }
      }
      else if (bVar7 < 2) {
        if ((bVar1 & 3) == 0) {
          if (*(byte *)(iVar9 + 0x1d) < *(byte *)(iVar9 + 0x1c)) {
            *(ushort *)(piVar8 + 5) =
                 *(short *)(piVar8 + 5) - (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
            if (*(short *)(piVar8 + 5) <= (short)(ushort)*(byte *)(iVar9 + 0x1d)) {
              *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
              if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
                GameBit_Set((int)*(short *)(iVar9 + 0x1a),1);
              }
              *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
            }
          }
          else {
            *(ushort *)(piVar8 + 5) =
                 *(short *)(piVar8 + 5) + (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
            if ((short)(ushort)*(byte *)(iVar9 + 0x1d) <= *(short *)(piVar8 + 5)) {
              *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
              if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
                GameBit_Set((int)*(short *)(iVar9 + 0x1a),1);
              }
              *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
            }
          }
        }
        else if (*(byte *)(iVar9 + 0x1d) < *(byte *)(iVar9 + 0x1c)) {
          *(ushort *)(piVar8 + 5) =
               *(short *)(piVar8 + 5) - (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
          if (*(short *)(piVar8 + 5) < (short)(ushort)*(byte *)(iVar9 + 0x1d)) {
            *(ushort *)(piVar8 + 5) =
                 (ushort)*(byte *)(iVar9 + 0x1c) -
                 ((ushort)*(byte *)(iVar9 + 0x1d) - *(short *)(piVar8 + 5));
          }
        }
        else {
          *(ushort *)(piVar8 + 5) =
               *(short *)(piVar8 + 5) + (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
          if ((short)(ushort)*(byte *)(iVar9 + 0x1c) < *(short *)(piVar8 + 5)) {
            *(short *)(piVar8 + 5) = *(short *)(piVar8 + 5);
          }
        }
      }
      else if (bVar7 < 4) {
        uVar3 = (uint)*(char *)(iVar9 + 0x1f);
        if ((int)uVar3 < 0) {
          uVar3 = -uVar3;
        }
        piVar8[1] = (int)(((float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e4c28
                                  ) / lbl_803E4C18) * lbl_803DC074 + (float)piVar8[1]);
        if ((float)piVar8[3] < (float)piVar8[1]) {
          piVar8[1] = piVar8[3];
          GameBit_Set((int)*(short *)(iVar9 + 0x1a),1);
          *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
        }
        piVar8[2] = (int)((float)piVar8[1] - lbl_803E4C1C);
      }
    }
  }
LAB_8019364c:
  FUN_8028688c();
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80193378
 * EN v1.0 Address: 0x80193378
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x80193688
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
uint FUN_80193378(int param_1)
{
  return ((uint)(byte)((lbl_803E4C30 *
                        (float)((double)CONCAT44(0x43300000,
                                                 (uint)*(byte *)(*(int *)&((GameObject *)param_1)->anim.placementData + 0x20)) -
                               DOUBLE_803e4c38) < *(float *)(*(int *)&((GameObject *)param_1)->extra + 0xc)) << 2)
         << 0x1c) >> 0x1e;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801933d8
 * EN v1.0 Address: 0x801933D8
 * EN v1.0 Size: 364b
 * EN v1.1 Address: 0x801936D0
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
double FUN_801933d8(int param_1,int param_2)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  
  iVar5 = *(int *)&((GameObject *)param_1)->extra;
  iVar6 = *(int *)&((GameObject *)param_1)->anim.placementData;
  fVar1 = *(float *)(param_2 + 0x10) - ((GameObject *)param_1)->anim.localPosY;
  if ((fVar1 < lbl_803E4C40) || (lbl_803E4C44 < fVar1)) {
    dVar7 = (double)lbl_803E4C48;
  }
  else {
    fVar1 = *(float *)(param_2 + 0xc) - ((GameObject *)param_1)->anim.localPosX;
    fVar2 = *(float *)(param_2 + 0x14) - ((GameObject *)param_1)->anim.localPosZ;
    fVar3 = lbl_803E4C4C + *(float *)(iVar5 + 0x14);
    if (fVar1 * fVar1 + fVar2 * fVar2 <= fVar3 * fVar3) {
      fVar1 = lbl_803E4C30 *
              (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x20)) - DOUBLE_803e4c38);
      if ((fVar1 <= *(float *)(iVar5 + 0xc)) && (*(int *)(iVar5 + 8) != 0)) {
        *(float *)(iVar5 + 0xc) = fVar1;
        iVar4 = *(int *)(iVar5 + 8);
        if (*(short *)(iVar4 + 0x46) == 0x519) {
          FUN_801a8b20(iVar4,'\0');
        }
        else {
          (**(code **)(**(int **)(iVar4 + 0x68) + 0x24))(iVar4,0);
        }
      }
      *(float *)(iVar5 + 0xc) = lbl_803E4C54 * lbl_803DC074 + *(float *)(iVar5 + 0xc);
      *(byte *)(iVar5 + 0x2d) = *(byte *)(iVar5 + 0x2d) | 4;
      dVar7 = (double)(*(float *)(iVar5 + 0x14) *
                      (*(float *)(iVar5 + 0xc) /
                      (lbl_803E4C30 *
                      (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x20)) -
                             DOUBLE_803e4c38))));
    }
    else {
      dVar7 = (double)lbl_803E4C50;
    }
  }
  return dVar7;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80193544
 * EN v1.0 Address: 0x80193544
 * EN v1.0 Size: 700b
 * EN v1.1 Address: 0x80193844
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80193544(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  ushort *puVar3;
  uint uVar4;
  ushort *puVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double in_f28;
  double in_f29;
  double in_f30;
  double dVar18;
  double in_f31;
  double dVar19;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar20;
  float local_a8;
  float local_a4;
  float local_a0;
  longlong local_98;
  longlong local_90;
  undefined4 local_88;
  uint uStack_84;
  undefined8 local_80;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar20 = FUN_8028681c();
  iVar8 = (int)((ulonglong)uVar20 >> 0x20);
  piVar6 = (int *)uVar20;
  iVar2 = FUN_8005b398((double)*(float *)(iVar8 + 0xc),(double)*(float *)(iVar8 + 0x10));
  iVar2 = FUN_8005af70(iVar2);
  if ((iVar2 != 0) && ((*(ushort *)(iVar2 + 4) & 8) != 0)) {
    dVar16 = (double)FUN_802924c4();
    local_98 = (longlong)(int)dVar16;
    dVar17 = (double)FUN_802924c4();
    local_90 = (longlong)(int)dVar17;
    uStack_84 = (int)dVar16 ^ 0x80000000;
    local_88 = 0x43300000;
    dVar19 = (double)(*(float *)(iVar8 + 0xc) -
                     (lbl_803E4C58 *
                      (f32)(s32)uStack_84 +
                     lbl_803DDA58));
    dVar17 = (double)(*(float *)(iVar8 + 0x14) -
                     (lbl_803E4C58 * (f32)(s32)((int)dVar17) + lbl_803DDA5C));
    iVar10 = 0;
    *(undefined *)((int)piVar6 + 0x2a) = 0;
    dVar16 = (double)((float)piVar6[5] * (float)piVar6[5]);
    iVar9 = 0;
    for (iVar8 = 0; iVar8 < (int)(uint)*(ushort *)(iVar2 + 0x9a); iVar8 = iVar8 + 1) {
      puVar3 = (ushort *)FUN_800600c4(iVar2,iVar8);
      uVar4 = FUN_80060058((int)puVar3);
      if (*(byte *)(param_3 + 0x25) == uVar4) {
        dVar18 = (double)lbl_803E4C5C;
        iVar11 = iVar9;
        iVar12 = iVar10;
        for (uVar4 = (uint)*puVar3; (int)uVar4 < (int)(uint)puVar3[10]; uVar4 = uVar4 + 1) {
          puVar5 = (ushort *)FUN_800600b4(iVar2,uVar4);
          iVar7 = 0;
          iVar13 = iVar11;
          iVar14 = iVar12;
          do {
            FUN_8005ff90((short *)(*(int *)(iVar2 + 0x58) + (uint)*puVar5 * 6),&local_a8);
            dVar15 = (double)(float)((double)((float)((double)local_a8 - dVar19) *
                                              (float)((double)local_a8 - dVar19) +
                                             (float)((double)local_a0 - dVar17) *
                                             (float)((double)local_a0 - dVar17)) / dVar16);
            if (dVar18 < dVar15) {
              dVar15 = dVar18;
            }
            *(float *)(*piVar6 + iVar14) = (float)(dVar18 - (double)(float)(dVar15 * dVar15));
            local_80 = (double)(longlong)(int)local_a4;
            *(short *)(piVar6[1] + iVar13) = (short)(int)local_a4;
            iVar14 = iVar14 + 4;
            iVar13 = iVar13 + 2;
            iVar12 = iVar12 + 4;
            iVar11 = iVar11 + 2;
            iVar10 = iVar10 + 4;
            iVar9 = iVar9 + 2;
            puVar5 = puVar5 + 1;
            iVar7 = iVar7 + 1;
          } while (iVar7 < 3);
        }
        bVar1 = *(byte *)((int)piVar6 + 0x2a);
        *(byte *)((int)piVar6 + 0x2a) = bVar1 + 1;
        *(short *)((int)piVar6 + (uint)bVar1 * 2 + 0x1c) = (short)iVar8;
      }
    }
  }
  FUN_80286868();
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80193800
 * EN v1.0 Address: 0x80193800
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x80193ACC
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80193800(void)
{
  int iVar1;
  int iVar2;
  ushort *puVar3;
  ushort *puVar4;
  uint uVar5;
  uint uVar6;
  short *psVar7;
  int iVar8;
  uint *puVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  undefined8 uVar15;
  float fStack_58;
  float local_54;
  undefined4 local_48;
  uint uStack_44;
  
  uVar15 = FUN_80286820();
  iVar1 = (int)((ulonglong)uVar15 >> 0x20);
  puVar9 = *(uint **)(iVar1 + 0xb8);
  iVar8 = *(int *)(iVar1 + 0x4c);
  if ((int)uVar15 == 0) {
    iVar2 = FUN_8005b398((double)*(float *)(iVar1 + 0xc),(double)*(float *)(iVar1 + 0x10));
    iVar2 = FUN_8005af70(iVar2);
    if (iVar2 != 0) {
      iVar12 = 0;
      for (iVar11 = 0; iVar11 < (int)(uint)*(ushort *)(iVar2 + 0x9a); iVar11 = iVar11 + 1) {
        puVar3 = (ushort *)FUN_800600c4(iVar2,iVar11);
        uVar6 = FUN_80060058((int)puVar3);
        if (*(byte *)(iVar8 + 0x25) == uVar6) {
          iVar13 = iVar12;
          for (uVar6 = (uint)*puVar3; (int)uVar6 < (int)(uint)puVar3[10]; uVar6 = uVar6 + 1) {
            puVar4 = (ushort *)FUN_800600b4(iVar2,uVar6);
            iVar10 = 0;
            iVar14 = iVar13;
            do {
              psVar7 = (short *)(*(int *)(iVar2 + 0x58) + (uint)*puVar4 * 6);
              FUN_8005ff90(psVar7,&fStack_58);
              uVar5 = puVar9[1];
              if (uVar5 != 0) {
                uStack_44 = (int)*(short *)(uVar5 + iVar14) ^ 0x80000000;
                local_48 = 0x43300000;
                local_54 = (f32)(s32)uStack_44;
                FUN_8005ff38(psVar7,&fStack_58);
              }
              iVar14 = iVar14 + 2;
              iVar13 = iVar13 + 2;
              iVar12 = iVar12 + 2;
              puVar4 = puVar4 + 1;
              iVar10 = iVar10 + 1;
            } while (iVar10 < 3);
          }
        }
      }
    }
  }
  uVar6 = *puVar9;
  if (uVar6 != 0) {
    FUN_80017814(uVar6);
  }
  ObjGroup_RemoveObject(iVar1,0x31);
  FUN_8028686c();
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80193924
 * EN v1.0 Address: 0x80193924
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80193C2C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80193924(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8019394c
 * EN v1.0 Address: 0x8019394C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80193C5C
 * EN v1.1 Size: 1500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019394c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80193950
 * EN v1.0 Address: 0x80193950
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x80194238
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80193950(int param_1,int param_2)
{
  double dVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)&((GameObject *)param_1)->extra;
  *(char *)(iVar3 + 0x2b) = (char)*(undefined2 *)(param_2 + 0x1e);
  dVar1 = DOUBLE_803e4c38;
  *(float *)(iVar3 + 0x18) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x27)) - DOUBLE_803e4c38);
  *(float *)(iVar3 + 0x10) = lbl_803E4C50;
  *(float *)(iVar3 + 0x14) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x26)) - dVar1);
  if (*(char *)(param_2 + 0x25) != '\0') {
    uVar2 = GameBit_Get((int)*(short *)(param_2 + 0x18));
    if (uVar2 != 0) {
      *(float *)(iVar3 + 0xc) =
           lbl_803E4C30 *
           (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x20)) - DOUBLE_803e4c38);
      *(byte *)(iVar3 + 0x2d) = *(byte *)(iVar3 + 0x2d) | 2;
    }
    ObjGroup_AddObject(param_1,0x31);
    if (1 < *(byte *)(param_2 + 0x21)) {
      *(undefined *)(param_2 + 0x21) = 0;
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80193a50
 * EN v1.0 Address: 0x80193A50
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x80194338
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80193a50(undefined4 param_1,undefined4 param_2,char *param_3,int param_4)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar1 = FUN_80286840();
  if ((*(byte *)(param_4 + 0x1c) & 0x10) == 0) {
    for (iVar5 = 0; iVar5 < (int)(uint)*(ushort *)(iVar1 + 0x9a); iVar5 = iVar5 + 1) {
      iVar3 = FUN_800600c4(iVar1,iVar5);
      uVar2 = FUN_80060058(iVar3);
      if (*(byte *)(param_4 + 0x1b) == uVar2) {
        if (*param_3 == '\0') {
          *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) | 2;
          if ((*(byte *)(param_4 + 0x1c) & 2) != 0) {
            *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) | 1;
          }
        }
        else {
          *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) & 0xfffffffd;
          if ((*(byte *)(param_4 + 0x1c) & 2) != 0) {
            *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) & ~1;
          }
        }
      }
    }
  }
  if ((*(byte *)(param_4 + 0x1c) & 2) != 0) {
    for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(iVar1 + 0xa2); iVar5 = iVar5 + 1) {
      iVar3 = FUN_800600e4(iVar1,iVar5);
      iVar4 = FUN_800480a0(iVar3,0);
      if (*(char *)(param_4 + 0x1b) == *(char *)(iVar4 + 5)) {
        if (*param_3 == '\0') {
          *(uint *)(iVar3 + 0x3c) = *(uint *)(iVar3 + 0x3c) | 2;
        }
        else {
          *(uint *)(iVar3 + 0x3c) = *(uint *)(iVar3 + 0x3c) & 0xfffffffd;
        }
      }
    }
  }
  FUN_8028688c();
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80193ba8
 * EN v1.0 Address: 0x80193BA8
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x801944AC
 * EN v1.1 Size: 476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80193ba8(int param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  int iVar5;
  
  iVar5 = *(int *)&((GameObject *)param_1)->anim.placementData;
  pbVar4 = ((GameObject *)param_1)->extra;
  iVar1 = FUN_8005b398((double)((GameObject *)param_1)->anim.localPosX,(double)((GameObject *)param_1)->anim.localPosY);
  iVar1 = FUN_8005af70(iVar1);
  if (iVar1 == 0) {
    pbVar4[1] = pbVar4[1] & 0xfe;
    pbVar4[1] = pbVar4[1] | 4;
  }
  else {
    uVar2 = GameBit_Get((int)*(short *)(iVar5 + 0x18));
    pbVar4[2] = (byte)uVar2;
    if (pbVar4[3] != pbVar4[2]) {
      *pbVar4 = *pbVar4 ^ 1;
      if (*(char *)(iVar5 + 0x1a) == '\x01') {
        pbVar4[1] = pbVar4[1] | 1;
      }
      if ((*(byte *)(iVar5 + 0x1c) & 8) != 0) {
        pbVar4[1] = pbVar4[1] | 2;
      }
      if ((*(byte *)(iVar5 + 0x1c) & 4) != 0) {
        pbVar4[1] = pbVar4[1] | 4;
      }
    }
    pbVar4[3] = pbVar4[2];
    if ((*(byte *)(iVar5 + 0x1c) & 8) != 0) {
      iVar3 = FUN_80063298();
      if (iVar3 != 0) {
        pbVar4[1] = pbVar4[1] | 2;
      }
      if (((pbVar4[1] & 2) != 0) && (iVar3 = FUN_80063298(), iVar3 == 0)) {
        FUN_800631d4((uint)*(byte *)(iVar5 + 0x1d),*(int *)&((GameObject *)param_1)->anim.parent,(int)(char)*pbVar4);
        pbVar4[1] = pbVar4[1] & 0xfd;
      }
    }
    if ((((*(byte *)(iVar5 + 0x1c) & 4) != 0) && (*(char *)(iVar5 + 0x1b) != '\0')) &&
       ((pbVar4[1] & 4) != 0)) {
      FUN_80193a50(iVar1,param_1,(char *)pbVar4,iVar5);
      pbVar4[1] = pbVar4[1] & 0xfb;
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */
void waveanimator_update(void) {}
void waveanimator_release(void) {}
void waveanimator_initialise(void) {}
void alphaanimator_hitDetect(void) {}
void alphaanimator_release(void) {}
void alphaanimator_initialise(void) {}
void visanimator_free(void) {}
void visanimator_render(void) {}
void visanimator_hitDetect(void) {}
void visanimator_release(void) {}
void visanimator_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int waveanimator_getExtraSize(void) { return 0x3c; }
int waveanimator_getObjectTypeId(void) { return 0x0; }
int alphaanimator_getExtraSize(void) { return 0x1c; }
int alphaanimator_getObjectTypeId(void) { return 0x0; }
int groundanimator_getExtraSize(void) { return 0x30; }
int hitanimator_getExtraSize(void) { return 0x4; }
int visanimator_getExtraSize(void) { return 0x5; }
int visanimator_getObjectTypeId(void) { return 0x0; }

/* Pattern wrappers. */
u8 groundanimator_modelMtxFn(int *obj) { return *(u8*)((char*)((int**)obj)[0xb8/4] + 0x2b); }

/* 16b chained patterns. */
void alphaanimator_init(int *obj) { s8 v = -1; *(s8 *)&((AlphaAnimatorState *)((int**)obj)[0xb8/4])->prevGate = v; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3F70;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3F78;
extern f32 lbl_803E3FC4;
void waveanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3F70); }
void alphaanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3F78); }
void groundanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3FC4); }

/* wall variant: hashes lha to byte */
u8 wallanimator_modelMtxFn(int *obj) { return (u8)*(s16 *)((char *)((int **)obj)[0x4c/4] + 0x1c); }
void waveanimator_setScale(int *obj, f32 fval)
{
  WaveAnimatorState *p = (WaveAnimatorState *)((int **)obj)[0xb8 / 4];
  p->flags |= 1;
  p->scaleB = fval;
}

extern f32 lbl_803E3F98;
u8 groundanimator_func0B(int *obj)
{
    GroundAnimatorState *p1 = (GroundAnimatorState *)((int **)obj)[0xB8 / 4];
    f32 v = p1->sinkDepth;
    int *p2 = ((int **)obj)[0x4C / 4];
    u8 byte = *(u8 *)((char *)p2 + 0x20);
    return v > lbl_803E3F98 * (f32)byte;
}

extern int objPosToMapBlockIdx(double x, double y, double z);
extern void *mapGetBlock(int idx);
extern void fn_801923F8(int *cfg);
extern void hitAnimatorFn_80193dbc(void *block, HitAnimatorObject *obj, HitAnimatorState *vstate, HitAnimatorPlacement *desc);
extern int fn_80065640(void);
extern void fn_80065574(int a, int b, int c);
extern u8 lbl_803DDAE8;
void waveanimator_init(int *obj, int *desc)
{
    WaveAnimatorState *vstate = (WaveAnimatorState *)((int**)obj)[0xB8/4];
    f32 fz;
    vstate->unk18 = *(s8 *)((char*)desc + 0x20);
    vstate->originX = *(s16*)((char*)desc + 0x18);
    vstate->originY = *(s16*)((char*)desc + 0x1A);
    vstate->spanX = *(s8 *)((char*)desc + 0x1C);
    vstate->spanY = *(s8 *)((char*)desc + 0x1D);
    vstate->ampX = (f32)*(s8*)((char*)desc + 0x1E);
    vstate->ampY = (f32)*(s8*)((char*)desc + 0x1F);
    vstate->period = *(s8 *)((char*)desc + 0x21);
    vstate->gridN = *(s8 *)((char*)desc + 0x22);
    fz = lbl_803E3F70;
    vstate->scaleA = fz;
    vstate->scaleB = fz;
    if (lbl_803DDAE8 == 0) {
        fn_801923F8((int *)vstate);
    }
    ObjGroup_AddObject(obj, 27);
    lbl_803DDAE8++;
}

void hitanimator_update(HitAnimatorObject *obj)
{
    HitAnimatorPlacement *setup = (HitAnimatorPlacement *)obj->objAnim.placementData;
    HitAnimatorState *state = obj->state;
    void *block;
    block = mapGetBlock(objPosToMapBlockIdx(
        (double)obj->objAnim.localPosX,
        (double)obj->objAnim.localPosY,
        (double)obj->objAnim.localPosZ));
    if (block == NULL) {
        state->flags &= ~HITANIMATOR_STATE_FLAG_TOGGLE_PENDING;
        state->flags |= HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING;
        return;
    }
    state->gameBitValue = (u8)GameBit_Get(setup->gameBit);
    if (state->previousGameBitValue != state->gameBitValue) {
        state->activeBit = state->activeBit ^ 1;
        if (setup->toggleMode == 1) {
            state->flags |= HITANIMATOR_STATE_FLAG_TOGGLE_PENDING;
        }
        if ((setup->flags & HITANIMATOR_SETUP_FLAG_SOUND) != 0) {
            state->flags |= HITANIMATOR_STATE_FLAG_SOUND_PENDING;
        }
        if ((setup->flags & HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE) != 0) {
            state->flags |= HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING;
        }
    }
    state->previousGameBitValue = state->gameBitValue;
    if ((setup->flags & HITANIMATOR_SETUP_FLAG_SOUND) != 0) {
        if (fn_80065640() != 0) {
            state->flags |= HITANIMATOR_STATE_FLAG_SOUND_PENDING;
        }
        if ((state->flags & HITANIMATOR_STATE_FLAG_SOUND_PENDING) != 0) {
            if (fn_80065640() == 0) {
                fn_80065574(setup->soundId, (int)obj->objAnim.parent, state->activeBit);
                state->flags &= ~HITANIMATOR_STATE_FLAG_SOUND_PENDING;
            }
        }
    }
    if ((setup->flags & HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE) != 0) {
        if (setup->blockEffectId != 0) {
            if ((state->flags & HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING) != 0) {
                hitAnimatorFn_80193dbc(block, obj, state, setup);
                state->flags &= ~HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING;
            }
        }
    }
}

extern f32 lbl_803E3FB8;
void groundanimator_init(int *obj, int *desc)
{
    GroundAnimatorState *vstate = (GroundAnimatorState *)((int**)obj)[0xB8/4];
    vstate->modelVariant = (u8)*(s16*)((char*)desc + 0x1E);
    vstate->yOffset = (f32)*(u8*)((char*)desc + 0x27);
    vstate->lastDepth = lbl_803E3FB8;
    vstate->radius = (f32)*(u8*)((char*)desc + 0x26);
    if (*(u8*)((char*)desc + 0x25) != 0) {
        if (GameBit_Get(*(s16*)((char*)desc + 0x18)) != 0) {
            vstate->sinkDepth = lbl_803E3F98 * (f32)*(u8*)((char*)desc + 0x20);
            vstate->flags |= 2;
        }
        ObjGroup_AddObject(obj, 49);
        if (*(u8*)((char*)desc + 0x21) > 1) {
            *(u8*)((char*)desc + 0x21) = 0;
        }
    }
}

void hitanimator_init(HitAnimatorObject *obj, HitAnimatorPlacement *desc)
{
    HitAnimatorState *state = obj->state;
    void *block;
    u8 g;
    s8 init_bit;
    init_bit = (s8)(desc->flags & HITANIMATOR_SETUP_FLAG_INITIAL_INVERT);
    state->activeBit = init_bit;
    state->flags = 0;
    if (GameBit_Get(desc->gameBit) != 0) {
        state->activeBit = state->activeBit ^ 1;
        if (desc->toggleMode == 1) {
            state->flags |= HITANIMATOR_STATE_FLAG_TOGGLE_PENDING;
        }
    }
    block = mapGetBlock(objPosToMapBlockIdx(
        (double)obj->objAnim.localPosX,
        (double)obj->objAnim.localPosY,
        (double)obj->objAnim.localPosZ));
    if (block != NULL) {
        if ((desc->flags & HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE) != 0 && desc->blockEffectId != 0) {
            hitAnimatorFn_80193dbc(block, obj, state, desc);
        }
    }
    state->flags |= HITANIMATOR_STATE_FLAG_SOUND_PENDING;
    if ((desc->flags & HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE) != 0) {
        state->flags |= HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING;
    }
    g = (u8)GameBit_Get(desc->gameBit);
    state->gameBitValue = g;
    state->previousGameBitValue = g;
    obj->objectFlags |= HITANIMATOR_OBJECT_FLAGS_ENABLED;
}

void visanimator_init(int *obj, int *desc)
{
    VisAnimatorState *vstate;
    u32 gate;
    u8 tmp;
    int sv;
    ((GameObject *)obj)->objectFlags |= 0x6000;
    vstate = (VisAnimatorState *)((int**)obj)[0xB8/4];
    sv = *(s8*)((char*)desc + 0x1B);
    vstate->visBit = (s8)sv;
    vstate->gateMask = (u8)(1 << *(u8*)((char*)desc + 0x1C));
    gate = (u32)GameBit_Get(*(s16*)((char*)desc + 0x18));
    if ((vstate->gateMask & gate) != 0) {
        vstate->visBit = vstate->visBit ^ 1;
    }
    mapGetBlock(objPosToMapBlockIdx((double)((GameObject *)obj)->anim.localPosX,
                                     (double)((GameObject *)obj)->anim.localPosY,
                                     (double)((GameObject *)obj)->anim.localPosZ));
    gate = (u32)GameBit_Get(*(s16*)((char*)desc + 0x18));
    tmp = (u8)(vstate->gateMask & gate);
    vstate->gateNow = tmp;
    vstate->gatePrev = tmp;
    vstate->flags |= 1;
}

void visanimator_update(int *obj)
{
    int *state = ((int**)obj)[0x4C / 4];
    VisAnimatorState *vstate = (VisAnimatorState *)((int**)obj)[0xB8 / 4];
    int idx = objPosToMapBlockIdx((double)((GameObject *)obj)->anim.localPosX,
                                  (double)((GameObject *)obj)->anim.localPosY,
                                  (double)((GameObject *)obj)->anim.localPosZ);
    if (mapGetBlock(idx) == NULL) {
        vstate->flags |= 1;
        return;
    }
    {
        int gate = GameBit_Get(*(s16*)((char*)state + 0x18));
        vstate->gateNow = (u8)(vstate->gateMask & gate);
        if (vstate->gatePrev != vstate->gateNow) {
            vstate->visBit = (s8)(vstate->visBit ^ 1);
            vstate->flags |= 1;
        }
        vstate->gatePrev = vstate->gateNow;
        if (vstate->flags & 1) {
            vstate->flags &= ~1;
        }
    }
}

extern void *lbl_803DDAEC;
extern void *lbl_803DDAF0;
extern void *lbl_803DDAF4;
void waveanimator_free(int *obj)
{
    if (--lbl_803DDAE8 == 0) {
        if (lbl_803DDAF4 != NULL) mm_free(lbl_803DDAF4);
        if (lbl_803DDAF0 != NULL) mm_free(lbl_803DDAF0);
        if (lbl_803DDAEC != NULL) mm_free(lbl_803DDAEC);
    }
    ObjGroup_RemoveObject(obj, 27);
}
extern u8 lbl_803DDAF8;
extern u8 framesThisStep;
void waveanimator_hitDetect(int *obj) {
    int i;
    int j;
    int off;
    WaveAnimatorState *w;
    if (lbl_803DDAF8 != 0) {
        return;
    }
    w = (WaveAnimatorState *)obj[46];
    off = 0;
    for (i = 0; i < w->gridN; i++) {
        for (j = 0; j < w->gridN; j++) {
            ((s16 *)lbl_803DDAF0)[off] += framesThisStep >> 1;
            while (((s16 *)lbl_803DDAF0)[off] >= w->period) {
                ((s16 *)lbl_803DDAF0)[off] -= w->period;
            }
            ((s16 *)lbl_803DDAF0)[off + 1] += framesThisStep >> 1;
            while (((s16 *)lbl_803DDAF0)[off + 1] >= w->period) {
                ((s16 *)lbl_803DDAF0)[off + 1] -= w->period;
            }
            off += 2;
        }
    }
    lbl_803DDAF8 = 1;
}
extern void *mapBlockFn_800606ec(void *block, int idx);
extern int mapBlockFn_80060678(void *entry);
extern void *fn_800606DC(void *block, int idx);
extern void fn_800605F0(void *cell, void *out);
extern void fn_8006058C(void *cell, void *in);
void groundanimator_free(int *obj, int flag) {
    GroundAnimatorState *w;
    int *r21;
    void *block;
    void *entry;
    void *vtx;
    int blkIdx;
    int mid;
    int inner;
    int off;
    int midoff;
    int innoff;
    int *cell;
    f32 local[2];
    w = (GroundAnimatorState *)obj[46];
    r21 = (int *)obj[19];
    if (flag == 0) {
        block = mapGetBlock(objPosToMapBlockIdx((double)((GameObject *)obj)->anim.localPosX,
                                                (double)((GameObject *)obj)->anim.localPosY,
                                                (double)((GameObject *)obj)->anim.localPosZ));
        if (block != NULL) {
            off = 0;
            for (blkIdx = 0; blkIdx < *(u16 *)((char *)block + 0x9a); blkIdx++) {
                entry = mapBlockFn_800606ec(block, blkIdx);
                if (*(u8 *)((char *)r21 + 0x25) == mapBlockFn_80060678(entry)) {
                    midoff = off;
                    for (mid = *(u16 *)entry; mid < *(u16 *)((char *)block + 0x14); mid++) {
                        vtx = fn_800606DC(block, mid);
                        innoff = midoff;
                        for (inner = 0; inner < 3; inner++) {
                            cell = (int *)((char *)*(int *)((char *)block + 0x58) +
                                           *(u16 *)vtx * 6);
                            fn_800605F0(cell, local);
                            if (w->heightBuf != 0) {
                                local[1] = (f32)*(s16 *)((char *)w->heightBuf + innoff);
                                fn_8006058C(cell, local);
                            }
                            innoff += 2;
                            midoff += 2;
                            off += 2;
                            vtx = (char *)vtx + 2;
                        }
                    }
                }
            }
        }
    }
    if (w->falloffBuf != 0) {
        mm_free((void *)w->falloffBuf);
    }
    ObjGroup_RemoveObject(obj, 0x31);
}
extern f32 lbl_803E3FA8;
extern f32 lbl_803E3FAC;
extern f32 lbl_803E3FB0;
extern f32 lbl_803E3FB4;
extern f32 lbl_803E3FBC;
extern f32 timeDelta;
extern void fn_801A80F0(int *e, int arg);
f32 groundanimator_setScale(int *obj, int *target) {
    GroundAnimatorState *g;
    int *r31;
    f32 dy;
    f32 dx;
    f32 dz;
    f32 r;
    g = (GroundAnimatorState *)obj[46];
    r31 = (int *)obj[19];
    dy = *(f32 *)((char *)target + 0x10) - ((GameObject *)obj)->anim.localPosY;
    if (dy < lbl_803E3FA8 || dy > lbl_803E3FAC) {
        return lbl_803E3FB0;
    }
    dx = *(f32 *)((char *)target + 0xc) - ((GameObject *)obj)->anim.localPosX;
    dz = *(f32 *)((char *)target + 0x14) - ((GameObject *)obj)->anim.localPosZ;
    r = lbl_803E3FB4 + g->radius;
    if (dx * dx + dz * dz > r * r) {
        return lbl_803E3FB8;
    }
    if (g->sinkDepth >= lbl_803E3F98 * (f32)(u32)*(u8 *)((char *)r31 + 0x20)) {
        if (g->linkedObj != 0) {
            int *e = (int *)g->linkedObj;
            g->sinkDepth = lbl_803E3F98 * (f32)(u32)*(u8 *)((char *)r31 + 0x20);
            if (*(s16 *)((char *)e + 0x46) == 0x519) {
                fn_801A80F0(e, 0);
            } else {
                (*(code *)(*(int *)(*(int *)((char *)e + 0x68)) + 0x24))(e, 0);
            }
        }
    }
    g->sinkDepth = lbl_803E3FBC * timeDelta + g->sinkDepth;
    g->flags = g->flags | 4;
    return g->radius *
           (g->sinkDepth / (lbl_803E3F98 * (f32)(u32)*(u8 *)((char *)r31 + 0x20)));
}
extern float fastFloorf(float x);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E3FC0;
void fn_801932C8(int *obj, GroundAnimatorState *p2, int *p3) {
    void *block;
    void *entry;
    void *vtx;
    int blkIdx;
    int mid;
    int inner;
    int foff;
    int ix;
    int iz;
    f32 fracX;
    f32 fracZ;
    f32 radsq;
    f32 clampMax;
    f32 vpos[3];
    block = mapGetBlock(objPosToMapBlockIdx((double)((GameObject *)obj)->anim.localPosX,
                                            (double)((GameObject *)obj)->anim.localPosY,
                                            (double)((GameObject *)obj)->anim.localPosZ));
    if (block == NULL) {
        return;
    }
    if ((*(u16 *)((char *)block + 4) & 8) == 0) {
        return;
    }
    ix = (int)fastFloorf((((GameObject *)obj)->anim.localPosX - playerMapOffsetX) / lbl_803E3FC0);
    iz = (int)fastFloorf((((GameObject *)obj)->anim.localPosZ - playerMapOffsetZ) / lbl_803E3FC0);
    fracX = ((GameObject *)obj)->anim.localPosX - (lbl_803E3FC0 * (f32)ix + playerMapOffsetX);
    fracZ = ((GameObject *)obj)->anim.localPosZ - (lbl_803E3FC0 * (f32)iz + playerMapOffsetZ);
    p2->entryCount = 0;
    radsq = p2->radius * p2->radius;
    foff = 0;
    for (blkIdx = 0; blkIdx < *(u16 *)((char *)block + 0x9a); blkIdx++) {
        entry = mapBlockFn_800606ec(block, blkIdx);
        if (*(u8 *)((char *)p3 + 0x25) == mapBlockFn_80060678(entry)) {
            mid = *(u16 *)entry;
            clampMax = lbl_803E3FC4;
            for (; mid < *(u16 *)((char *)block + 0x14); mid++) {
                vtx = fn_800606DC(block, mid);
                for (inner = 0; inner < 3; inner++) {
                    void *cell = (char *)*(int *)((char *)block + 0x58) + *(u16 *)vtx * 6;
                    f32 dx;
                    f32 dz;
                    f32 d;
                    fn_800605F0(cell, vpos);
                    dx = vpos[0] - fracX;
                    dz = vpos[2] - fracZ;
                    d = (dx * dx + dz * dz) / radsq;
                    if (d > clampMax) {
                        d = clampMax;
                    }
                    d = d * d;
                    ((f32 *)p2->falloffBuf)[foff] = clampMax - d;
                    *(s16 *)((char *)p2->heightBuf + foff * 2) = (int)vpos[1];
                    foff++;
                    vtx = (char *)vtx + 2;
                }
            }
            p2->blockEntries[(p2->entryCount)++] = (s16)blkIdx;
        }
    }
}
extern int *Obj_GetPlayerObject(void);
extern int fn_80060688(void *block, int v);
extern void fn_801A80C4(void *o, f32 x, f32 y, f32 z);
extern void Sfx_PlayFromObject(int *obj, int id);
extern void *getTrickyObject(void);
extern void objRenderFn_80041018(int *obj);
extern void DCStoreRangeNoSync(void *addr, int len);
extern void *mmAlloc(int size, int align, int tag);
extern u16 lbl_803DBDF0[];
void groundanimator_update(int *obj) {
    GroundAnimatorState *g;
    int *r20;
    s8 bi;
    void *block;
    void *near;
    void *entry;
    void *vtx;
    int blkIdx;
    int mid;
    int inner;
    int foff;
    int hoff;
    int oldbit;
    int allow;
    void *tricky;
    f32 nd;
    f32 vbuf[2];
    Obj_GetPlayerObject();
    g = (GroundAnimatorState *)obj[46];
    r20 = (int *)obj[19];
    if (*(u8 *)((char *)r20 + 0x25) == 0) {
        return;
    }
    bi = objPosToMapBlockIdx((double)((GameObject *)obj)->anim.localPosX,
                             (double)((GameObject *)obj)->anim.localPosY,
                             (double)((GameObject *)obj)->anim.localPosZ);
    oldbit = g->flags & 1;
    if (bi > -1) {
        g->flags = g->flags | 1;
    } else {
        g->flags = g->flags & ~1;
    }
    if ((g->flags & 1) != oldbit) {
        g->dirtyFrames = 2;
    }
    if ((g->flags & 1) == 0) {
        return;
    }
    if ((g->flags & 1) != 0 && *(void **)&g->falloffBuf == NULL) {
        int p;
        block = mapGetBlock(bi);
        g->vertCount = (s16)(fn_80060688(block, *(u8 *)((char *)r20 + 0x25)) * 3);
        if (g->vertCount > 0) {
            p = (int)mmAlloc(g->vertCount * 6, 5, 0);
            g->falloffBuf = p;
            g->heightBuf = p + g->vertCount * 4;
            fn_801932C8(obj, g, r20);
        }
    }
    if (g->vertCount == 0) {
        return;
    }
    if (*(u8 *)((char *)r20 + 0x22) == 0) {
        if (*(void **)&g->linkedObj == NULL) {
            nd = lbl_803E3F98;
            g->linkedObj = (int)ObjGroup_FindNearestObject(4, obj, &nd);
            near = (void *)g->linkedObj;
            if (g->linkedObj != 0) {
                if (*(s16 *)((char *)near + 0x46) == 0x519) {
                    if ((g->flags & 2) == 0) {
                        fn_801A80F0(near, 1);
                    }
                    fn_801A80C4(near, ((GameObject *)obj)->anim.localPosX,
                                ((GameObject *)obj)->anim.localPosY - g->yOffset,
                                ((GameObject *)obj)->anim.localPosZ);
                } else {
                    if ((g->flags & 2) == 0) {
                        (*(code *)(*(int *)(*(int *)((char *)near + 0x68)) + 0x24))(near, 1);
                    }
                    (*(code *)(*(int *)(*(int *)((char *)near + 0x68)) + 0x38))(
                        near, ((GameObject *)obj)->anim.localPosX,
                        ((GameObject *)obj)->anim.localPosY - g->yOffset,
                        ((GameObject *)obj)->anim.localPosZ);
                }
            }
        } else if ((*(u16 *)((char *)g->linkedObj + 0xb0) & 0x40) != 0) {
            g->linkedObj = 0;
        }
    }
    block = mapGetBlock(bi);
    if (block == NULL) {
        return;
    }
    if ((*(u16 *)((char *)block + 4) & 8) == 0) {
        return;
    }
    if (g->sinkDepth > lbl_803E3FB0) {
        if ((g->flags & 4) != 0) {
            g->flags = g->flags & ~4;
        } else if (g->sinkDepth <
                   lbl_803E3F98 * (f32)(u32)*(u8 *)((char *)r20 + 0x20)) {
            g->sinkDepth = g->sinkDepth - timeDelta;
            if (g->sinkDepth < lbl_803E3FB0) {
                g->sinkDepth = lbl_803E3FB0;
            }
        }
        if (g->sinkDepth != g->lastDepth) {
            g->dirtyFrames = 2;
            g->lastDepth = g->sinkDepth;
        }
        if (g->dirtyFrames != 0) {
            f32 lim = lbl_803E3F98 * (f32)(u32)*(u8 *)((char *)r20 + 0x20);
            g->dirtyFrames = g->dirtyFrames - 1;
            if (g->lastDepth > lim) {
                g->lastDepth = lim;
                g->sinkDepth = lim;
                if (g->linkedObj != 0 && *(int *)((char *)g->linkedObj + 0xb8) != 0) {
                    if (*(s16 *)((char *)g->linkedObj + 0x46) == 0x519) {
                        fn_801A80F0((void *)g->linkedObj, 0);
                    } else {
                        (*(code *)(*(int *)(*(int *)((char *)g->linkedObj + 0x68)) + 0x24))((void *)g->linkedObj, 0);
                    }
                }
                GameBit_Set(*(s16 *)((char *)r20 + 0x18), 1);
                g->flags = g->flags | 2;
                Sfx_PlayFromObject(obj, lbl_803DBDF0[*(u8 *)((char *)r20 + 0x21)]);
            }
            foff = 0;
            hoff = 0;
            for (blkIdx = 0; blkIdx < g->entryCount; blkIdx++) {
                entry = mapBlockFn_800606ec(block, g->blockEntries[blkIdx]);
                for (mid = *(u16 *)entry; mid < *(u16 *)((char *)entry + 0x14); mid++) {
                    vtx = fn_800606DC(block, mid);
                    for (inner = 0; inner < 3; inner++) {
                        if (*(f32 *)((char *)g->falloffBuf + foff) > lbl_803E3FB0) {
                            void *cell = (char *)*(int *)((char *)block + 0x58) + *(u16 *)vtx * 6;
                            f32 fv = (f32)*(s16 *)((char *)g->heightBuf + hoff);
                            fn_800605F0(cell, &vbuf[1]);
                            vbuf[0] = fv - (g->lastDepth / lbl_803E3F98) *
                                               *(f32 *)((char *)g->falloffBuf + foff);
                            fn_8006058C(cell, &vbuf[1]);
                        }
                        foff += 4;
                        hoff += 2;
                        vtx = (char *)vtx + 2;
                    }
                }
            }
            DCStoreRangeNoSync((void *)*(int *)((char *)block + 0x58),
                               *(u16 *)((char *)block + 0x90) * 6);
        }
    }
    if (*(s16 *)((char *)r20 + 0x1a) == -1) {
        allow = 1;
    } else {
        allow = GameBit_Get(*(s16 *)((char *)r20 + 0x1a)) != 0;
    }
    if ((g->flags & 2) == 0 && allow != 0) {
        tricky = getTrickyObject();
        if (tricky != NULL && GameBit_Get(0x4e4) != 0) {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x10;
        } else {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x10;
        }
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x8;
        if (tricky != NULL && (*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) != 0) {
            (*(code *)(*(int *)(*(int *)((char *)tricky + 0x68)) + 0x28))(tricky, obj, 1, 1);
        }
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x8;
    }
    objRenderFn_80041018(obj);
}
extern f32 lbl_803E3F7C;
extern f32 lbl_803E3F80;
extern f32 lbl_803E3F84;
void alphaanimator_update(int *obj) {
    int *d;
    AlphaAnimatorState *s;
    int mode;
    void *block;
    f32 sp;
    d = (int *)obj[19];
    s = (AlphaAnimatorState *)obj[46];
    mode = *(u8 *)((char *)d + 0x20) & 3;
    block = mapGetBlock(objPosToMapBlockIdx((double)((GameObject *)obj)->anim.localPosX,
                                            (double)((GameObject *)obj)->anim.localPosY,
                                            (double)((GameObject *)obj)->anim.localPosZ));
    if (block == NULL) {
        s->doneCount = 0;
        return;
    }
    if ((*(u16 *)((char *)block + 4) & 8) == 0) {
        return;
    }
    if (s->vertCount == 0) {
        s->active = *(u8 *)((char *)d + 0x1e);
        if (s->vertCount == 0) {
            s->active = 0;
        }
        if ((s8)s->active == 0) {
            return;
        }
        s->fadeA = lbl_803E3F7C;
        s->fadeB = lbl_803E3F7C;
        s->fadeMax = (f32)(u32)*(u16 *)((char *)d + 0x22);
        if (*(s16 *)((char *)d + 0x18) == -1) {
            s->gateVal = 1;
        } else {
            s->gateVal = (s8)GameBit_Get(*(s16 *)((char *)d + 0x18));
        }
        s->alphaLevel = *(u8 *)((char *)d + 0x1c);
        if (*(s16 *)((char *)d + 0x1a) != -1 && GameBit_Get(*(s16 *)((char *)d + 0x1a)) != 0) {
            s->alphaLevel = *(u8 *)((char *)d + 0x1d);
            s->fadeA = lbl_803E3F78 + s->fadeMax;
            s->gateVal = 1;
        }
        if (mode == 3) {
            *(int *)&s->buf = (int)mmAlloc(s->vertCount << 2, 5, 0);
        }
        *(u16 *)((char *)block + 4) = *(u16 *)((char *)block + 4) ^ 1;
        *(u16 *)((char *)block + 4) = *(u16 *)((char *)block + 4) ^ 1;
    }
    if ((s8)s->active == 0) {
        return;
    }
    if (mode == 2) {
        s->gateVal = (s8)GameBit_Get(*(s16 *)((char *)d + 0x18));
        if ((s8)s->doneCount > 2 &&
            (s8)s->gateVal != (s8)s->prevGate) {
            if ((*(u8 *)((char *)d + 0x20) >> 2) != 0) {
                Sfx_PlayFromObject(obj, *(u16 *)((char *)d + 0x24));
            }
            s->doneCount = 0;
            s->prevGate = s->gateVal;
        }
        if ((s8)s->doneCount > 2) {
            return;
        }
    } else {
        if ((s8)s->doneCount > 2) {
            return;
        }
        if ((s8)s->gateVal == 0) {
            s->gateVal = (s8)GameBit_Get(*(s16 *)((char *)d + 0x18));
            if ((s8)s->gateVal == 0) {
                return;
            }
            if ((*(u8 *)((char *)d + 0x20) >> 2) != 0) {
                Sfx_PlayFromObject(obj, *(u16 *)((char *)d + 0x24));
            }
        }
    }
    if (mode == 0) {
        if (*(u8 *)((char *)d + 0x1c) > *(u8 *)((char *)d + 0x1d)) {
            s->alphaLevel =
                (s16)(s->alphaLevel - (s8)*(u8 *)((char *)d + 0x1f) * framesThisStep);
            if (s->alphaLevel <= *(u8 *)((char *)d + 0x1d)) {
                s->alphaLevel = *(u8 *)((char *)d + 0x1d);
                if (*(s16 *)((char *)d + 0x1a) != -1) {
                    GameBit_Set(*(s16 *)((char *)d + 0x1a), 1);
                }
                s->doneCount = s->doneCount + 1;
            }
        } else {
            s->alphaLevel =
                (s16)(s->alphaLevel + (s8)*(u8 *)((char *)d + 0x1f) * framesThisStep);
            if (s->alphaLevel >= *(u8 *)((char *)d + 0x1d)) {
                s->alphaLevel = *(u8 *)((char *)d + 0x1d);
                if (*(s16 *)((char *)d + 0x1a) != -1) {
                    GameBit_Set(*(s16 *)((char *)d + 0x1a), 1);
                }
                s->doneCount = s->doneCount + 1;
            }
        }
    } else if (mode == 1) {
        if (*(u8 *)((char *)d + 0x1c) > *(u8 *)((char *)d + 0x1d)) {
            s->alphaLevel =
                (s16)(s->alphaLevel - (s8)*(u8 *)((char *)d + 0x1f) * framesThisStep);
            if (s->alphaLevel < *(u8 *)((char *)d + 0x1d)) {
                s->alphaLevel =
                    (s16)(*(u8 *)((char *)d + 0x1c) -
                          (*(u8 *)((char *)d + 0x1d) - s->alphaLevel));
            }
        } else {
            s->alphaLevel =
                (s16)(s->alphaLevel + (s8)*(u8 *)((char *)d + 0x1f) * framesThisStep);
            if (s->alphaLevel > *(u8 *)((char *)d + 0x1c)) {
                s->alphaLevel =
                    (s16)(*(u8 *)((char *)d + 0x1d) +
                          (s->alphaLevel - *(u8 *)((char *)d + 0x1d)));
            }
        }
    } else if (mode == 2) {
        if ((s8)s->gateVal != 0) {
            if (*(u8 *)((char *)d + 0x1c) > *(u8 *)((char *)d + 0x1d)) {
                s->alphaLevel =
                    (s16)(s->alphaLevel - (s8)*(u8 *)((char *)d + 0x1f) * framesThisStep);
                if (s->alphaLevel > *(u8 *)((char *)d + 0x1d)) {
                    return;
                }
            } else {
                s->alphaLevel =
                    (s16)(s->alphaLevel + (s8)*(u8 *)((char *)d + 0x1f) * framesThisStep);
                if (s->alphaLevel < *(u8 *)((char *)d + 0x1d)) {
                    return;
                }
            }
            s->alphaLevel = *(u8 *)((char *)d + 0x1d);
            if (*(s16 *)((char *)d + 0x1a) != -1) {
                GameBit_Set(*(s16 *)((char *)d + 0x1a), 1);
            }
            s->doneCount = s->doneCount + 1;
        } else {
            if (*(u8 *)((char *)d + 0x1c) > *(u8 *)((char *)d + 0x1d)) {
                s->alphaLevel =
                    (s16)(s->alphaLevel + (s8)*(u8 *)((char *)d + 0x1f) * framesThisStep);
                if (s->alphaLevel < *(u8 *)((char *)d + 0x1c)) {
                    return;
                }
            } else {
                s->alphaLevel =
                    (s16)(s->alphaLevel - (s8)*(u8 *)((char *)d + 0x1f) * framesThisStep);
                if (s->alphaLevel > *(u8 *)((char *)d + 0x1c)) {
                    return;
                }
            }
            s->alphaLevel = *(u8 *)((char *)d + 0x1c);
            if (*(s16 *)((char *)d + 0x1a) != -1) {
                GameBit_Set(*(s16 *)((char *)d + 0x1a), 0);
            }
            s->doneCount = s->doneCount + 1;
        }
    } else {
        sp = (f32)(s8)*(u8 *)((char *)d + 0x1f);
        if ((s8)*(u8 *)((char *)d + 0x1f) < 0) {
            sp = (f32)(-(s8)*(u8 *)((char *)d + 0x1f));
        }
        s->fadeA =
            sp / lbl_803E3F80 * timeDelta + s->fadeA;
        if (s->fadeA > s->fadeMax) {
            s->fadeA = s->fadeMax;
            GameBit_Set(*(s16 *)((char *)d + 0x1a), 1);
            s->doneCount = s->doneCount + 1;
        }
        s->fadeB = s->fadeA - lbl_803E3F84;
    }
}

extern f32 lbl_803E3F40;
extern f32 lbl_803E3F44;
extern f32 lbl_803E3F48;
extern f32 lbl_803E3F4C;
extern f32 lbl_803E3F50;
extern f32 lbl_803E3F54;
extern f32 lbl_803E3F58;
extern f32 lbl_803E3F5C;
extern f32 lbl_803E3F60;
extern f32 lbl_803E3F64;
extern f32 mathSinf(f32);

void fn_801923F8(int *cfgArg)
{
    int i;
    int j;
    int x;
    int stepX;
    int y;
    int stepY;
    int flat;
    int fi;
    int bi;
    int hi;
    f32 c48;
    f32 c4C;
    f32 z;
    WaveAnimatorState *cfg = (WaveAnimatorState *)cfgArg;

    lbl_803DDAF4 = mmAlloc(4 * cfg->period * cfg->period, 0xFFFFFF, 0);
    lbl_803DDAEC = mmAlloc(3 * cfg->period * cfg->period, 0xFFFFFF, 0);

    x = cfg->originX;
    stepX = (s32)((lbl_803E3F40 * (f32)cfg->spanX) / (f32)cfg->period);
    y = cfg->originY;
    stepY = (s32)((lbl_803E3F40 * (f32)cfg->spanY) / (f32)cfg->period);

    z = lbl_803E3F44;
    cfg->maxHeight = z;
    cfg->minHeight = z;

    flat = 0;
    c48 = lbl_803E3F48;
    c4C = lbl_803E3F4C;
    for (i = 0; i < cfg->period; i++) {
        f32 xv = c48 * (f32)x;
        for (j = 0; j < cfg->period; j++) {
            f32 s1 = mathSinf((c48 * (f32)y) / c4C);
            f32 a = cfg->ampY * s1;
            f32 s2 = mathSinf(xv / c4C);
            ((f32 *)lbl_803DDAF4)[flat] = cfg->ampX * s2 + a;
            if (((f32 *)lbl_803DDAF4)[flat] < cfg->minHeight) {
                cfg->minHeight = ((f32 *)lbl_803DDAF4)[flat];
            }
            if (((f32 *)lbl_803DDAF4)[flat] > cfg->maxHeight) {
                cfg->maxHeight = ((f32 *)lbl_803DDAF4)[flat];
            }
            y += stepY;
            flat++;
        }
        x += stepX;
    }

    {
        f32 negMin = -cfg->minHeight;
        f32 zero2;
        fi = 0;
        bi = 0;
        zero2 = lbl_803E3F44;
        for (i = 0; i < cfg->period; i++) {
            for (j = 0; j < cfg->period; j++) {
                f32 v = ((f32 *)lbl_803DDAF4)[fi];
                if (v < zero2) {
                    f32 t = (v - cfg->minHeight) / negMin;
                    ((s8 *)lbl_803DDAEC)[bi] = (s32)(lbl_803E3F54 * t + lbl_803E3F50);
                    ((s8 *)lbl_803DDAEC)[bi + 1] = (s32)(lbl_803E3F5C * t + lbl_803E3F58);
                    ((s8 *)lbl_803DDAEC)[bi + 2] = (s32)(lbl_803E3F64 * t + lbl_803E3F60);
                } else {
                    ((s8 *)lbl_803DDAEC)[bi] = 255;
                    ((s8 *)lbl_803DDAEC)[bi + 1] = 255;
                    ((s8 *)lbl_803DDAEC)[bi + 2] = 255;
                }
                fi++;
                bi += 3;
            }
        }
    }

    lbl_803DDAF0 = mmAlloc(4 * cfg->gridN * cfg->gridN, 0xFFFFFF, 0);
    hi = 0;
    for (i = 0; i < cfg->gridN; i++) {
        for (j = 0; j < cfg->gridN; j++) {
            ((s16 *)lbl_803DDAF0)[hi] = (s16)(i * 10);
            ((s16 *)lbl_803DDAF0)[hi + 1] = (s16)(j * 10);
            hi += 2;
        }
    }
}

extern char *fn_8006070C(void *block, int idx);
extern u8 *Shader_getLayer(char *s, int layer);

void hitAnimatorFn_80193dbc(void *block, HitAnimatorObject *obj, HitAnimatorState *vstate, HitAnimatorPlacement *desc)
{
    int i;
    char *m;

    if ((desc->flags & 0x10) == 0) {
        for (i = 0; i < *(u16 *)((char *)block + 0x9a); i++) {
            m = (char *)mapBlockFn_800606ec(block, i);
            if (desc->blockEffectId == mapBlockFn_80060678(m)) {
                if (vstate->activeBit != 0) {
                    *(int *)(m + 0x10) &= ~2;
                    if ((desc->flags & 0x2) != 0) {
                        *(int *)(m + 0x10) &= ~1;
                    }
                } else {
                    *(int *)(m + 0x10) |= 2;
                    if ((desc->flags & 0x2) != 0) {
                        *(int *)(m + 0x10) |= 1;
                    }
                }
            }
        }
    }
    if ((desc->flags & 0x2) != 0) {
        for (i = 0; i < *((u8 *)block + 0xa2); i++) {
            char *s = fn_8006070C(block, i);
            u8 *layer = Shader_getLayer(s, 0);
            if (desc->blockEffectId == layer[5]) {
                if (vstate->activeBit != 0) {
                    *(int *)(s + 0x3c) &= ~2;
                } else {
                    *(int *)(s + 0x3c) |= 2;
                }
            }
        }
    }
}
