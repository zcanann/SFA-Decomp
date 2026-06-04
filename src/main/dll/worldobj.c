#include "ghidra_import.h"
#include "main/dll/worldobj.h"

#define SFXwp_gcfir1_c 331
#define SFXwp_hitpos_6 332
#define SFXwp_mpwru1 333

extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern double FUN_80017708();
extern double FUN_80017714();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a90();
extern undefined4 FUN_80017ac8();
extern int FUN_80017af8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjGroup_FindNearestObject();
extern int ObjTrigger_IsSet();
extern int FUN_80039520();
extern undefined4 FUN_8003a1c4();
extern undefined4 fn_8003A328();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 objAudioFn_8006ef38();
extern undefined4 FUN_8014ccac();
extern int FUN_80163ac8();
extern undefined4 FUN_80163b8c();
extern undefined8 FUN_80286834();
extern undefined4 FUN_80286880();
extern int FUN_80294c54();
extern uint countLeadingZeros();

extern undefined4 DAT_803274f4;
extern int DAT_8032750c;
extern uint DAT_8032751c;
extern undefined4 DAT_803dcc10;
extern undefined4 DAT_803dcc14;
extern undefined4 DAT_803dcc18;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e5eb8;
extern f32 lbl_803DC074;
extern f32 lbl_803E5E98;
extern f32 lbl_803E5EA4;
extern f32 lbl_803E5EA8;
extern f32 lbl_803E5EAC;
extern f32 lbl_803E5EB0;
extern f32 lbl_803E5EC0;
extern f32 lbl_803E5EC4;
extern f32 lbl_803E5EC8;
extern f32 lbl_803E5ECC;
extern f32 lbl_803E5ED0;

/*
 * --INFO--
 *
 * Function: FUN_801ce078
 * EN v1.0 Address: 0x801CE078
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CE1A0
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ce078(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801ce07c
 * EN v1.0 Address: 0x801CE07C
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x801CE22C
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801ce07c(int param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  
  uVar1 = GameBit_Get(10);
  if (uVar1 != 0) {
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
  }
  iVar2 = FUN_80039520(param_1,0);
  FUN_80039520(param_1,1);
  *(short *)(iVar2 + 10) = *(short *)(iVar2 + 10) + (short)(int)(lbl_803E5E98 * lbl_803DC074);
  if (0x4e80 < *(short *)(iVar2 + 10)) {
    *(short *)(iVar2 + 10) = *(short *)(iVar2 + 10) + -0x4e80;
  }
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x70) & ~0x40;
  *(undefined *)(param_3 + 0x56) = 0;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce144
 * EN v1.0 Address: 0x801CE144
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801CE304
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ce144(int param_1)
{
  (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),0x1f,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce188
 * EN v1.0 Address: 0x801CE188
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x801CE344
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ce188(uint param_1)
{
  uint uVar1;
  
  uVar1 = GameBit_Get(10);
  if (uVar1 == 0) {
    FUN_800068d0(param_1,0x372);
    FUN_800068d0(param_1,0x373);
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    ObjHits_EnableObject(param_1);
  }
  else {
    *(undefined2 *)(param_1 + 6) = 0x4000;
    *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
    FUN_800068cc();
    FUN_800068cc();
    ObjHits_DisableObject(param_1);
    GameBit_Set(0x398,1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce238
 * EN v1.0 Address: 0x801CE238
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x801CE424
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_801ce238(int param_1)
{
  return *(int *)(param_1 + 0xb8) + 0xc;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce244
 * EN v1.0 Address: 0x801CE244
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x801CE430
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801ce244(short *param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  if ((*(byte *)(iVar1 + 0x43c) & 0x20) == 0) {
    FUN_8000680c((int)param_1,0x7f);
    *(float *)(iVar1 + 0x54) = lbl_803E5EA4;
    *(byte *)(iVar1 + 0x43c) = *(byte *)(iVar1 + 0x43c) & 0xef;
    *(byte *)(iVar1 + 0x43c) = *(byte *)(iVar1 + 0x43c) | 0x20;
  }
  if ((*(byte *)(iVar1 + 0x43c) & 4) != 0) {
    *(float *)(iVar1 + 0x18) = lbl_803E5EA4;
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & ~0x8;
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & ~0x40;
    FUN_801ce340(param_1,iVar1,1);
  }
  objAudioFn_8006ef38((double)lbl_803E5EA8,(double)lbl_803E5EA8,param_1,iVar1 + 0x440,8,iVar1 + 0x45c,
               iVar1 + 0x16c);
  if (*(char *)(param_3 + 0x8b) != '\0') {
    param_1[0x58] = param_1[0x58] & 0xfbff;
    *(uint *)(*(int *)(param_1 + 0x32) + 0x30) = *(uint *)(*(int *)(param_1 + 0x32) + 0x30) | 4;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce340
 * EN v1.0 Address: 0x801CE340
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x801CE548
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ce340(short *param_1,int param_2,int param_3)
{
  if (((param_3 == 0) || (*(int *)(param_2 + 0x28) == 0)) ||
     (lbl_803E5EAC <= *(float *)(param_2 + 0x18))) {
    *(undefined *)(param_2 + 0x40c) = 0;
  }
  else {
    *(undefined *)(param_2 + 0x40c) = 1;
    *(undefined4 *)(param_2 + 0x410) = *(undefined4 *)(*(int *)(param_2 + 0x28) + 0xc);
    *(undefined4 *)(param_2 + 0x414) = *(undefined4 *)(*(int *)(param_2 + 0x28) + 0x10);
    *(undefined4 *)(param_2 + 0x418) = *(undefined4 *)(*(int *)(param_2 + 0x28) + 0x14);
  }
  if (((&DAT_803274f4)[*(byte *)(param_2 + 0x408)] & 2) == 0) {
    fn_8003A328((double)lbl_803E5EA4,param_1,(char *)(param_2 + 0x40c));
    FUN_8003b280((int)param_1,param_2 + 0x40c);
  }
  else {
    FUN_8003a1c4((int)param_1,param_2 + 0x40c);
    FUN_8003b1a4((int)param_1,param_2 + 0x40c);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce424
 * EN v1.0 Address: 0x801CE424
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x801CE62C
 * EN v1.1 Size: 580b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801ce424(uint param_1,int param_2)
{
  byte bVar1;
  float fVar2;
  uint uVar3;
  char cVar4;
  undefined auStack_38 [4];
  undefined auStack_34 [12];
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  cVar4 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_38);
  if (*(char *)(param_2 + 0x45b) == '\0') {
    uVar3 = 0;
  }
  else {
    uVar3 = countLeadingZeros((int)*(char *)(param_2 + 0x453));
    uVar3 = uVar3 >> 5;
  }
  if (*(byte *)(param_2 + 0x408) < 0x14) {
    if (cVar4 == '\0') {
      return 0;
    }
    if (lbl_803E5EA4 < *(float *)(param_2 + 0x54)) {
      return 0xffffffff;
    }
    *(byte *)(param_2 + 0x409) = *(byte *)(param_2 + 0x408);
    *(undefined *)(param_2 + 0x408) = 0x14;
  }
  bVar1 = *(byte *)(param_2 + 0x408);
  if (bVar1 == 0x15) {
    if (uVar3 != 0) {
      FUN_80006824(param_1,SFXwp_hitpos_6);
    }
    *(float *)(param_2 + 4) = *(float *)(param_2 + 4) - lbl_803DC074;
    if ((cVar4 == '\0') && (*(float *)(param_2 + 4) <= lbl_803E5EA4)) {
      *(undefined *)(param_2 + 0x408) = 0x16;
    }
    fVar2 = *(float *)(param_2 + 0x1c) - lbl_803DC074;
    *(float *)(param_2 + 0x1c) = fVar2;
    if (fVar2 <= lbl_803E5EA4) {
      if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
        local_28 = *(undefined4 *)(param_2 + 0xc);
        local_24 = *(undefined4 *)(param_2 + 0x10);
        local_20 = *(undefined4 *)(param_2 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7f0,auStack_34,0x200001,0xffffffff,0);
      }
      *(float *)(param_2 + 0x1c) = lbl_803E5EB0;
    }
  }
  else if (bVar1 < 0x15) {
    if (0x13 < bVar1) {
      if (uVar3 != 0) {
        FUN_80006824(param_1,SFXwp_gcfir1_c);
      }
      if ((*(byte *)(param_2 + 0x43c) & 2) != 0) {
        *(undefined *)(param_2 + 0x408) = 0x15;
        uVar3 = randomGetRange(0,300);
        *(float *)(param_2 + 4) =
             (f32)(s32)(uVar3);
      }
    }
  }
  else if (bVar1 < 0x17) {
    if (uVar3 != 0) {
      FUN_80006824(param_1,SFXwp_mpwru1);
    }
    if ((*(byte *)(param_2 + 0x43c) & 2) != 0) {
      *(undefined *)(param_2 + 0x408) = *(undefined *)(param_2 + 0x409);
    }
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce638
 * EN v1.0 Address: 0x801CE638
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CE870
 * EN v1.1 Size: 1880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ce638(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: nw_mammoth_getExtraSize
 * EN v1.0 Address: 0x801CEFB4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int nw_mammoth_getExtraSize(void)
{
  return 0x48c;
}

#pragma scheduling off
#pragma peephole off
void fn_801CEE0C(int p1, int p2)
{
  extern int fn_801CE078(int);
  extern int ObjTrigger_IsSetById(int, int);
  extern int gameBitDecrement(int);
  extern int *gObjectTriggerInterface;
  extern int lbl_803DBF70;
  extern int lbl_803DBF74;
  extern int lbl_803DBF78;
  extern int lbl_803DBF7C;

  if (fn_801CE078(p1) != 0) return;

  switch (*(u8 *)(p2 + 0x408)) {
    case 0:
      *(int *)(p2 + 0x48) = (int)&lbl_803DBF70;
      if (GameBit_Get(211) != 0) {
        *(u8 *)(p2 + 0x408) = 1;
      }
      break;
    case 1:
      *(int *)(p2 + 0x48) = (int)&lbl_803DBF74;
      {
        int v = GameBit_Get(1400);
        if (v == 1) {
          *(u8 *)(p2 + 0x408) = 2;
        } else if (v > 1) {
          *(u8 *)(p2 + 0x408) = 3;
        } else if (v == 0) {
          if (ObjTrigger_IsSetById(p1, 1398) != 0) {
            GameBit_Set(1400, 1);
            gameBitDecrement(1398);
            (**(void (**)(int, int, int))((char *)(*gObjectTriggerInterface) + 0x48))(2, p1, -1);
            *(u8 *)(p2 + 0x43c) = (u8)(*(u8 *)(p2 + 0x43c) | 0x10);
            *(u8 *)(p2 + 0x408) = 2;
          }
        } else {
          *(u8 *)(p2 + 0x408) = 3;
        }
      }
      break;
    case 2:
      *(int *)(p2 + 0x48) = (int)&lbl_803DBF78;
      if (ObjTrigger_IsSetById(p1, 1398) != 0) {
        GameBit_Set(1400, 2);
        gameBitDecrement(1398);
        (**(void (**)(int, int, int))((char *)(*gObjectTriggerInterface) + 0x48))(4, p1, -1);
        *(u8 *)(p2 + 0x408) = 3;
        *(u8 *)(p2 + 0x43c) = (u8)(*(u8 *)(p2 + 0x43c) | 0x10);
      }
      break;
    case 3:
      *(int *)(p2 + 0x48) = (int)&lbl_803DBF7C;
      break;
  }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_801CED2C(int p1, int p2)
{
  extern int ObjTrigger_IsSetById(int, int);
  extern int lbl_803DBFB4;
  extern int lbl_803DBFB8;
  extern int lbl_803DBFBC;

  switch (*(u8 *)(p2 + 0x408)) {
    case 4:
      *(int *)(p2 + 0x48) = (int)&lbl_803DBFB4;
      if (ObjTrigger_IsSetById(p1, 418) != 0) {
        *(u8 *)(p2 + 0x43c) = (u8)(*(u8 *)(p2 + 0x43c) | 0x10);
        GameBit_Set(413, 1);
        GameBit_Set(419, 1);
        GameBit_Set(3813, 1);
        GameBit_Set(3814, 1);
        *(u8 *)(p2 + 0x408) = 5;
      }
      break;
    case 5:
      *(int *)(p2 + 0x48) = (int)&lbl_803DBFB8;
      if (GameBit_Get(415) != 0) {
        *(u8 *)(p2 + 0x408) = 6;
      }
      break;
    case 6:
      *(int *)(p2 + 0x48) = (int)&lbl_803DBFBC;
      break;
  }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 timeDelta;
extern f32 lbl_803E520C;
extern f32 lbl_803E5218;
extern void Sfx_PlayFromObject(int *obj, int sfx);
extern void *gSHthorntailAnimationInterface;
extern void *gPartfxInterface;
typedef struct {
    u8 pad[0xc];
    f32 pos[3];
} WoPartfxBlock;
typedef void (*WoPartfxFn)(int *obj, int id, void *blk, int flags, int p5, int p6);

#pragma scheduling off
#pragma peephole off
int fn_801CE078(int *obj, u8 *st) {
    u8 cv;
    int snd;
    u8 buf[4];
    WoPartfxBlock blk;

    cv = ((u8 (*)(u8 *))((void **)*(void **)gSHthorntailAnimationInterface)[0x24 / 4])(buf);
    if (*(s8 *)(st + 0x45b) != 0) {
        snd = !*(s8 *)(st + 0x453);
    } else {
        snd = 0;
    }
    if (st[0x408] < 0x14) {
        if (cv != 0) {
            if (*(f32 *)(st + 0x54) > lbl_803E520C) {
                return -1;
            }
            st[0x409] = st[0x408];
            st[0x408] = 0x14;
        } else {
            return 0;
        }
    }
    switch (st[0x408]) {
    case 0x14:
        if (snd != 0) {
            Sfx_PlayFromObject(obj, 0x14b);
        }
        if (st[0x43c] & 2) {
            st[0x408] = 0x15;
            *(f32 *)(st + 4) = (f32)(s32)randomGetRange(0, 300);
        }
        break;
    case 0x15:
        if (snd != 0) {
            Sfx_PlayFromObject(obj, 0x14c);
        }
        *(f32 *)(st + 4) -= timeDelta;
        if (cv == 0 && *(f32 *)(st + 4) <= lbl_803E520C) {
            st[0x408] = 0x16;
        }
        {
            f32 t = *(f32 *)(st + 0x1c) - timeDelta;
            *(f32 *)(st + 0x1c) = t;
            if (t <= lbl_803E520C) {
                if (*(u16 *)((char *)obj + 0xb0) & 0x800) {
                    blk.pos[0] = *(f32 *)(st + 0xc);
                    blk.pos[1] = *(f32 *)(st + 0x10);
                    blk.pos[2] = *(f32 *)(st + 0x14);
                    (*(WoPartfxFn *)(*(char **)gPartfxInterface + 8))(obj, 0x7f0, &blk, 0x200001, -1, 0);
                }
                *(f32 *)(st + 0x1c) = lbl_803E5218;
            }
        }
        break;
    case 0x16:
        if (snd != 0) {
            Sfx_PlayFromObject(obj, 0x14d);
        }
        if (st[0x43c] & 2) {
            st[0x408] = st[0x409];
        }
        break;
    }
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 oneOverTimeDelta;
extern f32 lbl_803E523C;
extern f32 lbl_803E5240;
extern f32 lbl_803E5244;
extern f32 lbl_803E5248;
extern f32 lbl_803E524C;
extern f32 lbl_803E5250;
extern int lbl_803DBF80;
extern int lbl_803DBF84;
extern int lbl_803DBF88;
extern int lbl_803DBF8C;
extern int lbl_803DBF90;
extern int lbl_803DBF94;
extern int lbl_803DBF98;
extern int lbl_803DBF9C;
extern int lbl_803DBFA0;
extern int lbl_803DBFA4;
extern int curveFn_80010320(u8 *cv, f32 t);
extern void *gRomCurveInterface;
extern void ObjAnim_SampleRootCurvePhase(short *obj, u8 *p2, f32 speed);
extern int getAngle(f32 a, f32 b);
extern f32 sqrtf(f32 x);

#pragma scheduling off
#pragma peephole off
void fn_801CEA14(short *obj, u8 *st, u8 *p3) {
    switch (fn_801CE078((int *)obj, st)) {
    case -1:
        *(f32 *)(st + 0x54) -= lbl_803E523C * timeDelta;
        if (*(f32 *)(st + 0x54) < lbl_803E5240) {
            *(f32 *)(st + 0x54) = lbl_803E520C;
        }
        break;
    case 0:
        if ((*((u8 *)obj + 0xaf) & 4) || *(f32 *)(st + 0x18) < lbl_803E5244) {
            *(f32 *)(st + 0x54) -= lbl_803E5248 * timeDelta;
            if (*(f32 *)(st + 0x54) < lbl_803E5240) {
                *(f32 *)(st + 0x54) = lbl_803E520C;
            }
        } else {
            *(f32 *)(st + 0x54) += lbl_803E523C * timeDelta;
            if (*(f32 *)(st + 0x54) > lbl_803E524C) {
                *(f32 *)(st + 0x54) = lbl_803E524C;
            }
        }
        break;
    case 1:
        return;
    }
    switch (st[0x408]) {
    case 8:
    {
        u8 *cv = st + 0x5c;
        if (curveFn_80010320(cv, *(f32 *)(st + 0x54)) != 0 || *(int *)(cv + 0x10) != 0) {
            ((void (*)(u8 *))((void **)*(void **)gRomCurveInterface)[0x90 / 4])(cv);
        }
        {
            f32 dx = *(f32 *)(cv + 0x68) - *(f32 *)((char *)obj + 0xc);
            f32 dz = *(f32 *)(cv + 0x70) - *(f32 *)((char *)obj + 0x14);
            ObjAnim_SampleRootCurvePhase(obj, st + 0x4c, oneOverTimeDelta * sqrtf(dx * dx + dz * dz));
        }
        obj[0] = (s16)(getAngle(*(f32 *)(cv + 0x74), *(f32 *)(cv + 0x7c)) + 0x8000);
        *(f32 *)((char *)obj + 0xc) = *(f32 *)(cv + 0x68);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)(cv + 0x70);
        if (*(f32 *)(st + 0x54) <= lbl_803E520C) {
            st[0x408] = 7;
        }
        break;
    }
    case 7:
        if (*(f32 *)(st + 0x54) > lbl_803E5250) {
            st[0x408] = 8;
        }
        break;
    }
    if (*(s8 *)(p3 + 0x1d) == 1) {
        if (GameBit_Get(0x19d) != 0) {
            *(int *)(st + 0x48) = (int)&lbl_803DBF90;
        } else if (GameBit_Get(0x1a2) != 0) {
            *(int *)(st + 0x48) = (int)&lbl_803DBF8C;
        } else if (GameBit_Get(0x102) != 0) {
            *(int *)(st + 0x48) = (int)&lbl_803DBF88;
        } else if (GameBit_Get(0x9e) != 0) {
            *(int *)(st + 0x48) = (int)&lbl_803DBF84;
        } else {
            *(int *)(st + 0x48) = (int)&lbl_803DBF80;
        }
    } else {
        if (GameBit_Get(0x19d) != 0) {
            *(int *)(st + 0x48) = (int)&lbl_803DBFA4;
        } else if (GameBit_Get(0x1a2) != 0) {
            *(int *)(st + 0x48) = (int)&lbl_803DBFA0;
        } else if (GameBit_Get(0x102) != 0) {
            *(int *)(st + 0x48) = (int)&lbl_803DBF9C;
        } else if (GameBit_Get(0x9e) != 0) {
            *(int *)(st + 0x48) = (int)&lbl_803DBF98;
        } else {
            *(int *)(st + 0x48) = (int)&lbl_803DBF94;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E5228;
extern f32 lbl_803E522C;
extern f32 lbl_803E5230;
extern f32 lbl_803E5234;
extern f32 lbl_803E5238;
extern int lbl_803DBFA8;
extern int lbl_803DBFAC;
extern int lbl_803DBFB0;
extern int lbl_803268CC[];
extern int lbl_803268DC[];
extern int *ObjList_FindObjectById(int id);
extern int *fn_80296118(int p);
extern void fn_8014C66C(int *o, int *target);
extern int *tumbleweedbush_findNearestActive(void *pos);
extern f32 vec3f_distanceSquared(void *a, void *b);
extern int *getTrickyObject(void);
extern f32 getXZDistance(void *a, void *b);
extern int Sfx_IsPlayingFromObjectChannel(int *obj, int ch);
extern void fn_80163980(int o);
extern void Obj_FreeObject(int o);
extern int *gObjectTriggerInterface;
extern int *gGameUIInterface;
extern int *gScreenTransitionInterface;

#pragma scheduling off
#pragma peephole off
void fn_801CE2BC(int *obj, u8 *st, short *p3) {
    int near_ = ObjGroup_FindNearestObject(0xf, obj, 0);
    switch (st[0x408]) {
    case 9:
        *(f32 *)(st + 0) += timeDelta;
        if (*(f32 *)(st + 0) > lbl_803E5228) {
            Sfx_PlayFromObject(obj, 0x150);
            *(f32 *)(st + 0) -= lbl_803E5228;
        }
        if (*(f32 *)(st + 0x18) < (f32)(s32)(p3[0xc] * p3[0xc])) {
            st[0x408] = 0xa;
        }
        break;
    case 0xa:
        if (st[0x43c] & 2) {
            st[0x408] = 0xb;
        }
        break;
    case 0xb:
        *(f32 *)(st + 0) += timeDelta;
        if (*(f32 *)(st + 0) > lbl_803E5228) {
            Sfx_PlayFromObject(obj, 0x150);
            *(f32 *)(st + 0) -= lbl_803E5228;
        }
        if (ObjTrigger_IsSet(obj) != 0) {
            (**(void (**)(int, int, int))((char *)(*gObjectTriggerInterface) + 0x48))(3, near_, -1);
            st[0x43c] = (u8)(st[0x43c] | 0x10);
            st[0x408] = 0xd;
            GameBit_Set(0xce1, 1);
            GameBit_Set(0xd32, 1);
        }
        break;
    case 0xc:
        (**(void (**)(int, int))((char *)(*gObjectTriggerInterface) + 0x54))(near_, 0x5aa);
        (**(void (**)(int, int, int))((char *)(*gObjectTriggerInterface) + 0x48))(3, near_, 0x30);
        st[0x408] = 0xd;
        break;
    case 0xd:
    {
        int n = 4;
        if (GameBit_Get(0x120) == 0) {
            n = 3;
        }
        if (GameBit_Get(0x121) == 0) {
            n -= 1;
        }
        {
            int i = 0;
            int *gb = lbl_803268DC;
            int *ids = lbl_803268CC;
            for (; i < n; i++) {
                if (GameBit_Get(*gb) != 0) {
                    GameBit_Set(*gb, 0);
                }
                {
                    int *o2 = ObjList_FindObjectById(*ids);
                    if (fn_80296118(*(int *)(st + 0x28)) == o2) {
                        fn_8014C66C(o2, *(int **)(st + 0x28));
                    } else {
                        int *tw = tumbleweedbush_findNearestActive((char *)o2 + 0x18);
                        if (tw == NULL || vec3f_distanceSquared((char *)tw + 0x18, (char *)o2 + 0x18) < lbl_803E522C) {
                            if (vec3f_distanceSquared(*(char **)(st + 0x28) + 0x18, (char *)o2 + 0x18) < lbl_803E522C) {
                                fn_8014C66C(o2, obj);
                            } else {
                                fn_8014C66C(o2, *(int **)(st + 0x28));
                            }
                        } else {
                            fn_8014C66C(o2, tw);
                        }
                    }
                }
                gb++;
                ids++;
            }
        }
        {
            int *tw2 = tumbleweedbush_findNearestActive(st + 0xc);
            if (tw2 != NULL) {
                int *tk = getTrickyObject();
                (**(void (**)(int *, int *, int, int))((char *)(*(int **)((char *)tk + 0x68)) + 0x28))(tk, obj, 1, 1);
            }
            *(int *)(st + 0x48) = (int)&lbl_803DBFA8;
            if (*(int *)(st + 0x24) == 0) {
                short *cfg = *(short **)((char *)obj + 0x4c);
                if (tw2 != NULL && *(s16 *)((char *)tw2 + 0x46) == 0x3fb) {
                    if (getXZDistance((char *)obj + 0x18, (char *)tw2 + 0x18) < (f32)(s32)(cfg[0xc] * cfg[0xc])) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                            Sfx_PlayFromObject(obj, 0x38a);
                        }
                        if ((**(int (**)(int *))((char *)(*(int **)((char *)tw2 + 0x68)) + 0x30))(tw2) == 0) {
                            (**(void (**)(int *, u8 *))((char *)(*(int **)((char *)tw2 + 0x68)) + 0x2c))(tw2, st + 0xc);
                            *(int **)(st + 0x24) = tw2;
                            st[0x408] = 0xe;
                        }
                    }
                }
            }
        }
        if (!(st[0x43c] & 0x40)) {
            (**(void (**)(int, int))((char *)(*gGameUIInterface) + 0x58))(0xc8, 0x5d0);
            st[0x43c] = (u8)(st[0x43c] | 0x40);
        }
        break;
    }
    case 0xe:
        if (getXZDistance(st + 0xc, *(char **)(st + 0x24) + 0x18) < lbl_803E5230) {
            Sfx_PlayFromObject(obj, 0x38b);
            fn_80163980(*(int *)(st + 0x24));
            st[0x408] = 0xf;
        }
        break;
    case 0xf:
        if (st[0x43c] & 2) {
            Obj_FreeObject(*(int *)(st + 0x24));
            *(int *)(st + 0x24) = 0;
            st[0x43f] = st[0x43f] + 1;
            if (*(s8 *)(st + 0x43f) > 3) {
                st[0x43f] = 3;
            }
            GameBit_Set(0x48b, *(s8 *)(st + 0x43f));
            if (*(s8 *)(st + 0x43f) >= 3) {
                st[0x408] = 0x11;
            } else {
                if (*(s8 *)(st + 0x43f) % 2 == 0) {
                    Sfx_PlayFromObject(obj, 0x14f);
                }
                st[0x408] = 0xd;
            }
        }
        break;
    case 0x10:
        (**(void (**)(int, int))((char *)(*gObjectTriggerInterface) + 0x54))(near_, 0x157c);
        (**(void (**)(int, int, int))((char *)(*gObjectTriggerInterface) + 0x48))(1, near_, 2);
        st[0x408] = 0x13;
        break;
    case 0x11:
        if (!(*(u16 *)(*(char **)(st + 0x28) + 0xb0) & 0x1000) && *(f32 *)(st + 8) >= lbl_803E5234) {
            Sfx_PlayFromObject(obj, 0x109);
            (**(void (**)(int, int))((char *)(*gScreenTransitionInterface) + 0x8))(0x14, 1);
            st[0x408] = 0x12;
            GameBit_Set(0xd32, 0);
            st[0x43c] = (u8)(st[0x43c] & ~0x40);
            (**(void (**)(void))((char *)(*gGameUIInterface) + 0x64))();
        }
        break;
    case 0x12:
        if (!(*(u16 *)(*(char **)(st + 0x28) + 0xb0) & 0x1000)) {
            if ((**(int (**)(void))((char *)(*gScreenTransitionInterface) + 0x14))() != 0) {
                GameBit_Set(0x102, 1);
                (**(void (**)(int, int, int))((char *)(*gObjectTriggerInterface) + 0x48))(1, near_, -1);
                st[0x408] = 0x13;
            }
        }
        break;
    default:
        if (GameBit_Get(0x224) != 0) {
            *(int *)(st + 0x48) = (int)&lbl_803DBFB0;
        } else {
            if (GameBit_Get(0xea7) == 0) {
                GameBit_Set(0xea7, 1);
                GameBit_Set(0x9d5, 1);
            }
            *(int *)(st + 0x48) = (int)&lbl_803DBFAC;
        }
        fn_801CE078(obj, st);
        break;
    }
    if (st[0x43c] & 0x40) {
        if (*(f32 *)(st + 8) < lbl_803E5238 * (f32)*(s8 *)(st + 0x43f)) {
            *(f32 *)(st + 8) += timeDelta;
        }
        if (*(f32 *)(st + 8) >= lbl_803E5234) {
            (**(void (**)(int))((char *)(*gGameUIInterface) + 0x5c))(0xc8);
        } else {
            (**(void (**)(int))((char *)(*gGameUIInterface) + 0x5c))((int)*(f32 *)(st + 8));
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
