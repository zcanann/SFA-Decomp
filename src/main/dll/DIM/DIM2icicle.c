#include "ghidra_import.h"
#include "main/dll/DIM/DIM2icicle.h"

extern undefined4 FUN_80003494();
extern undefined8 FUN_80006728();
extern undefined4 FUN_80006824();
extern undefined4 FUN_8000691c();
extern undefined4 FUN_80006920();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017544();
extern undefined4 FUN_80017548();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_80017580();
extern undefined4 FUN_80017584();
extern undefined4 FUN_80017588();
extern undefined4 FUN_80017594();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175d8();
extern undefined4 FUN_800175ec();
extern void* FUN_80017624();
extern undefined8 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjMsg_SendToObject();
extern uint ObjPath_GetPointModelMtx();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_80053c98();
extern undefined4 skyFn_800894a8();
extern undefined4 skyFn_800895e0();
extern undefined4 skyFn_80089710();
extern undefined8 FUN_8012e0b8();
extern undefined4 FUN_801bbf98();
extern undefined4 FUN_80247bf8();
extern undefined8 FUN_80286824();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286870();
extern undefined4 FUN_8028688c();
extern uint FUN_80294bd8();

extern undefined4 DAT_802c2ac8;
extern undefined4 DAT_802c2acc;
extern undefined4 DAT_802c2ad0;
extern undefined4 DAT_802c2ad4;
extern undefined4 DAT_80326620;
extern undefined4 DAT_80326624;
extern undefined4 DAT_803266f8;
extern undefined4 DAT_803266fc;
extern undefined4 DAT_80326700;
extern undefined4 DAT_80326704;
extern undefined4 DAT_803ad5d0;
extern undefined4 DAT_803ad5d4;
extern undefined4 DAT_803ad5d8;
extern undefined4 DAT_803ad5dc;
extern undefined4 DAT_803ad5e8;
extern undefined4 DAT_803ad5ec;
extern undefined4 DAT_803ad5f0;
extern undefined4 DAT_803ad5f4;
extern undefined4 DAT_803ad5f6;
extern undefined4 DAT_803ad5f8;
extern undefined4 DAT_803ad5fc;
extern undefined4 DAT_803ad600;
extern undefined4 DAT_803ad604;
extern undefined4 DAT_803ad608;
extern undefined4 DAT_803adc60;
extern undefined4 DAT_803adc78;
extern undefined4* DAT_803dd6f4;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd734;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de800;
extern undefined4* DAT_803de808;
extern undefined4 DAT_803de80c;
extern f64 DOUBLE_803e5878;
extern f32 lbl_803DC074;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E5854;
extern f32 lbl_803E585C;
extern f32 lbl_803E5860;
extern f32 lbl_803E5864;
extern f32 lbl_803E5870;
extern f32 lbl_803E5884;
extern f32 lbl_803E588C;
extern f32 lbl_803E5890;
extern f32 lbl_803E58A8;
extern f32 lbl_803E58C0;
extern f32 lbl_803E58C4;
extern f32 lbl_803E58C8;
extern f32 lbl_803E58CC;
extern f32 lbl_803E58D0;
extern f32 lbl_803E58D4;
extern f32 lbl_803E58D8;
extern f32 lbl_803E58DC;
extern f32 lbl_803E58E0;
extern f32 lbl_803E58E4;
extern f32 lbl_803E58E8;
extern f32 lbl_803E58EC;
extern f32 lbl_803E58F0;
extern f32 lbl_803E58F4;
extern f32 lbl_803E58F8;
extern f32 lbl_803E58FC;
extern f32 lbl_803E5900;
extern f32 lbl_803E5904;
extern f32 lbl_803E5908;
extern f32 lbl_803E590C;
extern undefined4 gDIMbossAnimTable[];
extern undefined4 gDIMbossHitDetectAnimTable[];
extern void DIM2icicle_spawnBlueWhiteEffect(int* sourceObj, f32* velocity);
extern void DIM2icicle_createStateLight(int obj, u8 isGreen);

extern int getTrickyObject(void);
extern undefined4* gBaddieControlInterface;
extern int gPlayerInterface;
extern u32 gDIMbossSequenceFlags;
extern f32 timeDelta;
extern f32 lbl_803E4BC8;
extern f32 lbl_803E4BD8;
extern f32 lbl_803E4BEC;
extern f32 lbl_803E4C44;
extern f32 lbl_803E4C70;
extern f32 lbl_803E4C74;
extern u8 lbl_803259E0[];

typedef struct IcicleEntry {
    f32 resetTime;
    u16 bit;
    u16 pad;
} IcicleEntry;

typedef struct IcicleState {
    u8 pad[0xa0];
    f32 meltTimer;
    f32 lightTimer;
    f32 fadeTimer;
    u8 pad2[9];
    u8 index;
} IcicleState;

extern void lightVecFn_8001dd88(int *light, f32 x, f32 y, f32 z);
extern void fn_8001D9F4(int light, u8 *a, u8 *b, u8 *c, u8 *d);
extern void fn_8001D71C(int light, u8 a, u8 b, u8 c, int d);
extern void PSMTXMultVec(f32 *mtx, f32 *src, f32 *dst);
extern void memcpy(void *dst, void *src, int n);
extern void *gPartfxInterface;
extern const f32 lbl_803E4BCC;
extern const f32 lbl_803E4C34;
extern const f32 lbl_803E4C38;
extern f32 lbl_803E4C3C;
extern f32 lbl_803E4C40;
extern f32 lbl_803E4C48;
extern u8 lbl_803AC97C[];
extern f32 lbl_803AC970[];

typedef struct IcicleFxPos {
    u8 pad[0xc];
    f32 x;
    f32 y;
    f32 z;
} IcicleFxPos;

/*
 * --INFO--
 *
 * Function: fn_801BB598
 * EN v1.0 Address: 0x801BB598
 * EN v1.0 Size: 1452b
 * EN v1.1 Size: 1452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void fn_801BB598(int objIndex, int param_2)
{
  int *piVar4;
  int *state;
  s16 brightness;
  int i;
  int iVar6;
  f32 zero;
  f32 m[12];
  u8 colA;
  u8 colB;
  u8 colG;
  u8 colR;

  state = *(int **)(param_2 + 0x40c);
  piVar4 = (int *)*state;
  if (piVar4 != NULL) {
    if (*(s16 *)(param_2 + 0x402) == 1) {
      lightVecFn_8001dd88(piVar4, *(f32 *)(state + 0x16), *(f32 *)(state + 0x17), *(f32 *)(state + 0x18));
    }
    else {
      lightVecFn_8001dd88(piVar4, *(f32 *)(state + 0x10), *(f32 *)(state + 0x11), *(f32 *)(state + 0x12));
    }
    fn_8001D9F4(*state, &colA, &colB, &colG, &colR);
    fn_8001D71C(*state, colA, colB, colG, 0xc0);
    iVar6 = *state;
    if (*(u8 *)(iVar6 + 0x2f8) != 0 && *(u8 *)(iVar6 + 0x4c) != 0) {
      brightness = *(u8 *)(iVar6 + 0x2f9) + *(s8 *)(iVar6 + 0x2fa);
      if (brightness < 0) {
        brightness = 0;
        *(u8 *)(iVar6 + 0x2fa) = 0;
      }
      else if (brightness > 0xc) {
        brightness = brightness + randomGetRange(-0xc, 0xc);
        if (brightness > 0xff) {
          brightness = 0xff;
          *(u8 *)(*state + 0x2fa) = 0;
        }
      }
      *(u8 *)(*state + 0x2f9) = brightness;
    }
  }
  if (gDIMbossSequenceFlags & 0x200) {
    ObjPath_GetPointWorldPosition(objIndex, 7, &((IcicleFxPos *)&lbl_803AC97C)->x, &((IcicleFxPos *)&lbl_803AC97C)->y, &((IcicleFxPos *)&lbl_803AC97C)->z, 0);
    i = 0;
    do {
      ((void (*)(int, int, void *, int, int, int))*(code **)(*(int *)gPartfxInterface + 8))(objIndex, 0x4b7, &lbl_803AC97C, 0x200001, -1, 0);
      i = i + 1;
    } while (i < 0xf);
  }
  if (gDIMbossSequenceFlags & 0x400) {
    ObjPath_GetPointWorldPosition(objIndex, 8, &((IcicleFxPos *)&lbl_803AC97C)->x, &((IcicleFxPos *)&lbl_803AC97C)->y, &((IcicleFxPos *)&lbl_803AC97C)->z, 0);
    i = 0;
    do {
      ((void (*)(int, int, void *, int, int, int))*(code **)(*(int *)gPartfxInterface + 8))(objIndex, 0x4b7, &lbl_803AC97C, 0x200001, -1, 0);
      i = i + 1;
    } while (i < 0xf);
  }
  if (gDIMbossSequenceFlags & 0x800) {
    ObjPath_GetPointWorldPosition(objIndex, 9, &((IcicleFxPos *)&lbl_803AC97C)->x, &((IcicleFxPos *)&lbl_803AC97C)->y, &((IcicleFxPos *)&lbl_803AC97C)->z, 0);
    i = 0;
    do {
      ((void (*)(int, int, void *, int, int, int))*(code **)(*(int *)gPartfxInterface + 8))(objIndex, 0x4b7, &lbl_803AC97C, 0x200001, -1, 0);
      i = i + 1;
    } while (i < 0xf);
  }
  if (gDIMbossSequenceFlags & 0x1000) {
    ObjPath_GetPointWorldPosition(objIndex, 10, &((IcicleFxPos *)&lbl_803AC97C)->x, &((IcicleFxPos *)&lbl_803AC97C)->y, &((IcicleFxPos *)&lbl_803AC97C)->z, 0);
    i = 0;
    do {
      ((void (*)(int, int, void *, int, int, int))*(code **)(*(int *)gPartfxInterface + 8))(objIndex, 0x4b7, &lbl_803AC97C, 0x200001, -1, 0);
      i = i + 1;
    } while (i < 0xf);
  }
  if (gDIMbossSequenceFlags & 0x10) {
    memcpy(m, (void *)ObjPath_GetPointModelMtx(objIndex, 0xb), 0x30);
    zero = lbl_803E4BD8;
    m[3] = zero;
    m[7] = zero;
    m[11] = zero;
    i = 0;
    do {
      ((IcicleFxPos *)&lbl_803AC97C)->x = (f32)(int)randomGetRange(-0x19, 0x19);
      ((IcicleFxPos *)&lbl_803AC97C)->y = (f32)(int)randomGetRange(-0x19, 0x19);
      ((IcicleFxPos *)&lbl_803AC97C)->z = lbl_803E4C34;
      lbl_803AC970[0] = ((IcicleFxPos *)&lbl_803AC97C)->x / (lbl_803E4C34 * lbl_803E4C38);
      lbl_803AC970[1] = ((IcicleFxPos *)&lbl_803AC97C)->y / (lbl_803E4C34 * lbl_803E4C38);
      lbl_803AC970[2] = lbl_803E4BCC;
      PSMTXMultVec(m, lbl_803AC970, lbl_803AC970);
      ObjPath_GetPointWorldPosition(objIndex, 0xb, &((IcicleFxPos *)&lbl_803AC97C)->x, &((IcicleFxPos *)&lbl_803AC97C)->y, &((IcicleFxPos *)&lbl_803AC97C)->z, 1);
      ((void (*)(int, int, void *, int, int, f32 *))*(code **)(*(int *)gPartfxInterface + 8))(objIndex, 0x4b8, &lbl_803AC97C, 0x200001, -1, lbl_803AC970);
      i = i + 1;
    } while (i < 5);
  }
  *(f32 *)(state + 10) = lbl_803E4BD8;
  *(f32 *)(state + 0xb) = lbl_803E4C3C;
  *(f32 *)(state + 0xc) = lbl_803E4C40;
  *(f32 *)(state + 9) = lbl_803E4C44;
  *(u16 *)(state + 8) = 0;
  *(u16 *)((int)state + 0x1e) = 0;
  *(u16 *)(state + 7) = 0;
  ObjPath_GetPointWorldPosition(objIndex, 0xd, (f32 *)(state + 10), (f32 *)(state + 0xb), (f32 *)(state + 0xc), 1);
  ObjPath_GetPointWorldPosition(objIndex, 0xd, (f32 *)(state + 4), (f32 *)(state + 5), (f32 *)(state + 6), 0);
  ObjPath_GetPointWorldPosition(objIndex, 0xb, (f32 *)(state + 0x10), (f32 *)(state + 0x11), (f32 *)(state + 0x12), 0);
  *(f32 *)(state + 0x16) = lbl_803E4BD8;
  *(f32 *)(state + 0x17) = lbl_803E4C48;
  *(f32 *)(state + 0x18) = lbl_803E4BC8;
  *(f32 *)(state + 0x15) = lbl_803E4C44;
  *(u16 *)(state + 0x14) = 0;
  *(u16 *)((int)state + 0x4e) = 0;
  *(u16 *)(state + 0x13) = 0;
  ObjPath_GetPointWorldPosition(objIndex, 0xc, (f32 *)(state + 0x16), (f32 *)(state + 0x17), (f32 *)(state + 0x18), 1);
  memcpy(state + 0x19, (void *)ObjPath_GetPointModelMtx(objIndex, 0), 0x30);
  zero = lbl_803E4BD8;
  *(f32 *)(state + 0x1c) = zero;
  *(f32 *)(state + 0x20) = zero;
  *(f32 *)(state + 0x24) = zero;
  gDIMbossSequenceFlags = gDIMbossSequenceFlags & 0xffffe1ef;
}

/*
 * --INFO--
 *
 * Function: warpDarkIceMines_801bbb44
 * EN v1.0 Address: 0x801BBB44
 * EN v1.0 Size: 1940b
 * EN v1.1 Size: 1940b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void warpDarkIceMines_801bbb44(undefined8 param_1,double param_2,double param_3,
                               undefined8 param_4,undefined8 param_5,undefined8 param_6,
                               undefined8 param_7,undefined8 param_8,undefined4 param_9,
                               undefined4 param_10,undefined4 param_11,undefined4 param_12,
                               undefined4 param_13,undefined4 param_14,undefined4 param_15,
                               undefined4 param_16)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 extraout_f1;
  double dVar6;
  double in_f29;
  double in_f30;
  double dVar7;
  double in_f31;
  double dVar8;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar9;
  float local_78;
  float local_74;
  float local_70;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
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
  uVar9 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  iVar5 = *(int *)(iVar4 + 0x40c);
  if ((*(int *)(iVar5 + 0xb0) == 0) ||
     (*(int *)(iVar5 + 0xb0) = *(int *)(iVar5 + 0xb0) + -1, 0 < *(int *)(iVar5 + 0xb0))) {
    if (*(char *)(iVar5 + 0xb6) < '\0') {
      uVar9 = FUN_80006728(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                           0xdb,0,param_13,param_14,param_15,param_16);
      FUN_80006728(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0xdc,0,param_13
                   ,param_14,param_15,param_16);
      skyFn_80089710(7,1,0);
      skyFn_800894a8((double)lbl_803E58E4,(double)lbl_803E58E8,(double)lbl_803E58EC,7);
      skyFn_800895e0(7,0xa0,0xa0,0xff,0x7f,0x28);
      *(byte *)(iVar5 + 0xb6) = *(byte *)(iVar5 + 0xb6) & 0x7f;
    }
    if ((*(uint *)(iVar4 + 0x314) & 4) != 0) {
      *(uint *)(iVar4 + 0x314) = *(uint *)(iVar4 + 0x314) & 0xfffffffb;
      FUN_80006824(uVar1,(ushort)DAT_803266f8);
      DAT_803de800 = DAT_803de800 | 0x204;
      FUN_80006b94((double)lbl_803E5890);
    }
    if ((*(uint *)(iVar4 + 0x314) & 2) != 0) {
      *(uint *)(iVar4 + 0x314) = *(uint *)(iVar4 + 0x314) & 0xfffffffd;
      FUN_80006824(uVar1,(ushort)DAT_803266fc);
      DAT_803de800 = DAT_803de800 | 0x404;
      FUN_80006b94((double)lbl_803E5890);
    }
    if ((*(uint *)(iVar4 + 0x314) & 0x10) != 0) {
      *(uint *)(iVar4 + 0x314) = *(uint *)(iVar4 + 0x314) & 0xffffffef;
      FUN_80006824(uVar1,(ushort)DAT_80326700);
      DAT_803de800 = DAT_803de800 | 0x804;
      FUN_80006b94((double)lbl_803E5890);
    }
    if ((*(uint *)(iVar4 + 0x314) & 8) != 0) {
      *(uint *)(iVar4 + 0x314) = *(uint *)(iVar4 + 0x314) & 0xfffffff7;
      FUN_80006824(uVar1,(ushort)DAT_80326704);
      DAT_803de800 = DAT_803de800 | 0x1004;
      FUN_80006b94((double)lbl_803E5890);
    }
    if ((DAT_803de800 & 0x2000) != 0) {
      iVar3 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b1,iVar5 + 0x4c,0x200001,0xffffffff,0);
        iVar3 = iVar3 + 1;
      } while (iVar3 < 0x32);
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b2,iVar5 + 0x4c,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b3,iVar5 + 0x4c,0x200001,0xffffffff,0);
    }
    if ((DAT_803de800 & 0x80000) != 0) {
      (**(code **)(*DAT_803dd734 + 0xc))(uVar1,0x800,0,1,0);
    }
    if (((DAT_803de800 & 0x8020) != 0) || (*(char *)(iVar4 + 0x354) < '\x02')) {
      if ((DAT_803de800 & 0x20) == 0) {
        uVar2 = randomGetRange(0,(int)*(char *)(iVar4 + 0x354));
        if ((uVar2 == 0) && (*(short *)(iVar4 + 0x402) == 2)) {
          (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b4,iVar5 + 0x34,0x200001,0xffffffff,0);
        }
      }
      else {
        iVar4 = 0;
        do {
          (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b4,iVar5 + 0x34,0x200001,0xffffffff,0);
          iVar4 = iVar4 + 1;
        } while (iVar4 < 7);
      }
      if ((DAT_803de800 & 0x8000) != 0) {
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b2,iVar5 + 0x34,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b3,iVar5 + 0x34,0x200001,0xffffffff,0);
      }
    }
    if ((DAT_803de800 & 0x101c0) != 0) {
      if ((DAT_803de800 & 0x40) != 0) {
        iVar4 = 0;
        dVar7 = (double)lbl_803E58F0;
        dVar8 = (double)lbl_803E58F4;
        dVar6 = DOUBLE_803e5878;
        do {
          uStack_64 = randomGetRange(0xfffffffb,5);
          uStack_64 = uStack_64 ^ 0x80000000;
          local_68 = 0x43300000;
          local_78 = (float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uStack_64) - dVar6)
                            );
          uStack_5c = randomGetRange(0xfffffffb,5);
          uStack_5c = uStack_5c ^ 0x80000000;
          local_60 = 0x43300000;
          local_74 = (float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - dVar6)
                            );
          uStack_54 = randomGetRange(2,8);
          uStack_54 = uStack_54 ^ 0x80000000;
          local_58 = 0x43300000;
          local_70 = (float)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) - dVar6)
                            );
          FUN_80247bf8((float *)(iVar5 + 100),&local_78,&local_78);
          (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b5,iVar5 + 0x1c,0x200001,0xffffffff,&local_78);
          iVar4 = iVar4 + 1;
        } while (iVar4 < 5);
      }
      if ((DAT_803de800 & 0x80) != 0) {
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b5,iVar5 + 4,0x200001,0xffffffff,0);
      }
      if ((DAT_803de800 & 0x100) != 0) {
        local_78 = lbl_803E58F0;
        local_74 = lbl_803E58F8;
        uStack_54 = randomGetRange(4,8);
        uStack_54 = uStack_54 ^ 0x80000000;
        local_58 = 0x43300000;
        local_70 = lbl_803E58FC *
                   (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e5878);
        FUN_80247bf8((float *)(iVar5 + 100),&local_78,&local_78);
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b6,iVar5 + 4,0x200001,0xffffffff,&local_78);
      }
      if ((DAT_803de800 & 0x10000) != 0) {
        local_78 = lbl_803E5870;
        local_74 = lbl_803E58F8;
        local_70 = lbl_803E5900;
        FUN_80247bf8((float *)(iVar5 + 100),&local_78,&local_78);
        FUN_80003494(iVar5 + 0x94,(uint)&local_78,0xc);
        DAT_803de800 = DAT_803de800 | 0x20000;
      }
    }
    if ((DAT_803de800 & 0x4000) != 0) {
      iVar4 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b7,0,1,0xffffffff,0);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x32);
    }
    if ((DAT_803de800 & 1) != 0) {
      FUN_800069bc();
      FUN_80006b94((double)lbl_803E5890);
      FUN_8000691c((double)lbl_803E585C,(double)lbl_803E5860,(double)lbl_803E5864);
    }
    if ((DAT_803de800 & 0x40000) != 0) {
      FUN_800069bc();
      FUN_80006b94((double)lbl_803E5904);
      FUN_8000691c((double)lbl_803E5860,(double)lbl_803E588C,(double)lbl_803E5890);
    }
    if ((DAT_803de800 & 2) != 0) {
      FUN_800069bc();
      dVar6 = (double)lbl_803E5870;
      FUN_8000691c(dVar6,dVar6,dVar6);
      FUN_80006920((double)lbl_803E5870);
    }
    if ((DAT_803de800 & 4) == 0) {
      GameBit_Set(0x25e,0);
    }
    else {
      GameBit_Set(0x25e,1);
    }
    DAT_803de800 = DAT_803de800 & 0xa1ff0;
  }
  else {
    *(undefined4 *)(iVar5 + 0xb0) = 0;
    uVar9 = FUN_8012e0b8('\0');
    FUN_80053c98(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x77,'\x01',param_11,
                 param_12,param_13,param_14,param_15,param_16);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: fn_801BC2D8
 * EN v1.0 Address: 0x801BC2D8
 * EN v1.0 Size: 1292b
 * EN v1.1 Size: 1292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801BC2D8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  bool bVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 in_r7;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  undefined8 uVar8;
  int local_40;
  uint uStack_3c;
  int local_38;
  undefined4 local_34;
  int local_30;
  int local_2c;
  undefined4 local_28;
  
  uVar8 = FUN_80286840();
  uVar3 = (uint)((ulonglong)uVar8 >> 0x20);
  iVar6 = (int)uVar8;
  iVar7 = *(int *)(uVar3 + 0xb8);
  FUN_80017a98();
  bVar1 = false;
  local_34 = DAT_802c2ac8;
  local_30 = DAT_802c2acc;
  local_2c = DAT_802c2ad0;
  local_28 = DAT_802c2ad4;
  if (DAT_803de80c != 0) {
    DAT_803de80c = DAT_803de80c + -1;
  }
  iVar4 = ObjHits_GetPriorityHit(uVar3,&local_40,&local_38,&uStack_3c);
  if (iVar4 != 0) {
    uVar2 = DAT_803de800 & 0xffffffbf;
    if (*(short *)(iVar7 + 0x402) == 1) {
      if (((DAT_803de800 & 8) == 0) || (local_38 != 2)) {
        bVar1 = true;
      }
    }
    else if ((*(short *)(iVar7 + 0x402) == 2) &&
            (((local_38 != 4 || (*(float *)(uVar3 + 0x98) < lbl_803E58A8)) ||
             (*(short *)(uVar3 + 0xa0) != 0x12)))) {
      bVar1 = true;
    }
    DAT_803de800 = uVar2;
    if (bVar1) {
      if (DAT_803de80c == 0) {
        FUN_80006824(uVar3,0x4b2);
        iVar6 = *(int *)(*(int *)(*(int *)(uVar3 + 0x7c) + *(char *)(uVar3 + 0xad) * 4) + 0x50) +
                local_38 * 0x10;
        DAT_803ad600 = lbl_803DDA58 + *(float *)(iVar6 + 4);
        DAT_803ad604 = *(float *)(iVar6 + 8);
        DAT_803ad608 = lbl_803DDA5C + *(float *)(iVar6 + 0xc);
        (**(code **)(*DAT_803dd708 + 8))(uVar3,0x328,&DAT_803ad5f4,0x200001,0xffffffff,0);
        DAT_803ad600 = DAT_803ad600 - *(float *)(uVar3 + 0x18);
        DAT_803ad604 = DAT_803ad604 - *(float *)(uVar3 + 0x1c);
        DAT_803ad608 = DAT_803ad608 - *(float *)(uVar3 + 0x20);
        DAT_803ad5fc = lbl_803E58DC;
        DAT_803ad5f4 = 0;
        DAT_803ad5f6 = 0;
        DAT_803ad5f8 = 0;
        uVar2 = randomGetRange(0,0x9b);
        local_30 = local_30 + uVar2;
        uVar2 = randomGetRange(0,0x9b);
        local_2c = local_2c + uVar2;
        (**(code **)(*DAT_803de808 + 4))(uVar3,0,&DAT_803ad5f4,1,0xffffffff,&local_34);
        DAT_803de80c = 0x1e;
      }
    }
    else {
      if (*(int *)(iVar6 + 0x2d0) == 0) {
        iVar5 = FUN_80017a98();
        uVar2 = FUN_80294bd8(iVar5,1);
        if (uVar2 != 0) {
          in_r7 = 0;
          in_r8 = 2;
          in_r9 = 10;
          in_r10 = 0xffffffff;
          (**(code **)(*DAT_803dd738 + 0x28))
                    (uVar3,iVar6,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4));
          *(int *)(iVar6 + 0x2d0) = iVar5;
          *(undefined *)(iVar6 + 0x349) = 0;
        }
      }
      if (*(short *)(iVar7 + 0x402) == 1) {
        if (*(char *)(iVar6 + 0x354) == '\x03') {
          in_r7 = 0;
          in_r8 = *DAT_803dd6f4;
          (**(code **)(in_r8 + 4))(uVar3,0x68,0,0);
        }
        else if (*(char *)(iVar6 + 0x354) == '\x02') {
          in_r7 = 0;
          in_r8 = *DAT_803dd6f4;
          (**(code **)(in_r8 + 4))(uVar3,0x6c,0,0);
        }
      }
      else if (*(short *)(iVar7 + 0x402) == 2) {
        if (*(char *)(iVar6 + 0x354) == '\x03') {
          in_r7 = 0;
          in_r8 = *DAT_803dd6f4;
          (**(code **)(in_r8 + 4))(uVar3,0x77,0,0);
        }
        else if (*(char *)(iVar6 + 0x354) == '\x02') {
          in_r7 = 0;
          in_r8 = *DAT_803dd6f4;
          (**(code **)(in_r8 + 4))(uVar3,0x78,0,0);
        }
      }
      *(undefined *)(iVar6 + 0x346) = 0;
      *(char *)(iVar6 + 0x34f) = (char)iVar4;
      *(char *)(iVar6 + 0x354) = *(char *)(iVar6 + 0x354) + -1;
      FUN_80006824(uVar3,0x4b1);
      if (*(char *)(iVar6 + 0x354) < '\x01') {
        *(undefined *)(iVar6 + 0x354) = 0;
        *(undefined *)(iVar6 + 0x349) = 0;
        (**(code **)(*DAT_803dd70c + 0x14))(uVar3,iVar6,0);
        *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) =
             *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) & ~1;
        *(byte *)(uVar3 + 0xaf) = *(byte *)(uVar3 + 0xaf) | 8;
        *(byte *)(uVar3 + 0xaf) = *(byte *)(uVar3 + 0xaf) & 0x7f;
        uVar8 = GameBit_Set(0x20e,1);
        if (*(short *)(iVar7 + 0x402) == 1) {
          uVar8 = GameBit_Set(0x20b,1);
        }
        else if (*(short *)(iVar7 + 0x402) == 2) {
          uVar8 = GameBit_Set(0x266,1);
        }
      }
      else if (*(short *)(iVar7 + 0x402) == 1) {
        uVar8 = (**(code **)(*DAT_803dd70c + 0x14))(uVar3,iVar6,10);
      }
      else {
        uVar8 = (**(code **)(*DAT_803dd70c + 0x14))(uVar3,iVar6,0xb);
      }
      ObjMsg_SendToObject(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_40,0xe0001,
                   uVar3,0,in_r7,in_r8,in_r9,in_r10);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: fn_801BC7E4
 * EN v1.0 Address: 0x801BC7E4
 * EN v1.0 Size: 848b
 * EN v1.1 Size: 848b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801BC7E4(int obj, int param_2, int param_3, int param_4)
{
  IcicleState *state;
  u8 *tricky;
  f32 timer;
  f32 limit;

  state = *(IcicleState **)(param_3 + 0x40c);
  tricky = (u8 *)getTrickyObject();
  ObjHits_EnableObject(obj);
  *(u8 *)(param_4 + 0x25f) = 1;
  ((void (*)(int, int, f32, int))*(code **)(*gBaddieControlInterface + 0x2c))(obj, param_4, lbl_803E4C70, 1);
  ((void (*)(int, int, int, int, int, int, int, int))*(code **)(*gBaddieControlInterface + 0x54))
            (obj, param_4, param_3 + 0x35c, (int)*(s16 *)(param_3 + 0x3f4), param_3 + 0x405, 0, 0, 0);
  if (*(s16 *)(param_4 + 0x274) == 6) {
    state->meltTimer =
         -(timeDelta * (lbl_803E4BC8 * *(f32 *)(obj + 0x98) + lbl_803E4C44) - state->meltTimer);
  }
  else {
    state->meltTimer = state->meltTimer - timeDelta;
  }
  if (state->meltTimer <= lbl_803E4BD8) {
    IcicleEntry *entry = (IcicleEntry *)lbl_803259E0;
    GameBit_Set(entry[state->index].bit, 1);
    state->meltTimer = *(f32 *)(lbl_803259E0 + state->index * 8);
    state->index++;
    if (state->index > 0x17) {
      state->index = 0;
    }
  }
  if (tricky != NULL) {
    timer = state->lightTimer;
    if (timer > lbl_803E4BD8) {
      limit = lbl_803E4C74;
      if (timer <= limit) {
        state->lightTimer = timer + timeDelta;
        if (state->lightTimer >= limit) {
          ((void (*)(u8 *, int, int))*(code **)(*(int *)(*(int *)(tricky + 0x68)) + 0x34))(tricky, 1, obj);
        }
      }
    }
    if (state->fadeTimer > (timer = lbl_803E4BD8)) {
      state->fadeTimer = state->fadeTimer + timeDelta;
      if (state->fadeTimer >= lbl_803E4BEC) {
        *(u16 *)(param_3 + 0x400) &= ~4;
        state->fadeTimer = timer;
        ((void (*)(u8 *, int, int))*(code **)(*(int *)(*(int *)(tricky + 0x68)) + 0x34))(tricky, 0, 0);
        state->lightTimer = lbl_803E4C44;
      }
    }
    else if (*(s16 *)(param_3 + 0x402) == 1) {
      *(u16 *)(param_3 + 0x400) |= 4;
      state->fadeTimer = lbl_803E4C44;
      DIM2icicle_createStateLight(obj, 0);
    }
  }
  if (*(s16 *)(param_3 + 0x402) == 2) {
    DIM2icicle_createStateLight(obj, 1);
  }
  {
    /* MWCC quirk: target materializes ~0x20000 via lis/addi; clean C folds to rlwinm */
    register u32 tmp;
    register u32 hi;
    register u32 flags;
    flags = gDIMbossSequenceFlags;
    if (flags & 0x20000) {
      asm {
        lis hi, -2
        addi tmp, hi, -1
        and tmp, flags, tmp
      }
      gDIMbossSequenceFlags = tmp;
      DIM2icicle_spawnBlueWhiteEffect((int *)(*(int *)(param_3 + 0x40c) + 4), (f32 *)(*(int *)(param_3 + 0x40c) + 0x94));
    }
  }
  if (*(u16 *)(param_3 + 0x400) & 4) {
    gDIMbossSequenceFlags |= 8;
  }
  if (*(s16 *)(param_3 + 0x402) == 1) {
    ((void (*)(u8 *, int, int, int))*(code **)(*(int *)(*(int *)(tricky + 0x68)) + 0x28))(tricky, obj, 1, 2);
    *(u8 *)(obj + 0xe4) = 1;
  }
  else {
    *(u8 *)(obj + 0xe4) = 2;
  }
  *(int *)(param_3 + 0x3e0) = *(int *)(obj + 0xc0);
  *(int *)(obj + 0xc0) = 0;
  ((void (*)(f32, int, int, f32, void *, void *))*(code **)(*(int *)gPlayerInterface + 8))
            (timeDelta, obj, param_4, timeDelta, gDIMbossHitDetectAnimTable, gDIMbossAnimTable);
  *(int *)(obj + 0xc0) = *(int *)(param_3 + 0x3e0);
}
