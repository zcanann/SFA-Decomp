#include "ghidra_import.h"
#include "main/dll/explosion.h"


extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80006c10();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_8001771c();
extern int FUN_80017a98();
extern int ObjHits_GetPriorityHit();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern int FUN_80044404();
extern undefined4 FUN_80055ef0();
extern undefined4 FUN_80057690();
extern undefined8 FUN_80080f28();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80294ccc();

extern undefined4 DAT_802c2b48;
extern undefined4 DAT_802c2b4c;
extern undefined4 DAT_802c2b50;
extern undefined4 DAT_802c2b54;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc270;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f0;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de850;
extern undefined4 DAT_803de858;
extern f64 DOUBLE_803e5de0;
extern f32 lbl_803E5DD0;
extern f32 lbl_803E5DD4;
extern f32 lbl_803E5DD8;
extern f32 lbl_803E5DDC;

/*
 * --INFO--
 *
 * Function: dll_197_init
 * EN v1.0 Address: 0x801CA5B4
 * EN v1.0 Size: 1148b
 * EN v1.1 Address: 0x801CA6BC
 * EN v1.1 Size: 1196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void *Resource_Acquire(int idx, int p);
extern f32 lbl_803E513C;
extern f32 lbl_803E5140;
extern f32 lbl_803E5144;
extern f64 lbl_803E5148;

#pragma scheduling off
#pragma peephole off
void dll_197_init(int obj, int data)
{
    u8 *st;
    int *res;
    struct {
        u8 buf[16];
        f32 f;
    } stk;

    st = *(u8 **)(obj + 0xb8);
    *(s16 *)obj = (s16)(((s8)*(u8 *)(data + 0x18) & 0x3fu) << 10);
    if (*(s16 *)(data + 0x1a) > 0) {
        *(f32 *)(obj + 8) = (f32)*(s16 *)(data + 0x1a) / lbl_803E5140;
    } else {
        *(f32 *)(obj + 8) = lbl_803E5144;
    }
    *(u8 *)(st + 0xb) = *(u8 *)(data + 0x19);
    *(u8 *)(st + 0xc) = 0;
    *(u8 *)(st + 0xf) = 0;
    *(int *)st = *(s16 *)(data + 0x1e);
    stk.f = lbl_803E513C;
    switch (*(u8 *)(st + 0xb)) {
    case 0:
        *(u8 *)(st + 0xc) = 1;
        res = (int *)Resource_Acquire(0x69, 1);
        if (*(s16 *)(data + 0x1c) == 0) {
            (**(void (**)(int, int, void *, int, int, int))(*res + 4))(obj, 0, stk.buf, 0x10004, -1, 0);
        }
        break;
    case 1:
        *(u8 *)(st + 0xf) = *(s16 *)(data + 0x1c);
        *(u8 *)(st + 0xd) = 0;
        *(s16 *)(st + 8) = *(u8 *)(st + 0xf) * 0x28 + 0x398;
        *(u8 *)(st + 0xe) = 0;
        break;
    }
    *(s16 *)(st + 4) = 0;
}
#pragma peephole reset
#pragma scheduling reset


/*
 * --INFO--
 *
 * Function: FUN_801caa30
 * EN v1.0 Address: 0x801CAA30
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x801CAB68
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801caa30(undefined2 *param_1,int param_2)
{
  int *piVar1;
  int *piVar2;
  undefined auStack_38 [16];
  float local_28;
  undefined4 local_20;
  uint uStack_1c;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  *param_1 = (short)(((int)*(char *)(param_2 + 0x18) & 0x3fU) << 10);
  if (*(short *)(param_2 + 0x1a) < 1) {
    *(float *)(param_1 + 4) = lbl_803E5DDC;
  }
  else {
    uStack_1c = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5de0) / lbl_803E5DD8;
  }
  *(undefined *)((int)piVar2 + 0xb) = *(undefined *)(param_2 + 0x19);
  *(undefined *)(piVar2 + 3) = 0;
  *(undefined *)((int)piVar2 + 0xf) = 0;
  *piVar2 = (int)*(short *)(param_2 + 0x1e);
  local_28 = lbl_803E5DD4;
  if (*(char *)((int)piVar2 + 0xb) == '\x01') {
    *(char *)((int)piVar2 + 0xf) = (char)*(undefined2 *)(param_2 + 0x1c);
    *(undefined *)((int)piVar2 + 0xd) = 0;
    *(ushort *)(piVar2 + 2) = (ushort)*(byte *)((int)piVar2 + 0xf) * 0x28 + 0x398;
    *(undefined *)((int)piVar2 + 0xe) = 0;
  }
  else if (*(char *)((int)piVar2 + 0xb) == '\0') {
    *(undefined *)(piVar2 + 3) = 1;
    piVar1 = (int *)FUN_80006b14(0x69);
    if (*(short *)(param_2 + 0x1c) == 0) {
      (**(code **)(*piVar1 + 4))(param_1,0,auStack_38,0x10004,0xffffffff,0);
    }
  }
  *(undefined2 *)(piVar2 + 1) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cab60
 * EN v1.0 Address: 0x801CAB60
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x801CACCC
 * EN v1.1 Size: 320b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801cab60(undefined4 param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_80017a98();
  if (iVar1 != 0) {
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
      if (*(char *)(param_3 + iVar2 + 0x81) == '\x01') {
        FUN_80294ccc(iVar1,0x10,1);
        FUN_80017698(0x174,1);
        (**(code **)(*DAT_803dd72c + 0x50))(0xb,4,1);
        (**(code **)(*DAT_803dd72c + 0x50))(0xb,0x1d,1);
        (**(code **)(*DAT_803dd72c + 0x50))(0xb,0x1e,1);
        (**(code **)(*DAT_803dd72c + 0x50))(0xb,0x1f,1);
        (**(code **)(*DAT_803dd72c + 0x44))(0xb,6);
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801caca0
 * EN v1.0 Address: 0x801CACA0
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801CAE0C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801caca0(void)
{
  FUN_800067c0((int *)0x6,0);
  FUN_80017698(0xefd,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cacd4
 * EN v1.0 Address: 0x801CACD4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801CAE40
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cacd4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cacfc
 * EN v1.0 Address: 0x801CACFC
 * EN v1.0 Size: 432b
 * EN v1.1 Address: 0x801CAE74
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cacfc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar1;
  
  if ((*(int *)(param_9 + 0xf4) != 0) &&
     (*(int *)(param_9 + 0xf4) = *(int *)(param_9 + 0xf4) + -1, *(int *)(param_9 + 0xf4) == 0)) {
    uVar1 = FUN_80080f28(7,'\x01');
    uVar1 = FUN_80006728(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0xd1,0,
                         in_r7,in_r8,in_r9,in_r10);
    uVar1 = FUN_80006728(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0xd6,0,
                         in_r7,in_r8,in_r9,in_r10);
    FUN_80006728(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x222,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801caeac
 * EN v1.0 Address: 0x801CAEAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CAEF8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801caeac(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801caeb0
 * EN v1.0 Address: 0x801CAEB0
 * EN v1.0 Size: 1240b
 * EN v1.1 Address: 0x801CAF74
 * EN v1.1 Size: 788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801caeb0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,int param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  
  iVar1 = FUN_80286840();
  iVar4 = *(int *)(iVar1 + 0xb8);
  *(undefined2 *)(param_11 + 0x70) = 0xffff;
  *(undefined *)(param_11 + 0x56) = 0;
  uVar5 = extraout_f1;
  if (*(short *)(iVar4 + 10) != 0) {
    *(short *)(iVar4 + 8) = *(short *)(iVar4 + 8) + *(short *)(iVar4 + 10);
    if ((*(short *)(iVar4 + 8) < 2) && (*(short *)(iVar4 + 10) < 1)) {
      *(undefined2 *)(iVar4 + 8) = 1;
      *(undefined2 *)(iVar4 + 10) = 0;
    }
    else if ((0x45 < *(short *)(iVar4 + 8)) && (-1 < *(short *)(iVar4 + 10))) {
      *(undefined2 *)(iVar4 + 8) = 0x46;
      *(undefined2 *)(iVar4 + 10) = 0;
    }
    uVar5 = (**(code **)(*DAT_803dd6f0 + 0x38))(3,*(ushort *)(iVar4 + 8) & 0xff);
  }
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
    switch(*(undefined *)(param_11 + iVar3 + 0x81)) {
    case 1:
      uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1
                           ,0xc3,0,param_13,param_14,param_15,param_16);
      break;
    case 2:
      if (DAT_803dc270 == 0xffffffff) {
        uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                             iVar1,0x14,0,param_13,param_14,param_15,param_16);
      }
      else {
        uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                             iVar1,DAT_803dc270 & 0xffff,0,param_13,param_14,param_15,param_16);
      }
      break;
    case 3:
      *(undefined *)(iVar4 + 0x10) = 1;
      break;
    case 4:
      *(undefined *)(iVar4 + 0xf) = 4;
      *(undefined *)(iVar4 + 0x10) = 2;
      FUN_80017698(0x129,1);
      FUN_80017698(0x1cf,0);
      uVar5 = FUN_80017698(0x126,1);
      *(undefined2 *)(iVar4 + 10) = 0xfffd;
      break;
    case 5:
      *(undefined *)(iVar4 + 0x10) = 3;
      *(undefined2 *)(iVar4 + 10) = 0xfffd;
      uVar5 = FUN_80017698(0x129,1);
      break;
    case 6:
      uVar5 = FUN_80017698(0x1cf,1);
      break;
    case 7:
      uVar5 = FUN_80017698(0x1cf,0);
      *(undefined2 *)(iVar4 + 10) = 0xfffd;
      break;
    case 8:
      uVar5 = FUN_80017698(0x127,1);
      break;
    case 9:
      uVar5 = FUN_80017698(0x128,1);
      if (DAT_803de858 == 0) {
        DAT_803de858 = FUN_80055ef0();
      }
      break;
    case 10:
      *(undefined2 *)(iVar4 + 8) = 100;
      param_13 = 0;
      param_14 = *DAT_803dd6f0;
      uVar5 = (**(code **)(param_14 + 0x18))(3,0x2d,0x50,*(ushort *)(iVar4 + 8) & 0xff);
      break;
    case 0xb:
      *(undefined *)(iVar4 + 0xf) = 7;
    }
    *(undefined *)(param_11 + iVar3 + 0x81) = 0;
  }
  if (*(char *)(iVar4 + 0xf) == '\a') {
    uVar2 = FUN_80006c10(0);
    if ((uVar2 & 0x100) == 0) {
      uVar2 = FUN_80006c10(0);
      if ((uVar2 & 0x200) != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x4c))((int)*(char *)(param_11 + 0x57));
        *(undefined *)(iVar4 + 0xf) = 7;
        *(undefined2 *)(iVar4 + 2) = 0;
      }
    }
    else {
      (**(code **)(*DAT_803dd6d4 + 0x4c))((int)*(char *)(param_11 + 0x57));
      *(undefined *)(iVar4 + 0xf) = 8;
      *(undefined2 *)(iVar4 + 2) = 0;
    }
  }
  FUN_8028688c();
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void dll_197_release(void) {}
void dll_197_initialise(void) {}
void nwsh_levcon_hitDetect(void) {}
void nwsh_levcon_release(void) {}
void nwsh_levcon_initialise(void) {}
void dll_199_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int nwsh_levcon_getExtraSize(void) { return 0x0; }
int nwsh_levcon_getObjectTypeId(void) { return 0x0; }
int dll_199_getExtraSize(void) { return 0x14; }
int dll_199_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5150;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5158;
#pragma peephole off
void nwsh_levcon_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5150); }
void dll_199_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5158); }
#pragma peephole reset

extern void Music_Trigger(int track, int param);
extern int GameBit_Set(int eventId, int value);
#pragma scheduling off
void nwsh_levcon_free(int obj) {
    Music_Trigger(6, 0);
    GameBit_Set(3837, 0);
}
#pragma scheduling reset

extern int NWSH_levcon_SeqFn(int p1, int p2, u8 *p3);
extern int mapGetDirIdx(int mapId);
extern void unlockLevel(int a, int b, int c);
extern void skyFn_80088c94(int a, int b);
extern void getEnvfxAct(int a, int b, int c, int d);

#pragma scheduling off
#pragma peephole off
void nwsh_levcon_update(int *obj) {
    if (*(int*)((char*)obj + 0xf4) != 0) {
        *(int*)((char*)obj + 0xf4) = *(int*)((char*)obj + 0xf4) - 1;
        if (*(int*)((char*)obj + 0xf4) == 0) {
            skyFn_80088c94(7, 1);
            getEnvfxAct(0, 0, 0xd1, 0);
            getEnvfxAct(0, 0, 0xd6, 0);
            getEnvfxAct(0, 0, 0x222, 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void nwsh_levcon_init(int *obj) {
    *(void**)((char*)obj + 0xbc) = (void*)&NWSH_levcon_SeqFn;
    unlockLevel(mapGetDirIdx(0x28), 1, 0);
    Music_Trigger(6, 1);
    *(int*)((char*)obj + 0xf4) = 1;
    GameBit_Set(0xea2, 1);
    GameBit_Set(0xefd, 1);
}
#pragma peephole reset
#pragma scheduling reset

extern void *gModgfxInterface;
extern void *gTitleMenuControlInterface;

#pragma scheduling off
#pragma peephole off
void dll_199_free(int *obj) {
    ((void(*)(int*))((void**)*(void**)gModgfxInterface)[6])(obj);
    ((void(*)(int, int))((void**)*(void**)gTitleMenuControlInterface)[14])(3, 0);
    ((void(*)(int, int))((void**)*(void**)gTitleMenuControlInterface)[14])(2, 0);
}
#pragma peephole reset
#pragma scheduling reset

extern void *Obj_GetPlayerObject(void);
extern void fn_80296518(void *player, int a, int b);
extern int *gMapEventInterface;
extern int *gObjectTriggerInterface;
extern int getButtonsHeld(int pad);
extern int return0_8005669C(int p);
extern int lbl_803DB610;
extern u32 lbl_803DDBD8;

#pragma scheduling off
#pragma peephole off
int NWSH_levcon_SeqFn(int p1, int p2, u8 *p3)
{
    void *player;
    int i;

    player = Obj_GetPlayerObject();
    if (player != 0) {
        for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
            if (p3[i + 0x81] != 1) {
            } else {
                fn_80296518(player, 0x10, 1);
                GameBit_Set(0x174, 1);
                (**(void (**)(int, int, int))(*gMapEventInterface + 0x50))(0xb, 4, 1);
                (**(void (**)(int, int, int))(*gMapEventInterface + 0x50))(0xb, 0x1d, 1);
                (**(void (**)(int, int, int))(*gMapEventInterface + 0x50))(0xb, 0x1e, 1);
                (**(void (**)(int, int, int))(*gMapEventInterface + 0x50))(0xb, 0x1f, 1);
                (**(void (**)(int, int))(*gMapEventInterface + 0x44))(0xb, 6);
            }
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int dll_199_SeqFn(int obj, int p2, u8 *p3)
{
    u8 *st;
    int i;
    int idx;

    st = *(u8 **)(obj + 0xb8);
    *(s16 *)(p3 + 0x70) = -1;
    *(u8 *)(p3 + 0x56) = 0;
    if (*(s16 *)(st + 0xa) != 0) {
        *(s16 *)(st + 8) += *(s16 *)(st + 0xa);
        if (*(s16 *)(st + 8) <= 1 && *(s16 *)(st + 0xa) <= 0) {
            *(s16 *)(st + 8) = 1;
            *(s16 *)(st + 0xa) = 0;
        } else if (*(s16 *)(st + 8) >= 0x46 && *(s16 *)(st + 0xa) >= 0) {
            *(s16 *)(st + 8) = 0x46;
            *(s16 *)(st + 0xa) = 0;
        }
        (**(void (**)(int, int))(*(int *)gTitleMenuControlInterface + 0x38))(3, *(s16 *)(st + 8) & 0xff);
    }
    for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
        idx = i + 0x81;
        switch (p3[idx]) {
        case 0xb:
            *(u8 *)(st + 0xf) = 7;
            break;
        case 1:
            getEnvfxAct(obj, obj, 0xc3, 0);
            break;
        case 2:
            if (lbl_803DB610 == -1) {
                getEnvfxAct(obj, obj, 0x14, 0);
            } else {
                getEnvfxAct(obj, obj, (u16)lbl_803DB610, 0);
            }
            break;
        case 3:
            *(u8 *)(st + 0x10) = 1;
            break;
        case 4:
            *(u8 *)(st + 0xf) = 4;
            *(u8 *)(st + 0x10) = 2;
            GameBit_Set(0x129, 1);
            GameBit_Set(0x1cf, 0);
            GameBit_Set(0x126, 1);
            *(s16 *)(st + 0xa) = -3;
            break;
        case 5:
            *(u8 *)(st + 0x10) = 3;
            *(s16 *)(st + 0xa) = -3;
            GameBit_Set(0x129, 1);
            break;
        case 6:
            GameBit_Set(0x1cf, 1);
            break;
        case 7:
            GameBit_Set(0x1cf, 0);
            *(s16 *)(st + 0xa) = -3;
            break;
        case 9:
            GameBit_Set(0x128, 1);
            if (lbl_803DDBD8 == 0) {
                lbl_803DDBD8 = return0_8005669C(1);
            }
            break;
        case 8:
            GameBit_Set(0x127, 1);
            break;
        case 10:
            *(s16 *)(st + 8) = 100;
            (**(void (**)(int, int, int, int, int))(*(int *)gTitleMenuControlInterface + 0x18))(3, 0x2d, 0x50, *(s16 *)(st + 8) & 0xff, 0);
            break;
        }
        p3[idx] = 0;
    }
    if (*(u8 *)(st + 0xf) != 7) {
    } else {
        if ((getButtonsHeld(0) & 0x100) != 0) {
            (**(void (**)(int))(*gObjectTriggerInterface + 0x4c))((s8)*(u8 *)(p3 + 0x57));
            *(u8 *)(st + 0xf) = 8;
            *(s16 *)(st + 2) = 0;
        } else if ((getButtonsHeld(0) & 0x200) != 0) {
            (**(void (**)(int))(*gObjectTriggerInterface + 0x4c))((s8)*(u8 *)(p3 + 0x57));
            *(u8 *)(st + 0xf) = 7;
            *(s16 *)(st + 2) = 0;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
