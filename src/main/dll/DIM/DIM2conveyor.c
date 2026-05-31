#include "ghidra_import.h"
#include "main/dll/DIM/DIM2conveyor.h"

#define SFXbaddie_eggsnatch_sniff1 705

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b14();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern int ObjHits_GetPriorityHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 FUN_8003b818();
extern int FUN_800480a0();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern uint FUN_80060058();
extern int FUN_800600c4();
extern int FUN_800600e4();
extern undefined4 FUN_801b2550();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();
extern uint countLeadingZeros();

extern undefined4* DAT_803dd6d4;
extern void* DAT_803de7d0;
extern f32 lbl_803E5550;

/*
 * --INFO--
 *
 * Function: dimlavasmash_init
 * EN v1.0 Address: 0x801B3658
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B367C
 * EN v1.1 Size: 636b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int fn_801B3458(int obj, int p2, char *r5);
extern void fn_801B3344(int *block, int mode, int v);
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern int *mapGetBlock(int idx);
#pragma scheduling off
#pragma peephole off
void dimlavasmash_init(s16 *obj, s8 *def) {
    int *block;
    char *inner;
    obj[0] = (s16)((s32)def[0x18] << 8);
    *(int *)((char *)obj + 0xbc) = (int)&fn_801B3458;
    inner = *(char **)((char *)obj + 0xb8);
    *(u8 *)(inner + 1) = (u8)*(s16 *)(def + 0x1a);
    *(s8 *)(inner + 0) = (s8)*(s16 *)(def + 0x1c);
    *(u8 *)(inner + 2) = (u8)GameBit_Get(*(s16 *)(def + 0x1e));
    if (*(u8 *)(inner + 2) == 1) {
        block = mapGetBlock(objPosToMapBlockIdx(*(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x10), *(f32 *)((char *)obj + 0x14)));
        if (block != NULL) {
            fn_801B3344(block, 1, *(u8 *)(inner + 1));
            fn_801B3344(block, 0, *(u8 *)(inner + 1) + 1);
        }
    }
    *(s8 *)((char *)obj + 0xad) = def[0x19];
    {
        s16 *p = *(s16 **)((char *)obj + 0x54);
        p[0x30] = (s16)(p[0x30] & ~1);
    }
    *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x2000);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801b365c
 * EN v1.0 Address: 0x801B365C
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x801B38F8
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b365c(undefined4 param_1,undefined4 param_2,uint param_3)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  for (iVar5 = 0; iVar5 < (int)(uint)*(ushort *)(iVar1 + 0x9a); iVar5 = iVar5 + 1) {
    iVar3 = FUN_800600c4(iVar1,iVar5);
    uVar2 = FUN_80060058(iVar3);
    if (param_3 == uVar2) {
      if ((int)uVar6 == 0) {
        *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) | 2;
        *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) | 1;
      }
      else {
        *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) & 0xfffffffd;
        *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) & ~1;
      }
    }
  }
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(iVar1 + 0xa2); iVar5 = iVar5 + 1) {
    iVar3 = FUN_800600e4(iVar1,iVar5);
    iVar4 = FUN_800480a0(iVar3,0);
    if (param_3 == *(byte *)(iVar4 + 5)) {
      if ((int)uVar6 == 0) {
        *(uint *)(iVar3 + 0x3c) = *(uint *)(iVar3 + 0x3c) | 2;
      }
      else {
        *(uint *)(iVar3 + 0x3c) = *(uint *)(iVar3 + 0x3c) & 0xfffffffd;
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b376c
 * EN v1.0 Address: 0x801B376C
 * EN v1.0 Size: 700b
 * EN v1.1 Address: 0x801B3A0C
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_801b376c(uint param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int local_18 [4];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar3 + 2) == '\0') {
    uVar1 = GameBit_Get((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x20));
    if (uVar1 != 0) {
      *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) | 1;
      iVar2 = ObjHits_GetPriorityHit(param_1,local_18,(int *)0x0,(uint *)0x0);
      if ((iVar2 != 0) && (*(short *)(local_18[0] + 0x46) == 0x18d)) {
        *(undefined *)(iVar3 + 2) = 2;
        FUN_80006824(param_1,SFXbaddie_eggsnatch_sniff1);
        iVar2 = FUN_8005b398((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
        iVar2 = FUN_8005af70(iVar2);
        if (iVar2 != 0) {
          FUN_801b365c(iVar2,1,(uint)*(byte *)(iVar3 + 1));
          FUN_801b365c(iVar2,0,*(byte *)(iVar3 + 1) + 1);
        }
      }
    }
  }
  else if (*(char *)(param_3 + 0x80) == '\x01') {
    GameBit_Set((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e),1);
    *(undefined *)(iVar3 + 2) = 1;
  }
  uVar1 = countLeadingZeros((uint)*(byte *)(iVar3 + 2));
  return uVar1 >> 5;
}

/*
 * --INFO--
 *
 * Function: FUN_801b3a28
 * EN v1.0 Address: 0x801B3A28
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801B3B38
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3a28(int param_1,int p1,int p2,int p3,int p4,s8 visible)
{
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 2) == '\x02') && (visible != 0)) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dimbridgecogmai_release
 * EN v1.0 Address: 0x801B3A60
 * EN v1.0 Size: 144b
 * EN v1.1 Address: 0x801B3B7C
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_dropped_dimbridgecogmai_release(int param_1)
{
  int iVar1;
  
  if ((*(char **)(param_1 + 0xb8))[2] == '\x01') {
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & ~1;
  }
  else if (*(int *)(param_1 + 0xf4) == 0) {
    iVar1 = (int)**(char **)(param_1 + 0xb8);
    if (iVar1 != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(iVar1,param_1,0xffffffff);
    }
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b3af0
 * EN v1.0 Address: 0x801B3AF0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B3C0C
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3af0(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801b3af4
 * EN v1.0 Address: 0x801B3AF4
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x801B3D1C
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801b3af4(int param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x4c);
  *(undefined *)(param_3 + 0x56) = 0;
  if (((*(byte *)(iVar1 + 0x1d) & 2) != 0) && (*(char *)(param_3 + 0x80) == '\x01')) {
    GameBit_Set((int)*(short *)(iVar1 + 0x18),1);
    *(undefined *)(param_3 + 0x80) = 0;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: dimdismountpoint_getObjectTypeId
 * EN v1.0 Address: 0x801B3B58
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801B3D94
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_dropped_dimdismountpoint_getObjectTypeId(int param_1)
{
  ObjGroup_RemoveObject(param_1,0xf);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b3b7c
 * EN v1.0 Address: 0x801B3B7C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B3DB8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3b7c(int param_1,int p1,int p2,int p3,int p4,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b3ba4
 * EN v1.0 Address: 0x801B3BA4
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x801B3DEC
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3ba4(int param_1)
{
  short sVar1;
  uint uVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 unaff_r29;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  uVar2 = GameBit_Get((int)*(short *)(iVar5 + 0x1a));
  if (uVar2 != 0) {
    if (*(char *)(iVar5 + 0x1e) != -1) {
      sVar1 = *(short *)(iVar5 + 0x1a);
      if (sVar1 == 0x1e3) {
        uVar2 = GameBit_Get(0x182);
        uVar3 = GameBit_Get(0x183);
        uVar2 = uVar2 & 0xff | (uVar3 & 0x7f) << 1;
        uVar3 = GameBit_Get(0x184);
        uVar3 = uVar2 | (uVar3 & 0x3f) << 2;
        if (uVar3 == 7) {
          *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
          unaff_r29 = 0xffffffff;
          uVar4 = 2;
        }
        else {
          GameBit_Set((int)*(short *)(iVar5 + 0x1a),0);
          unaff_r29 = 0x1d;
          if (((uVar3 & 4) != 0) && (unaff_r29 = 0x1f, (uVar2 & 2) != 0)) {
            unaff_r29 = 0x3f;
          }
          uVar4 = 1;
        }
      }
      else if ((sVar1 < 0x1e3) && (sVar1 == 0x17a)) {
        uVar2 = GameBit_Get(0x181);
        if (uVar2 == 0) {
          GameBit_Set((int)*(short *)(iVar5 + 0x1a),0);
          unaff_r29 = 0x1f;
          uVar4 = 1;
        }
        else {
          *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
          unaff_r29 = 0xffffffff;
          uVar4 = 0;
        }
      }
      else {
        uVar4 = 0;
      }
      (**(code **)(*DAT_803dd6d4 + 0x48))(uVar4,param_1,unaff_r29);
    }
    if ((*(byte *)(iVar5 + 0x1d) & 2) == 0) {
      GameBit_Set((int)*(short *)(iVar5 + 0x18),1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b3d1c
 * EN v1.0 Address: 0x801B3D1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B3F7C
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b3d1c(short *param_1,int param_2)
{
}


/* Trivial 4b 0-arg blr leaves. */
void dimlavasmash_release(void) {}
void dimlavasmash_initialise(void) {}
void dimbridgecogmai_hitDetect(void) {}
void dimbridgecogmai_initialise(void) {}
void dimdismountpoint_hitDetect(void) {}
void dimdismountpoint_release(void) {}
void dimdismountpoint_initialise(void) {}

extern int* ObjGroup_FindNearestObject(int group, int *obj, f32 *dist);
extern void objRenderFn_80041018(int obj);
extern f32 lbl_803E4910;

#pragma scheduling off
#pragma peephole off
void dimdismountpoint_update(int *obj) {
    extern uint GameBit_Get(int eventId);
    int *nearest;
    f32 d;

    d = lbl_803E4910;
    nearest = ObjGroup_FindNearestObject(0xa, obj, &d);
    *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) & ~8);
    if (GameBit_Get(0x3e3) != 0) {
        *(u8*)((char*)obj + 0xe4) = 1;
        *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) & ~0x10);
    } else {
        *(u8*)((char*)obj + 0xe4) = 0;
        if (nearest != NULL &&
            ((int (*)(int*, int*))(*(int *)(*(int *)*(int **)((char*)nearest + 0x68) + 0x20)))(nearest, obj) != 0) {
            *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) & ~0x10);
        } else {
            *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) | 0x10);
        }
    }
    if ((*(u32*)(*(int*)((char*)obj + 0x50) + 0x44) & 1) != 0 && *(void **)((char*)obj + 0x74) != NULL) {
        objRenderFn_80041018((int)obj);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E4908;
extern f32 lbl_803E4914;
extern f32 lbl_803E4918;
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern uint GameBit_Get(int eventId);
extern unsigned long GameBit_Set(int eventId, int value);

#pragma peephole off
#pragma scheduling off
void dimdismountpoint_init(u8* obj, u8* params) {
    f32 *sub;

    ObjGroup_AddObject(obj, 0x13);
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    sub = *(f32**)(obj + 0xb8);
    sub[0] = fn_80293E80(lbl_803E4914 * (f32)(s32)*(s16*)obj / lbl_803E4918);
    sub[1] = lbl_803E4908;
    sub[2] = sin(lbl_803E4914 * (f32)(s32)*(s16*)obj / lbl_803E4918);
    sub[3] = -(sub[0] * *(f32*)(obj + 0xc) + sub[1] * *(f32*)(obj + 0x10) + sub[2] * *(f32*)(obj + 0x14));
    *(int*)(obj + 0xf8) = 1;
}
#pragma scheduling reset
#pragma peephole reset

/* 8b "li r3, N; blr" returners. */
int dimbridgecogmai_getExtraSize(void) { return 0x1; }
int dimbridgecogmai_getObjectTypeId(void) { return 0x0; }
int dimdismountpoint_getExtraSize(void) { return 0x10; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4900;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void dimbridgecogmai_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4900); }
#pragma peephole reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
#pragma peephole off
void dimbridgecogmai_free(int x) { ObjGroup_RemoveObject(x, 0xf); }
void dimdismountpoint_free(int x) { ObjGroup_RemoveObject(x, 0x13); }
#pragma peephole reset
#pragma scheduling reset

void dimbridgecogmai_release(void) {}
int dimdismountpoint_getObjectTypeId(void) { return 0; }

extern int fn_801B3768(int obj, int p2, char *r5);
#pragma scheduling off
#pragma peephole off
void dimbridgecogmai_init(int *obj, int *def) {
    *(u8 *)*(int **)((char *)obj + 0xb8) = 100;
    *(s16 *)obj = (s16)((u32)*(u8 *)((char *)def + 0x1c) << 8);
    *(void **)((char *)obj + 0xbc) = (void *)fn_801B3768;
    ObjGroup_AddObject(obj, 15);
    if ((u8)GameBit_Get(*(s16 *)((char *)def + 0x18)) != 0) {
        *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x8000);
    }
    *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x6000);
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E490C;
extern void objRenderFn_80041018(int obj);
#pragma scheduling off
#pragma peephole off
void dimdismountpoint_render(int obj, int p1, int p2, int p3, int p4, s8 visible) {
    if (visible == 0 || *(int *)(obj + 0xf8) != 0) {
        if (*(int *)(obj + 0xf8) != 0) {
            objRenderFn_80041018(obj);
        }
    } else {
        objRenderFn_8003b8f4(lbl_803E490C);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_801B3768(int obj, int p2, char *r5) {
    char *param = *(char **)(obj + 0x4c);
    r5[0x56] = 0;
    if ((*(u8 *)(param + 0x1d) & 0x2) != 0 && *(u8 *)(r5 + 0x80) == 1) {
        GameBit_Set(*(s16 *)(param + 0x18), 1);
        *(u8 *)(r5 + 0x80) = 0;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern int *gObjectTriggerInterface;
#pragma scheduling off
#pragma peephole off

void dimbridgecogmai_update(int *obj) {
    u8 *def;
    int code;
    u8 bits;
    int callArg;

    def = *(u8**)((char*)obj + 0x4c);
    if (GameBit_Get(*(s16*)(def + 0x1a)) != 0) {
        if ((s8)def[0x1e] != -1) {
            switch (*(s16*)(def + 0x1a)) {
            case 0x17a:
                if (GameBit_Get(0x181) != 0) {
                    *(u16*)((char*)obj + 0xb0) = (u16)(*(u16*)((char*)obj + 0xb0) | 0x8000);
                    code = -1;
                    callArg = 0;
                } else {
                    GameBit_Set(*(s16*)(def + 0x1a), 0);
                    code = 0x1f;
                    callArg = 1;
                }
                break;
            case 0x1e3:
                bits = (u8)GameBit_Get(0x182);
                bits = (u8)(bits | (GameBit_Get(0x183) << 1));
                bits = (u8)(bits | (GameBit_Get(0x184) << 2));
                if (bits == 7) {
                    *(u16*)((char*)obj + 0xb0) = (u16)(*(u16*)((char*)obj + 0xb0) | 0x8000);
                    code = -1;
                    callArg = 2;
                } else {
                    GameBit_Set(*(s16*)(def + 0x1a), 0);
                    code = 0x1d;
                    if ((bits & 4) != 0) {
                        code = code | 2;
                        if ((bits & 2) != 0) {
                            code = code | 0x20;
                        }
                    }
                    callArg = 1;
                }
                break;
            default:
                callArg = 0;
                break;
            }
            ((void(*)(int, int*, int))((void**)*gObjectTriggerInterface)[18])(callArg, obj, code);
        }
        if ((def[0x1d] & 2) == 0) {
            GameBit_Set(*(s16*)(def + 0x18), 1);
        }
    }
}

void dimdismountpoint_func11(int obj, int flag) {
    (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))((flag ^ 1) + 2, obj, -1);
}

extern int Obj_GetPlayerObject(void);
extern f32 lbl_803E4908;
int dimdismountpoint_setScale(int obj) {
    int *player = (int *)Obj_GetPlayerObject();
    int *state = *(int **)((char *)obj + 0xB8);
    f32 result;
    int side;

    result = *(f32 *)((char *)state + 0xC) +
             (*(f32 *)((char *)state + 8) * *(f32 *)((char *)player + 0x14) +
              (*(f32 *)((char *)state + 0) * *(f32 *)((char *)player + 0xC) +
               *(f32 *)((char *)state + 4) * *(f32 *)((char *)player + 0x10)));

    if (result >= lbl_803E4908) {
        side = 0;
    } else {
        side = 1;
    }
    (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(side, obj, -1);
    return side;
}
#pragma peephole reset
#pragma scheduling reset
