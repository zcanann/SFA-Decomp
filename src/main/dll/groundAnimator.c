#include "ghidra_import.h"
#include "main/dll/groundAnimator.h"

extern undefined8 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern int FUN_80017b00();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 FUN_8003b818();
extern void objRenderFn_8003b8f4(int param_1, int param_2, int param_3, int param_4, int param_5,
                        f32 scale);
extern int FUN_800632d8();
extern undefined4 FUN_80081118();
extern undefined4 FUN_8011e868();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80294d60();
extern uint FUN_80294db4();
extern uint countLeadingZeros();
extern int GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern int *ObjList_GetObjects(int *startIndex, int *objectCount);
extern f32 Vec_distance(float *posA, float *posB);
extern int Obj_GetPlayerObject(void);
extern uint playerGetStateFlag310(int obj);
extern void setAButtonIcon(int param_1);
extern void dll_115_seqFn(void);

extern undefined4* lbl_803DCA54;
extern undefined4* lbl_803DCAC0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd740;
extern f32 lbl_803DC074;
extern f32 lbl_803E37B8;
extern f32 lbl_803E37BC;
extern f32 lbl_803E37C0;
extern f32 lbl_803E37C4;
extern f32 lbl_803E4454;
extern f32 lbl_803E4458;
extern f32 lbl_803E445C;
extern f32 lbl_803E4460;
extern f32 lbl_803E446C;
extern f32 lbl_803E4470;
extern f32 lbl_803E4474;
extern f32 lbl_803E4478;
extern f32 lbl_803E447C;
extern f32 lbl_803E4480;
extern f32 lbl_803E4484;
extern f32 lbl_803E4488;
extern f32 lbl_803E448C;
extern f32 lbl_803E4490;
extern f32 lbl_803E4494;
extern f32 lbl_803E4498;

typedef void (*GroundAnimatorActivateFn)(int obj, int eventId);
typedef void (*GroundAnimatorFreeFn)(int obj);
typedef void (*GroundAnimatorRefreshFn)(int objectId, int obj, int value);
typedef int (*GroundAnimatorVisibleFn)(int obj, int visible);
typedef int (*GroundAnimatorAnimStateFn)(int obj, int state);
typedef void (*GroundAnimatorSetVisibleFn)(int state, int visible);
typedef void (*GroundAnimatorInitAnimFn)(void *obj, undefined4 state, int param_3);

/*
 * --INFO--
 *
 * Function: dll_115_update
 * EN v1.0 Address: 0x8017D0D4
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x8017D134
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dll_115_update(int obj)
{
  u8 *state;
  int mapData;
  int step;
  int eventId;

  state = *(u8 **)(obj + 0xb8);
  mapData = *(int *)(obj + 0x4c);
  if ((state[1] & 1) != 0) {
    eventId = *(s16 *)(mapData + state[0] * 2 + 0x18);
    if (eventId != -1) {
      GameBit_Set(eventId, 1);
    }
    state[1] &= 0xfe;
    state[0]++;
  }
  if ((s8)state[0] == 9) {
    (*(GroundAnimatorActivateFn *)(*lbl_803DCA54 + 0x54))(obj, *(s16 *)(mapData + 0x3c));
    (*(GroundAnimatorRefreshFn *)(*lbl_803DCA54 + 0x48))
        (*(u8 *)(mapData + 0x3a), obj, *(u8 *)(mapData + 0x3b));
  } else if ((((s8)state[0] < 8) || ((s8)state[0] >= 0xb)) &&
             (*(s16 *)(mapData + state[0] * 2 + 0x28) == -1)) {
    state[0] = 8;
  } else if ((((s8)state[0] < 8) || ((s8)state[0] >= 0xb)) &&
             ((u32)GameBit_Get(*(s16 *)(mapData + state[0] * 2 + 0x28)) != 0) &&
             ((s8)*(u8 *)(mapData + state[0] + 0x40) != -1)) {
    (*(GroundAnimatorRefreshFn *)(*lbl_803DCA54 + 0x48))
        ((s8)*(u8 *)(mapData + state[0] + 0x40), obj, -1);
  }
  {
    short *p;
    step = state[0] - 1;
    p = (short *)mapData + step;
    while (step >= 0) {
      if (p[12] == -1) break;
      if ((u32)GameBit_Get(p[12]) != 0) break;
      state[0]--;
      step--;
      p--;
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dll_115_init
 * EN v1.0 Address: 0x8017D1BC
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017D228
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dll_115_init(short *obj, int mapData)
{
  short *p;
  u8 *state;
  int step;

  state = *(u8 **)((int)obj + 0xb8);
  *obj = (s16)(*(u8 *)(mapData + 0x38) << 8);
  *(void **)((int)obj + 0xbc) = dll_115_seqFn;
  *(u16 *)((int)obj + 0xb0) |= 0x6000;
  ObjGroup_AddObject((int)obj, 0xf);
  step = 0;
  p = (short *)mapData;
  do {
    if (p[12] == -1) break;
    if ((u32)GameBit_Get(p[12]) == 0) break;
    p++;
    step++;
  } while (step < 8);
  if ((step < 8) && (*(s16 *)(mapData + 0x18 + step * 2) == -1)) {
    state[0] = 8;
  } else {
    state[0] = step;
  }
  if ((state[0] == 8) && ((*(u8 *)(mapData + 0x39) & 0x10) != 0)) {
    state[0] = 9;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dll_115_release_nop
 * EN v1.0 Address: 0x8017D1E0
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017D24C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_115_release_nop(void)
{
}

/*
 * --INFO--
 *
 * Function: dll_115_initialise_nop
 * EN v1.0 Address: 0x8017D208
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x8017D280
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_115_initialise_nop(void)
{
}

/*
 * --INFO--
 *
 * Function: wm_column_getExtraSize
 * EN v1.0 Address: 0x8017D39C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017D3F8
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int wm_column_getExtraSize(void)
{
  return 0xa;
}

/*
 * --INFO--
 *
 * Function: wm_column_func08
 * EN v1.0 Address: 0x8017D3A0
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x8017D4E8
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int wm_column_func08(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: wm_column_free
 * EN v1.0 Address: 0x8017D488
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017D5D4
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wm_column_free(int obj)
{
  ObjGroup_RemoveObject(obj, 4);
  (*(GroundAnimatorFreeFn *)(*lbl_803DCAC0 + 0x10))(obj);
}

/*
 * --INFO--
 *
 * Function: wm_column_render
 * EN v1.0 Address: 0x8017D4AC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017D5F8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void wm_column_render(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if ((*(GroundAnimatorVisibleFn *)(*lbl_803DCAC0 + 0xc))(param_1, visible) != 0) {
    objRenderFn_8003b8f4(param_1, param_2, param_3, param_4, param_5, lbl_803E37B8);
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: wm_column_hitDetect
 * EN v1.0 Address: 0x8017D4D4
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x8017D62C
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wm_column_hitDetect(void)
{
}

/*
 * --INFO--
 *
 * Function: wm_column_update
 * EN v1.0 Address: 0x8017D67C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017D7D0
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void wm_column_update(int obj)
{
  int *objects;
  int flags;
  int i;
  int count;
  int other;
  int state;
  f32 nearest[5];

  state = *(int *)(obj + 0xb8);
  nearest[0] = lbl_803E37BC;
  if ((*(GroundAnimatorAnimStateFn *)(*lbl_803DCAC0 + 8))(obj, *(int *)(obj + 0xb8)) != 0) {
    if ((*(u32 *)(obj + 0xf4) & 2) != 0) {
      objects = ObjList_GetObjects(&i, &count);
      for (; i < count; i++) {
        other = objects[i];
        if (((u32)other != (u32)obj) && (*(s16 *)(other + 0x46) == 499) &&
            (Vec_distance((float *)(obj + 0x18), (float *)(other + 0x18)) < lbl_803E37C0)) {
          other = *(s16 *)(*(int *)(objects[i] + 0x4c) + 0x1e);
          if (other != -1) {
            GameBit_Set(other, 0);
          }
        }
      }
    }
    flags = Obj_GetPlayerObject();
    ObjGroup_FindNearestObject(0x10, obj, nearest);
    flags = playerGetStateFlag310(flags);
    if (((flags & 0x4000) != 0) && (nearest[0] > lbl_803E37C4)) {
      (*(GroundAnimatorSetVisibleFn *)(*lbl_803DCAC0 + 0x24))(state, 0);
      setAButtonIcon(5);
      *(u32 *)(obj + 0xf4) |= 1;
    } else {
      (*(GroundAnimatorSetVisibleFn *)(*lbl_803DCAC0 + 0x24))(state, 1);
    }
    *(u32 *)(obj + 0xf4) &= ~2;
  } else {
    if ((*(u32 *)(obj + 0xf4) & 1) != 0) {
      objects = ObjList_GetObjects(&i, &count);
      for (; i < count; i++) {
        other = objects[i];
        if (((u32)other != (u32)obj) && (*(s16 *)(other + 0x46) == 499) &&
            (Vec_distance((float *)(obj + 0x18), (float *)(other + 0x18)) < lbl_803E37C0)) {
          int mapData = *(int *)(objects[i] + 0x4c);
          if (*(s16 *)(obj + 0x46) == (s8)*(u8 *)(mapData + 0x19) + 500) {
            if (*(s16 *)(mapData + 0x1e) != -1) {
              GameBit_Set(*(s16 *)(mapData + 0x1e), 1);
            }
          } else if (*(s16 *)(mapData + 0x1e) != -1) {
            GameBit_Set(*(s16 *)(mapData + 0x1e), 0);
          }
          *(f32 *)(obj + 0xc) = *(f32 *)(objects[i] + 0xc);
          *(f32 *)(obj + 0x10) = *(f32 *)(objects[i] + 0x10);
          *(f32 *)(obj + 0x14) = *(f32 *)(objects[i] + 0x14);
        }
      }
    }
    flags = playerGetStateFlag310(Obj_GetPlayerObject());
    if ((flags & 0x4000) != 0) {
      (*(GroundAnimatorSetVisibleFn *)(*lbl_803DCAC0 + 0x24))(state, 0);
      *(u32 *)(obj + 0xf4) |= 2;
    } else {
      (*(GroundAnimatorSetVisibleFn *)(*lbl_803DCAC0 + 0x24))(state, 1);
      *(u32 *)(obj + 0xf4) &= ~2;
    }
    *(u32 *)(obj + 0xf4) &= ~1;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: wm_column_init
 * EN v1.0 Address: 0x8017D680
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8017D8E4
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void wm_column_init(short *obj, int mapData)
{
  undefined4 state = *(undefined4 *)((int)obj + 0xb8);
  *obj = (s16)(*(u8 *)(mapData + 0x18) << 8);
  *(u16 *)((int)obj + 0xb0) |= 0x2000;
  *(undefined4 *)((int)obj + 0xf4) = 0;
  *(s8 *)((int)obj + 0xad) = (s8)(int)*(s8 *)(mapData + 0x19);
  if (*(s8 *)((int)obj + 0xad) >= *(s8 *)(*(int *)((int)obj + 0x50) + 0x55)) {
    *(u8 *)((int)obj + 0xad) = 0;
  }
  (*(GroundAnimatorInitAnimFn *)(*lbl_803DCAC0 + 4))(obj, state, 0x32);
  ObjGroup_AddObject((int)obj, 4);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: wm_column_release
 * EN v1.0 Address: 0x8017D6CC
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x8017D92C
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wm_column_release(void)
{
}

/*
 * --INFO--
 *
 * Function: wm_column_initialise
 * EN v1.0 Address: 0x8017D730
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x8017D9AC
 * EN v1.1 Size: 784b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wm_column_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: appleontree_func0B
 * EN v1.0 Address: 0x8017DAA0
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x8017DCBC
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void appleontree_func0B(int obj, float *pos)
{
  u8 *state = *(u8 **)(obj + 0xb8);

  if (state[0x3a] == 4) {
    return;
  }
  if (state[0x3a] == 5) {
    return;
  }
  if (state[0x3a] == 6) {
    return;
  }
  *(float *)(obj + 0xc) = pos[0];
  *(float *)(obj + 0x10) = pos[1];
  *(float *)(obj + 0x14) = pos[2];
}

/*
 * --INFO--
 *
 * Function: FUN_8017db40
 * EN v1.0 Address: 0x8017DB40
 * EN v1.0 Size: 792b
 * EN v1.1 Address: 0x8017DDAC
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017db40(uint param_1,int param_2)
{
  undefined2 uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f4;
  double dVar8;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (param_2 == 1) {
    uVar1 = 2;
  }
  else {
    if (param_2 < 1) {
      if (-1 < param_2) {
        uVar1 = 2;
        goto LAB_8017de10;
      }
    }
    else if (param_2 < 3) {
      uVar1 = 2;
      goto LAB_8017de10;
    }
    uVar1 = 0;
  }
LAB_8017de10:
  *(undefined2 *)(iVar4 + 0x38) = uVar1;
  *(undefined *)(iVar4 + 0x3a) = 4;
  *(float *)(iVar4 + 8) = lbl_803DC074;
  *(float *)(iVar4 + 0xc) = lbl_803DC074;
  uVar2 = FUN_80017760(0xffff8000,0x7fff);
  *(short *)(iVar4 + 0x48) = (short)uVar2;
  uVar2 = FUN_80017760(0xffff8000,0x7fff);
  *(short *)(iVar4 + 0x4a) = (short)uVar2;
  *(undefined2 *)(iVar4 + 0x4c) = 0x2000;
  dVar5 = (double)*(float *)(param_1 + 0xc);
  dVar6 = (double)*(float *)(param_1 + 0x10);
  dVar7 = (double)*(float *)(param_1 + 0x14);
  iVar3 = FUN_800632d8(dVar5,dVar6,dVar7,param_1,(float *)(iVar4 + 0x30),0);
  if (iVar3 == 0) {
    iVar4 = *(int *)(param_1 + 0xb8);
    if ((*(ushort *)(param_1 + 6) & 0x2000) == 0) {
      if (*(int *)(param_1 + 0x54) != 0) {
        ObjHits_DisableObject(param_1);
      }
      *(byte *)(iVar4 + 0x5a) = *(byte *)(iVar4 + 0x5a) | 2;
    }
    else {
      FUN_80017ac8(dVar5,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,param_1);
    }
  }
  else {
    dVar5 = (double)*(float *)(iVar4 + 0x40);
    dVar6 = FUN_80293900(-(double)((float)((double)lbl_803E4470 * dVar5) *
                                   *(float *)(iVar4 + 0x30) - lbl_803E446C));
    dVar7 = (double)(float)((double)lbl_803E4474 * dVar5);
    dVar5 = dVar7;
    if (dVar7 < (double)lbl_803E446C) {
      dVar5 = -dVar7;
    }
    if ((double)lbl_803E4478 < dVar5) {
      dVar8 = (double)(float)((double)(float)((double)lbl_803E447C - dVar6) / dVar7);
      dVar5 = (double)(float)((double)(float)((double)lbl_803E447C + dVar6) / dVar7);
      if ((double)lbl_803E446C < dVar8) {
        dVar5 = dVar8;
      }
    }
    else {
      dVar5 = (double)lbl_803E4460;
    }
    *(float *)(iVar4 + 0x50) = (float)dVar5;
    if (lbl_803E446C <= *(float *)(iVar4 + 0x28)) {
      dVar6 = (double)lbl_803E4480;
      *(float *)(iVar4 + 0x30) =
           (float)(dVar6 * (double)(lbl_803E4470 * *(float *)(iVar4 + 0x24)) +
                  (double)*(float *)(iVar4 + 0x30));
    }
    else {
      dVar6 = (double)lbl_803E4470;
      *(float *)(iVar4 + 0x30) =
           -(float)(dVar6 * (double)*(float *)(iVar4 + 0x24) - (double)*(float *)(iVar4 + 0x30));
    }
    if ((double)lbl_803E446C < (double)*(float *)(iVar4 + 0x30)) {
      *(undefined4 *)(iVar4 + 0x2c) = *(undefined4 *)(param_1 + 0x10);
      *(float *)(iVar4 + 0x34) = *(float *)(param_1 + 0x10) - *(float *)(iVar4 + 0x30);
      if (*(int *)(param_1 + 0x54) != 0) {
        ObjHits_DisableObject(param_1);
      }
      FUN_80006824(param_1,0x52);
    }
    else {
      iVar3 = *(int *)(param_1 + 0xb8);
      if ((*(ushort *)(param_1 + 6) & 0x2000) == 0) {
        if (*(int *)(param_1 + 0x54) != 0) {
          ObjHits_DisableObject(param_1);
        }
        *(byte *)(iVar3 + 0x5a) = *(byte *)(iVar3 + 0x5a) | 2;
      }
      else {
        FUN_80017ac8((double)*(float *)(iVar4 + 0x30),dVar6,dVar7,dVar5,in_f5,in_f6,in_f7,in_f8,
                     param_1);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017de58
 * EN v1.0 Address: 0x8017DE58
 * EN v1.0 Size: 672b
 * EN v1.1 Address: 0x8017E048
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017de58(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  int iVar1;
  uint uVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  double dVar4;
  undefined8 uVar5;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  iVar1 = FUN_80017a98();
  dVar4 = (double)FUN_80017710((float *)(iVar1 + 0x18),(float *)(param_9 + 0x18));
  if ((dVar4 < (double)lbl_803E4484) &&
     (dVar4 = (double)FUN_8001771c((float *)(iVar1 + 0x18),(float *)(param_9 + 0x18)),
     dVar4 < (double)lbl_803E4488)) {
    uVar2 = FUN_80017690(0x90f);
    if (uVar2 == 0) {
      uVar5 = (**(code **)(*DAT_803dd6d4 + 0x7c))(0x444,0,0);
      *(undefined2 *)(iVar3 + 0x5c) = 0xffff;
      *(undefined2 *)(iVar3 + 0x5e) = 0;
      *(float *)(iVar3 + 0x60) = lbl_803E4460;
      ObjMsg_SendToObject(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0x7000a,
                   param_9,iVar3 + 0x5c,in_r7,in_r8,in_r9,in_r10);
      FUN_80017698(0x90f,1);
      *(byte *)(iVar3 + 0x5a) = *(byte *)(iVar3 + 0x5a) | 4;
    }
    else {
      FUN_80294d60(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                   (uint)*(ushort *)(iVar3 + 0x38));
      FUN_80081118((double)lbl_803E4460,param_9,0xff,0x28);
      uVar5 = FUN_80006824(param_9,0x58);
      iVar1 = *(int *)(param_9 + 0xb8);
      if ((*(ushort *)(param_9 + 6) & 0x2000) == 0) {
        if (*(int *)(param_9 + 0x54) != 0) {
          ObjHits_DisableObject(param_9);
        }
        *(byte *)(iVar1 + 0x5a) = *(byte *)(iVar1 + 0x5a) | 2;
      }
      else {
        FUN_80017ac8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017e0f8
 * EN v1.0 Address: 0x8017E0F8
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8017E1C4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017e0f8(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x14))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017e12c
 * EN v1.0 Address: 0x8017E12C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x8017E1F4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017e12c(int param_1)
{
  if ((*(byte *)(*(int *)(param_1 + 0xb8) + 0x5a) & 2) == 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017e15c
 * EN v1.0 Address: 0x8017E15C
 * EN v1.0 Size: 612b
 * EN v1.1 Address: 0x8017E22C
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017e15c(double param_1,undefined2 *param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  fVar1 = lbl_803E446C;
  dVar5 = (double)lbl_803E446C;
  dVar6 = (double)*(float *)(param_3 + 0x40);
  if (dVar5 == dVar6) {
    uVar4 = 1;
  }
  else {
    fVar2 = *(float *)(param_3 + 0x30);
    if (dVar5 <= (double)(fVar2 - (float)((double)*(float *)(param_3 + 0x2c) - param_1))) {
      *(float *)(param_2 + 8) = (float)param_1;
      uVar4 = 1;
    }
    else {
      dVar7 = (double)*(float *)(param_3 + 0x44);
      if (dVar5 == dVar7) {
        dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                                            (double)((float)((double)lbl_803E4470 * dVar6) * fVar2
                                                    )));
        fVar1 = (float)((double)lbl_803E4474 * dVar6);
        fVar2 = fVar1;
        if (fVar1 < lbl_803E446C) {
          fVar2 = -fVar1;
        }
        fVar3 = lbl_803E4460;
        if (lbl_803E4478 < fVar2) {
          fVar2 = (float)(-dVar7 - dVar5) / fVar1;
          fVar3 = (float)(-dVar7 + dVar5) / fVar1;
          if (lbl_803E446C < fVar2) {
            fVar3 = fVar2;
          }
        }
        *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
        *(float *)(param_3 + 0x2c) = *(float *)(param_3 + 0x2c) - *(float *)(param_3 + 0x30);
        *(float *)(param_3 + 0x30) = lbl_803E446C;
        *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
        *param_2 = *(undefined2 *)(param_3 + 0x48);
        param_2[1] = *(undefined2 *)(param_3 + 0x4a);
        param_2[2] = *(undefined2 *)(param_3 + 0x4c);
        *(float *)(param_3 + 0x44) = -*(float *)(param_3 + 0x28);
        if ((*(byte *)(param_3 + 0x5a) & 8) == 0) {
          FUN_80006824((uint)param_2,0x407);
          *(byte *)(param_3 + 0x5a) = *(byte *)(param_3 + 0x5a) | 8;
        }
        uVar4 = 1;
      }
      else if ((double)lbl_803E448C <= dVar7) {
        dVar6 = (double)(float)(dVar6 + (double)*(float *)(param_3 + 0x3c));
        dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                                            (double)((float)((double)lbl_803E4470 * dVar6) * fVar2
                                                    )));
        fVar1 = (float)((double)lbl_803E4474 * dVar6);
        fVar2 = fVar1;
        if (fVar1 < lbl_803E446C) {
          fVar2 = -fVar1;
        }
        fVar3 = lbl_803E4460;
        if (lbl_803E4478 < fVar2) {
          fVar2 = (float)(-dVar7 - dVar5) / fVar1;
          fVar3 = (float)(-dVar7 + dVar5) / fVar1;
          if (lbl_803E446C < fVar2) {
            fVar3 = fVar2;
          }
        }
        *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
        *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
        *(float *)(param_3 + 0x44) = *(float *)(param_3 + 0x44) * lbl_803E4490;
        uVar4 = 0;
      }
      else {
        *(float *)(param_2 + 8) = *(float *)(param_3 + 0x2c);
        *(float *)(param_3 + 0x40) = fVar1;
        *(float *)(param_3 + 0x44) = fVar1;
        uVar4 = 1;
      }
    }
  }
  return uVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_8017e3c0
 * EN v1.0 Address: 0x8017E3C0
 * EN v1.0 Size: 624b
 * EN v1.1 Address: 0x8017E48C
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017e3c0(double param_1,undefined2 *param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  if (lbl_803E446C == *(float *)(param_3 + 0x3c)) {
    if (lbl_803E446C <
        *(float *)(param_3 + 0x30) - (float)((double)*(float *)(param_3 + 0x2c) - param_1)) {
      *(float *)(param_2 + 8) = (float)param_1;
      uVar4 = 1;
    }
    else {
      dVar6 = (double)*(float *)(param_3 + 0x40);
      dVar7 = (double)*(float *)(param_3 + 0x44);
      dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                                          (double)((float)((double)lbl_803E4470 * dVar6) *
                                                  *(float *)(param_3 + 0x30))));
      fVar1 = (float)((double)lbl_803E4474 * dVar6);
      fVar2 = fVar1;
      if (fVar1 < lbl_803E446C) {
        fVar2 = -fVar1;
      }
      fVar3 = lbl_803E4460;
      if (lbl_803E4478 < fVar2) {
        fVar2 = (float)(-dVar7 - dVar5) / fVar1;
        fVar3 = (float)(-dVar7 + dVar5) / fVar1;
        if (lbl_803E446C < fVar2) {
          fVar3 = fVar2;
        }
      }
      *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
      *(float *)(param_3 + 0x2c) = *(float *)(param_3 + 0x2c) - *(float *)(param_3 + 0x30);
      *(float *)(param_3 + 0x30) = lbl_803E446C;
      *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
      *param_2 = *(undefined2 *)(param_3 + 0x48);
      param_2[1] = *(undefined2 *)(param_3 + 0x4a);
      param_2[2] = *(undefined2 *)(param_3 + 0x4c);
      *(float *)(param_3 + 0x44) =
           lbl_803E4474 * *(float *)(param_3 + 0x40) * fVar3 + *(float *)(param_3 + 0x44);
      *(undefined4 *)(param_3 + 0x3c) = *(undefined4 *)(param_3 + 0x28);
      (**(code **)(*DAT_803dd718 + 0x10))
                ((double)*(float *)(param_2 + 6),(double)*(float *)(param_3 + 0x34),
                 (double)*(float *)(param_2 + 10),param_2);
      uVar4 = 0;
    }
  }
  else if ((float)(param_1 - (double)*(float *)(param_3 + 0x2c)) < lbl_803E446C) {
    *(float *)(param_2 + 8) = (float)param_1;
    uVar4 = 1;
  }
  else {
    dVar7 = (double)(*(float *)(param_3 + 0x40) + *(float *)(param_3 + 0x3c));
    dVar6 = (double)*(float *)(param_3 + 0x44);
    dVar5 = FUN_80293900((double)(float)(dVar6 * dVar6 -
                                        (double)((float)((double)lbl_803E4470 * dVar7) *
                                                *(float *)(param_3 + 0x30))));
    fVar1 = (float)((double)lbl_803E4474 * dVar7);
    fVar2 = fVar1;
    if (fVar1 < lbl_803E446C) {
      fVar2 = -fVar1;
    }
    fVar3 = lbl_803E4460;
    if (lbl_803E4478 < fVar2) {
      fVar2 = (float)(-dVar6 - dVar5) / fVar1;
      fVar3 = (float)(-dVar6 + dVar5) / fVar1;
      if (lbl_803E446C < fVar2) {
        fVar3 = fVar2;
      }
    }
    *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
    *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
    *(float *)(param_3 + 0x3c) = lbl_803E4494;
    *(float *)(param_3 + 0x44) = lbl_803E4498;
    uVar4 = 0;
  }
  return uVar4;
}


/* Trivial 4b 0-arg blr leaves. */
void appleontree_setScale(void) {}

/* 8b "li r3, N; blr" returners. */
int appleontree_getExtraSize(void) { return 0x64; }

/* Pattern wrappers. */
u8 appleontree_modelMtxFn(int *obj) { return *(u8*)((char*)((int**)obj)[0xb8/4] + 0x3a); }
