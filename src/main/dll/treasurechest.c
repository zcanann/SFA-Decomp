#include "ghidra_import.h"
#include "main/dll/treasurechest.h"

extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017784();
extern undefined4 FUN_80017788();
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern int ObjContact_AddCallback();
extern int ObjList_FindNearestObjectByDefNo();
extern int FUN_800620e8();
extern undefined4 FUN_80081120();
extern undefined4 FUN_8016793c();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern void *memset(void *dst, int val, u32 size);
extern void ObjAnim_SetCurrentMove(int obj, int move, f32 progress, int flags);
extern void ObjHits_DisableObject(int obj);

extern undefined4 DAT_80320f38;
extern undefined4 DAT_80320fb0;
extern undefined4 DAT_803ad298;
extern undefined4 DAT_803ad2a4;
extern undefined4 DAT_803ad2a8;
extern undefined4 DAT_803ad2ac;
extern undefined4 DAT_803ad2b0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de708;
extern void *gBaddieControlInterface;
extern f64 DOUBLE_803e3cd8;
extern f32 lbl_803DC074;
extern f32 lbl_803E2FDC;
extern f32 lbl_803E2FF4;
extern f32 lbl_803E3048;
extern f32 lbl_803E3C74;
extern f32 lbl_803E3CCC;

extern void fn_801659B8(void);
extern void fn_8016558C(void);
extern void fn_801653D8(void);
extern void fn_80165188(void);
extern void fn_801650D8(void);
extern void fn_801650D0(void);
extern void *lbl_803AC650[];
extern void *lbl_803DDA88;

/*
 * --INFO--
 *
 * Function: dll_D3_update
 * EN v1.0 Address: 0x80166F2C
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x801672E4
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_D3_update(float *param_1,float *param_2,float *param_3)
{
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  local_38 = *param_2;
  local_34 = param_2[1];
  local_30 = param_2[2];
  FUN_80017784(&local_38);
  FUN_80017788(param_3,&local_38,&local_20);
  FUN_80017784(&local_20);
  FUN_80017788(&local_20,&local_38,&local_2c);
  FUN_80017784(&local_2c);
  *param_1 = -local_20;
  param_1[1] = -local_1c;
  param_1[2] = -local_18;
  param_1[4] = -local_2c;
  param_1[5] = -local_28;
  param_1[6] = -local_24;
  param_1[8] = -local_38;
  param_1[9] = -local_34;
  param_1[10] = -local_30;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016702c
 * EN v1.0 Address: 0x8016702C
 * EN v1.0 Size: 1296b
 * EN v1.1 Address: 0x801673D8
 * EN v1.1 Size: 1228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016702c(void)
{
  char cVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  int aiStack_80 [20];
  char local_30;
  undefined4 local_28;
  uint uStack_24;
  
  piVar2 = (int *)FUN_80286840();
  iVar8 = piVar2[0x13];
  iVar7 = piVar2[0x2e];
  piVar6 = *(int **)(iVar7 + 0x40c);
  iVar3 = FUN_80017a98();
  local_90 = lbl_803E3CCC;
  if ((*piVar6 == 0) && (*(undefined *)(piVar6 + 0x24) = 6, *(byte *)((int)piVar6 + 0x92) >> 4 != 0)
     ) {
    iVar4 = ObjList_FindNearestObjectByDefNo(piVar2,0x4ad,&local_90);
    *piVar6 = iVar4;
    if (iVar4 != 0) {
      (**(code **)(**(int **)(*piVar6 + 0x68) + 0x20))(*piVar6,piVar6 + 0x12,(int)piVar6 + 0x91);
      *(undefined *)(piVar6 + 0x24) = 5;
    }
    *(byte *)((int)piVar6 + 0x92) =
         ((*(byte *)((int)piVar6 + 0x92) >> 4) - 1) * '\x10' | *(byte *)((int)piVar6 + 0x92) & 0xf;
  }
  if (piVar2[0x3d] == 0) {
    if (piVar2[0x3e] == 0) {
      piVar2[3] = *(int *)(iVar8 + 8);
      piVar2[4] = *(int *)(iVar8 + 0xc);
      piVar2[5] = *(int *)(iVar8 + 0x10);
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar8 + 0x2e),piVar2,0xffffffff);
      piVar2[0x3e] = 1;
    }
    else {
      iVar8 = (**(code **)(*DAT_803dd738 + 0x30))(piVar2,iVar7,0);
      if (iVar8 != 0) {
        if (((*(byte *)((int)piVar6 + 0x92) >> 1 & 1) == 0) &&
           (iVar8 = ObjContact_AddCallback((int)piVar2,iVar3,FUN_8016793c), iVar8 != 0)) {
          *(byte *)((int)piVar6 + 0x92) = *(byte *)((int)piVar6 + 0x92) & 0xfd | 2;
        }
        FUN_8002fc3c((double)(float)piVar6[0x11],(double)lbl_803DC074);
        if (*(short *)(iVar7 + 0x402) != 1) {
          uStack_24 = (uint)*(ushort *)(iVar7 + 0x3fe);
          local_28 = 0x43300000;
          iVar8 = (**(code **)(*DAT_803dd738 + 0x48))
                            ((double)(float)((double)CONCAT44(0x43300000,uStack_24) -
                                            DOUBLE_803e3cd8),piVar2,iVar7,0x8000);
          if (iVar8 != 0) {
            (**(code **)(*DAT_803dd738 + 0x28))
                      (piVar2,iVar7,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),0,0,1,0,0xffffffff)
            ;
            *(int *)(iVar7 + 0x2d0) = iVar8;
            *(undefined *)(iVar7 + 0x349) = 0;
            *(undefined2 *)(iVar7 + 0x402) = 1;
            *(undefined *)(iVar7 + 0x405) = 2;
          }
          if ((*(int *)(iVar7 + 0x2d0) != 0) && (*(short *)(iVar7 + 0x402) == 2)) {
            uStack_24 = (uint)*(ushort *)(iVar7 + 0x3fe);
            local_28 = 0x43300000;
            if (*(float *)(iVar7 + 0x2c0) <=
                (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e3cd8)) {
              *(undefined2 *)(iVar7 + 0x402) = 1;
            }
          }
        }
        iVar8 = *(int *)(iVar7 + 0x2d0);
        if (iVar8 != 0) {
          local_8c = *(float *)(iVar8 + 0x18) - (float)piVar2[6];
          local_88 = *(float *)(iVar8 + 0x1c) - (float)piVar2[7];
          local_84 = *(float *)(iVar8 + 0x20) - (float)piVar2[8];
          dVar9 = FUN_80293900((double)(local_84 * local_84 +
                                       local_8c * local_8c + local_88 * local_88));
          *(float *)(iVar7 + 0x2c0) = (float)dVar9;
        }
        (**(code **)(*DAT_803dd738 + 0x54))
                  (piVar2,iVar7,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),0,0,0,0);
        cVar1 = *(char *)(iVar7 + 0x354);
        if (('\0' < cVar1) &&
           ((**(code **)(*DAT_803dd738 + 0x50))
                      (piVar2,iVar7,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),&DAT_80320f38,
                       &DAT_80320fb0,0,&DAT_803ad298), *(char *)(iVar7 + 0x354) < cVar1)) {
          (**(code **)(**(int **)(*(int *)(iVar3 + 200) + 0x68) + 0x50))();
          DAT_803ad2a4 = piVar2[3];
          DAT_803ad2a8 = piVar2[4];
          DAT_803ad2ac = piVar2[5];
          FUN_80081120(piVar2,&DAT_803ad298,1,(int *)0x0);
        }
        (**(code **)(*DAT_803dd738 + 0x2c))((double)lbl_803E3C74,piVar2,iVar7,0xffffffff);
        *(int *)(iVar7 + 0x3e0) = piVar2[0x30];
        piVar2[0x30] = 0;
        (**(code **)(*DAT_803dd70c + 8))
                  ((double)lbl_803DC074,(double)lbl_803DC074,piVar2,iVar7,&DAT_803ad2b0,
                   &DAT_803de708);
        piVar2[0x30] = *(int *)(iVar7 + 0x3e0);
        if (((*(byte *)((int)piVar6 + 0x92) & 1) == 0) && (*(char *)(piVar6 + 0x24) == '\x06')) {
          iVar3 = FUN_800620e8(piVar2 + 0x20,piVar2 + 3,(float *)0x0,aiStack_80,piVar2,0xffffff84,
                               0xffffffff,0xff,0);
          if ((iVar3 != 0) && (local_30 == '\r')) {
            *(byte *)((int)piVar6 + 0x92) = *(byte *)((int)piVar6 + 0x92) & 0xfe | 1;
            uVar5 = randomGetRange(10,0xf);
            *(short *)((int)piVar6 + 0x8e) = (short)uVar5 * 0x3c;
          }
        }
      }
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: dll_D3_init
 * EN v1.0 Address: 0x801673F8
 * EN v1.0 Size: 344b
 */
#pragma scheduling off
#pragma peephole off
void dll_D3_init(int obj, int def, int flag)
{
  int state;
  int extra;
  u8 setupFlags;
  f32 zero;

  state = *(int *)(obj + 0xb8);
  setupFlags = 6;
  if (flag != 0) {
    setupFlags |= 1;
  }
  ((void (*)(int, int, int, int, int, int, int, f32))((void **)*(int *)gBaddieControlInterface)[22])
      (obj, def, state, 5, 1, 0x108, setupFlags, lbl_803E3048);
  *(int *)(obj + 0xbc) = 0;

  extra = *(int *)(state + 0x40c);
  memset((void *)extra, 0, 0x94);
  *(u8 *)(extra + 0x90) = 5;
  *(u8 *)(extra + 0x92) = (*(u8 *)(extra + 0x92) & 0xf) | 0x30;
  *(f32 *)(extra + 0x7c) = lbl_803E2FDC;
  *(f32 *)(extra + 0x80) = lbl_803E2FF4;
  *(f32 *)(extra + 0x84) = lbl_803E2FDC;
  *(f32 *)(extra + 0x88) = -*(f32 *)(obj + 0x10);
  *(f32 *)(extra + 0x70) = *(f32 *)(obj + 0xc);
  *(f32 *)(extra + 0x74) = *(f32 *)(obj + 0x10);
  *(f32 *)(extra + 0x78) = *(f32 *)(obj + 0x14);

  ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
  *(s16 *)(state + 0x274) = *(u8 *)(def + 0x2b) != 0;
  *(s16 *)(state + 0x270) = 0;
  *(s16 *)(state + 0x402) = 0;
  *(u8 *)(state + 0x405) = 0;
  *(u8 *)(state + 0x25f) = 0;
  ObjHits_DisableObject(obj);

  zero = lbl_803E2FF4;
  *(f32 *)(extra + 4) = zero;
  *(f32 *)(extra + 0x18) = zero;
  *(f32 *)(extra + 0x2c) = zero;
  *(f32 *)(extra + 0x40) = zero;
}
#pragma peephole reset
#pragma scheduling reset

void dll_D3_initialise(void)
{
  void **table;

  table = lbl_803AC650;
  table[0] = fn_801659B8;
  table[1] = fn_8016558C;
  table[2] = fn_801653D8;
  table[3] = fn_80165188;
  table[4] = fn_801650D8;
  lbl_803DDA88 = fn_801650D0;
}


/* Trivial 4b 0-arg blr leaves. */
void dll_D3_release_nop(void) {}
void skeetlawall_free(void) {}
void skeetlawall_hitDetect(void) {}
void skeetlawall_update(void) {}
void skeetlawall_release(void) {}
void skeetlawall_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int skeetlawall_getExtraSize(void) { return 0x7; }
int skeetlawall_getObjectTypeId(void) { return 0x0; }

extern void skeetlawall_setScale(int *obj, f32 *outVec, u8 *outByte);

extern f32 lbl_803E3058;
extern void objRenderFn_8003b8f4(f32);
#pragma scheduling off
#pragma peephole off
void skeetlawall_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
    if (visible != 0) {
        if (*(int *)((char *)obj + 0xF4) == 0) {
            ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3058);
        }
    }
}

void skeetlawall_init(int obj, u8 *def) {
    u8 *state = *(u8 **)((char *)obj + 0xB8);
    state[0] = def[0x18];
    state[1] = def[0x19];
    state[2] = def[0x1A];
    state[3] = def[0x1B];
    state[4] = def[0x1C];
    state[5] = def[0x1D];
    state[6] = def[0x1E];
}
#pragma peephole reset
#pragma scheduling reset

ObjectDescriptor11WithPadding gSkeetlaWallObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)skeetlawall_initialise,
        (ObjectDescriptorCallback)skeetlawall_release,
        0,
        (ObjectDescriptorCallback)skeetlawall_init,
        (ObjectDescriptorCallback)skeetlawall_update,
        (ObjectDescriptorCallback)skeetlawall_hitDetect,
        (ObjectDescriptorCallback)skeetlawall_render,
        (ObjectDescriptorCallback)skeetlawall_free,
        (ObjectDescriptorCallback)skeetlawall_getObjectTypeId,
        skeetlawall_getExtraSize,
        (ObjectDescriptorCallback)skeetlawall_setScale,
    },
    0,
};

extern undefined4 *gPlayerInterface;
#pragma scheduling off
#pragma peephole off
void fn_80167550(int *obj) {
    int *state = *(int **)((char *)obj + 0xb8);
    ((void (*)(int *, int *, int))((void **)*gPlayerInterface)[5])(obj, state, 2);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void skeetlawall_setScale(int *obj, f32 *outVec, u8 *outByte) {
    u8 *state = *(u8 **)((char *)obj + 0xb8);
    outVec[0] = *(f32 *)((char *)obj + 0x18) - (f32)(u32)state[0];
    outVec[1] = *(f32 *)((char *)obj + 0x18) + (f32)(u32)state[1];
    outVec[2] = *(f32 *)((char *)obj + 0x20) + (f32)(u32)state[2];
    outVec[3] = *(f32 *)((char *)obj + 0x20) - (f32)(u32)state[3];
    outVec[4] = *(f32 *)((char *)obj + 0x1c) + (f32)(u32)state[4];
    outVec[5] = *(f32 *)((char *)obj + 0x1c) - (f32)(u32)state[5];
    outByte[0] = state[6];
}
#pragma peephole reset
#pragma scheduling reset
