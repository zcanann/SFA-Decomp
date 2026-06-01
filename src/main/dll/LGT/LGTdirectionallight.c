#include "ghidra_import.h"
#include "main/dll/LGT/LGTdirectionallight.h"

extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017544();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_80017588();
extern undefined4 FUN_80017594();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175ec();
extern void* FUN_80017624();
extern undefined4 FUN_80017710();
extern int FUN_80017a98();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern void ObjGroup_RemoveObject(int obj, int group);
extern void Music_Trigger(int musicId, int param);
extern void GameBit_Set(int eventId, int value);

extern undefined4 DAT_802c2c08;
extern undefined4 DAT_802c2c0c;
extern undefined4 DAT_802c2c10;
extern undefined4 DAT_802c2c14;
extern undefined4 DAT_802c2c18;
extern undefined4 DAT_802c2c1c;
extern undefined4 DAT_802c2c20;
extern undefined4 DAT_802c2c24;
extern undefined4 DAT_802c2c28;
extern undefined4 DAT_802c2c2c;
extern undefined4 DAT_802c2c30;
extern undefined4 DAT_802c2c34;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e6ae0;
extern f64 DOUBLE_803e6ae8;
extern f32 lbl_803DC074;
extern f32 lbl_803E6AA0;
extern f32 lbl_803E6AA4;
extern f32 lbl_803E6AA8;
extern f32 lbl_803E6AB8;
extern f32 lbl_803E6ABC;
extern f32 lbl_803E6AC0;
extern f32 lbl_803E6AC4;
extern f32 lbl_803E6AC8;
extern f32 lbl_803E6ACC;
extern f32 lbl_803E6AD0;
extern f32 lbl_803E6AD4;
extern f32 lbl_803E6AD8;
extern f32 lbl_803E6AF0;
extern f32 lbl_803E6AF4;
extern f32 lbl_803E6AF8;

/*
 * --INFO--
 *
 * Function: wmworm_update
 * EN v1.0 Address: 0x801F3C7C
 * EN v1.0 Size: 524b
 * EN v1.1 Address: 0x801F42B4
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wmworm_update(short *param_1)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  short sVar6;
  double dVar7;
  
  iVar5 = *(int *)(param_1 + 0x5c);
  iVar4 = FUN_80017a98();
  if (iVar4 != 0) {
    dVar7 = (double)FUN_80017710((float *)(iVar4 + 0x18),(float *)(*(int *)(param_1 + 0x26) + 8));
    if (dVar7 <= (double)lbl_803E6AF0) {
      fVar1 = *(float *)(iVar4 + 0x18) - *(float *)(param_1 + 6);
      fVar2 = *(float *)(iVar4 + 0x1c) - *(float *)(param_1 + 8);
      fVar3 = *(float *)(iVar4 + 0x20) - *(float *)(param_1 + 10);
      if ((lbl_803E6AF4 < fVar1) || (fVar1 < lbl_803E6AF4)) {
        *(float *)(param_1 + 6) = lbl_803E6AF8 * fVar1 * lbl_803DC074 + *(float *)(param_1 + 6);
      }
      if ((lbl_803E6AF4 < fVar2) || (fVar2 < lbl_803E6AF4)) {
        *(float *)(param_1 + 8) = lbl_803E6AF8 * fVar2 * lbl_803DC074 + *(float *)(param_1 + 8);
      }
      if ((lbl_803E6AF4 < fVar3) || (fVar3 < lbl_803E6AF4)) {
        *(float *)(param_1 + 10) =
             lbl_803E6AF8 * fVar3 * lbl_803DC074 + *(float *)(param_1 + 10);
      }
      sVar6 = *(short *)(iVar5 + 8);
      if ((-1 < sVar6) || ((-1 >= sVar6 && (*(int *)(param_1 + 0x7a) < 1)))) {
        if (sVar6 == 0) {
          *(undefined2 *)(iVar5 + 0xc) = 1;
        }
        *param_1 = *param_1 + 300;
        if (*(short *)(iVar5 + 8) < 1) {
          (**(code **)(*DAT_803dd708 + 8))(param_1,(int)*(short *)(iVar5 + 4),0,4,0xffffffff,0);
        }
        else {
          for (sVar6 = 0; sVar6 < *(short *)(iVar5 + 8); sVar6 = sVar6 + 1) {
            (**(code **)(*DAT_803dd708 + 8))(param_1,(int)*(short *)(iVar5 + 4),0,4,0xffffffff,0);
          }
        }
        *(int *)(param_1 + 0x7a) = -(int)*(short *)(iVar5 + 8);
      }
      else if ((sVar6 < 0) && (0 < *(int *)(param_1 + 0x7a))) {
        *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) - (uint)DAT_803dc070;
      }
    }
    else {
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar5 + 0x10);
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar5 + 0x14);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar5 + 0x18);
    }
  }
  return;
}

#pragma scheduling off
#pragma peephole off
void wmworm_init(s16* obj, s8* p2)
{
    int* state;

    *obj = 0;
    state = *(int**)((char*)obj + 0xb8);
    *(f32*)state = (f32)((s32)*(s8*)(p2 + 0x18) << 2);
    *(s16*)((char*)state + 0x4) = *(s16*)(p2 + 0x1a);
    *(s16*)((char*)state + 0x8) = *(s16*)(p2 + 0x1c);
    *(s16*)((char*)state + 0xc) = 0;
    if (*(s16*)((char*)state + 0x8) < 1) {
        *(int*)((char*)obj + 0xf4) = (int)*(s16*)((char*)state + 0x8);
    } else {
        *(int*)((char*)obj + 0xf4) = 0;
    }
    *(f32*)((char*)state + 0x10) = *(f32*)((char*)obj + 0xc);
    *(f32*)((char*)state + 0x14) = *(f32*)((char*)obj + 0x10);
    *(f32*)((char*)state + 0x18) = *(f32*)((char*)obj + 0x14);
}
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */
void wmworm_release(void) {}
void wmworm_initialise(void) {}
void wmlevelcontrol_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int wmlevelcontrol_getExtraSize(void) { return 0x1c; }
int wmlevelcontrol_getObjectTypeId(void) { return 0x0; }

#pragma scheduling off
#pragma peephole off
void wmlevelcontrol_free(int obj)
{
    ObjGroup_RemoveObject(obj, 9);
    Music_Trigger(0xa8, 0);
    GameBit_Set(0xa7f, 0);
    GameBit_Set(0x372, 1);
    GameBit_Set(0x390, 1);
}
#pragma peephole reset
#pragma scheduling reset

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5E74;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void wmlevelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5E74); }
#pragma peephole reset
