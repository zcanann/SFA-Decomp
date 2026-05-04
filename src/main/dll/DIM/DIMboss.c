#include "ghidra_import.h"
#include "main/dll/DIM/DIMboss.h"

extern undefined4 fn_8000A518();
extern undefined4 FUN_800069b8();
extern undefined4 FUN_80006b0c();
extern undefined8 fn_80014F40();
extern undefined4 fn_80015624();
extern undefined4 fn_80019C24();
extern undefined4 FUN_80017620();
extern uint GameBit_Get();
extern undefined8 GameBit_Set();
extern undefined4 fn_800202CC();
extern undefined8 fn_800234EC();
extern undefined4 fn_8002843C();
extern int fn_8002B588();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_8003b818();
extern undefined8 FUN_80040da0();
extern undefined8 fn_80043034();
extern undefined8 fn_80043074();
extern uint fn_800430AC();
extern undefined4 fn_8004350C();
extern undefined4 fn_80043560();
extern undefined8 fn_800437BC();
extern undefined8 fn_800443CC();
extern undefined4 fn_800481B0();
extern undefined8 fn_800481D4();
extern undefined4 fn_8004A43C();
extern undefined8 fn_8004A868();
extern undefined4 FUN_80053b3c();
extern undefined4 FUN_8005fe14();
extern undefined8 FUN_800723a0();
extern undefined8 fn_80114BB0();
extern undefined4 FUN_801149bc();
extern undefined4 FUN_801bb848();
extern undefined4 FUN_801bbed0();
extern undefined8 FUN_801bcc94();
extern undefined4 FUN_80286880();

extern undefined4 fn_8000FACC();
extern undefined4 fn_80013E2C();
extern undefined4 fn_8001F384();
extern undefined4 Obj_FreeObject();
extern undefined4 fn_8002B9EC();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 fn_8003B8F4();
extern undefined4 fn_80055000();
extern undefined4 fn_800604B4();
extern undefined4 fn_80114DEC();
extern undefined4 fn_801BB598();

extern undefined4 DAT_803adc60;
extern undefined4 DAT_803adc78;
extern undefined4 DAT_803dd5d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd70c;
extern undefined4* lbl_803DCAAC;
extern undefined4* lbl_803DCAB4;
extern undefined4* DAT_803dd738;
extern undefined4 lbl_803DDB80;
extern undefined4 DAT_803de808;
extern f32 lbl_803E58DC;
extern f32 lbl_803E5908;
extern undefined4 lbl_803AC9DC[];
extern undefined4 lbl_803AD018[];
extern int lbl_803DCA8C;
extern undefined4* lbl_803DCAB8;
extern undefined4 lbl_803DDB88;
extern f32 lbl_803E4C44;

typedef struct DIMbossEffect {
  u8 pad00[0x4C];
  u8 visible;
  u8 pad4D[0x2F8 - 0x4D];
  u8 active;
} DIMbossEffect;

typedef struct DIMbossRuntime {
  u8 pad000[0x274];
  s16 scale;
  u8 pad276[0x402 - 0x276];
  s16 phase;
  u8 pad404[0x40C - 0x404];
  DIMbossEffect **effect;
} DIMbossRuntime;

typedef struct DIMbossObject {
  u8 pad00[0xAF];
  u8 objectFlags;
  u8 padB0[0xB8 - 0xB0];
  DIMbossRuntime *runtime;
  u8 padBC[0xC8 - 0xBC];
  void *childObject;
  u8 padCC[0xF4 - 0xCC];
  int renderPause;
} DIMbossObject;

/*
 * --INFO--
 *
 * Function: DIMboss_updateState
 * EN v1.0 Address: 0x801BCB34
 * EN v1.0 Size: 3404b
 * EN v1.1 Address: 0x801BD0E8
 * EN v1.1 Size: 1836b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMboss_updateState(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                         undefined8 param_5,undefined8 param_6,undefined8 param_7,
                         undefined8 param_8,undefined4 param_9,undefined4 param_10,int param_11,
                         undefined4 param_12,undefined4 param_13,int param_14,int param_15,
                         undefined4 param_16)
{
  byte bVar1;
  bool bVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined4 *puVar13;
  undefined8 uVar14;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  
  puVar3 = (undefined4 *)fn_8002B9EC();
  puVar13 = (undefined4 *)puVar3[0x2e];
  iVar12 = puVar3[0x13];
  FUN_80017a98();
  iVar11 = puVar13[0x103];
  *(undefined2 *)((int)puVar13 + 0x402) = 0;
  uVar14 = (**(code **)(*lbl_803DCAAC + 0x50))(0x1c,5,0);
  if (puVar3[0x3d] == 0) {
    puVar7 = lbl_803AC9DC;
    puVar8 = (undefined4 *)0x1;
    puVar9 = (undefined4 *)0x1;
    uVar14 = fn_80114BB0(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,
                         param_11,(float *)lbl_803AC9DC,1,1,param_14,param_15,param_16);
    for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar10 = iVar10 + 1) {
      switch(*(undefined *)(param_11 + iVar10 + 0x81)) {
      case 1:
        (**(code **)(*lbl_803DCAB4 + 0xc))(puVar3,0x800,0,100,0);
        (**(code **)(*lbl_803DCAB4 + 0xc))(puVar3,0x800,0,100,0);
        (**(code **)(*lbl_803DCAB4 + 0xc))(puVar3,0x7ff,0,100,0);
        puVar7 = (undefined4 *)0x0;
        puVar8 = (undefined4 *)0x64;
        puVar9 = (undefined4 *)0x0;
        param_14 = *lbl_803DCAB4;
        (**(code **)(param_14 + 0xc))(puVar3,0x7ff);
        iVar4 = fn_8002B588((int)puVar3);
        uVar14 = fn_8002843C(iVar4);
        fn_8000A518((int *)0x27,1);
        break;
      case 2:
        *(undefined2 *)((int)puVar13 + 0x402) = 1;
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) | 0x80;
        puVar7 = (undefined4 *)0x0;
        puVar8 = (undefined4 *)*lbl_803DCAAC;
        uVar14 = (*(code *)puVar8[0x14])(0x1c,0);
        break;
      case 6:
        lbl_803DDB80 = lbl_803DDB80 | 0x40004;
        break;
      case 7:
        lbl_803DDB80 = lbl_803DDB80 | 2;
        break;
      case 8:
        iVar11 = puVar13[0x103];
        *(byte *)(iVar11 + 0xb6) = *(byte *)(iVar11 + 0xb6) & 0x7f | 0x80;
        fn_8000A518((int *)0xee,0);
        break;
      case 9:
        lbl_803DDB80 = lbl_803DDB80 | 0x40;
        break;
      case 10:
        lbl_803DDB80 = lbl_803DDB80 & 0xffffffbf;
        break;
      case 0xc:
        lbl_803DDB80 = lbl_803DDB80 & 0xffffff7f;
        break;
      case 0xd:
        lbl_803DDB80 = lbl_803DDB80 | 0x100;
        break;
      case 0xe:
        lbl_803DDB80 = lbl_803DDB80 & 0xfffffeff;
        break;
      case 0xf:
        lbl_803DDB80 = lbl_803DDB80 | 0x2001;
        break;
      case 0x10:
        lbl_803DDB80 = lbl_803DDB80 | 0x8021;
        break;
      case 0x11:
        *(undefined4 *)(iVar11 + 0xb0) = 10;
        GameBit_Set(0x123,1);
        uVar14 = GameBit_Set(0x17,1);
        fn_8000A518((int *)0x27,0);
        fn_8000A518((int *)0x36,0);
        fn_8000A518((int *)0xee,0);
        break;
      case 0x12:
        puVar8 = (undefined4 *)0x3c;
        puVar9 = (undefined4 *)*DAT_803dd6d4;
        puVar7 = puVar3;
        uVar14 = (*(code *)puVar9[0x14])(0x49,4);
        break;
      case 0x13:
        puVar7 = (undefined4 *)0x1;
        puVar8 = (undefined4 *)*lbl_803DCAAC;
        uVar14 = (*(code *)puVar8[0x14])(0x1c,2);
        break;
      case 0x14:
        puVar7 = (undefined4 *)0x0;
        puVar8 = (undefined4 *)*lbl_803DCAAC;
        uVar14 = (*(code *)puVar8[0x14])(0x1c,2);
        break;
      case 0x15:
        FUN_800723a0();
        uVar14 = fn_80043074();
        puVar7 = (undefined4 *)0x1;
        fn_8004350C(0,0,1);
        fn_800481B0(0x1c);
        uVar14 = fn_800437BC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        fn_800481B0(0x1b);
        fn_800437BC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        uVar14 = FUN_80040da0();
        break;
      case 0x16:
        uVar14 = FUN_800723a0();
        uVar5 = fn_800481B0(0x13);
        fn_80043560(uVar5,0);
        fn_800481B0(0x13);
        uVar14 = fn_800443CC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        fn_800481B0(0x13);
        uVar14 = fn_800443CC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        fn_800481B0(0x13);
        uVar14 = fn_800443CC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        fn_800481B0(0x13);
        uVar14 = fn_800443CC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        fn_800481B0(0x13);
        uVar14 = fn_800443CC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        fn_800481B0(0x13);
        uVar14 = fn_800443CC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        fn_800481B0(0x13);
        uVar14 = fn_800443CC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        fn_800481B0(0x13);
        uVar14 = fn_800443CC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        fn_800481B0(0x13);
        uVar14 = fn_800443CC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        fn_800481B0(0x13);
        uVar14 = fn_800443CC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        fn_800481B0(0x13);
        uVar14 = fn_800443CC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        fn_800481B0(0x13);
        uVar14 = fn_800443CC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        fn_800481B0(0x13);
        uVar14 = fn_800443CC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        fn_800481B0(0x13);
        fn_800443CC(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        bVar2 = false;
        while (uVar6 = fn_800430AC(0), (uVar6 & 0xffefffff) != 0) {
          uVar14 = fn_80014F40();
          fn_800202CC();
          if (bVar2) {
            uVar14 = fn_8004A868();
          }
          uVar14 = fn_800481D4(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          fn_80015624(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          if (bVar2) {
            uVar14 = fn_800234EC();
            fn_80019C24(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            fn_8004A43C('\x01');
          }
          if (DAT_803dd5d0 != '\0') {
            bVar2 = true;
          }
        }
        uVar14 = fn_80043034();
        break;
      case 0x17:
        lbl_803DDB80 = lbl_803DDB80 | 0x80000;
        break;
      case 0x18:
        lbl_803DDB80 = lbl_803DDB80 & 0xfff7ffff;
      }
    }
    if (*(short *)(puVar3 + 0x2d) != -1) {
      puVar7 = (undefined4 *)0x1;
      puVar8 = (undefined4 *)*DAT_803dd738;
      iVar11 = (*(code *)puVar8[0xc])(puVar3,puVar13);
      if (iVar11 == 0) goto LAB_801bd7dc;
      if (puVar3[0x32] != 0) {
        *(undefined4 *)(puVar3[0x32] + 0x30) = puVar3[0xc];
      }
      uVar14 = extraout_f1;
      if (((int)*(short *)((int)puVar13 + 0x3f6) != 0xffffffff) &&
         (uVar6 = GameBit_Get((int)*(short *)((int)puVar13 + 0x3f6)), uVar6 != 0)) {
        puVar7 = (undefined4 *)*DAT_803dd6d4;
        uVar14 = (*(code *)puVar7[0x16])(param_11,(int)*(short *)(iVar12 + 0x2c));
        *(undefined2 *)((int)puVar13 + 0x3f6) = 0xffff;
      }
      bVar1 = *(byte *)((int)puVar13 + 0x405);
      if (bVar1 == 1) {
        puVar8 = &DAT_803adc78;
        puVar9 = &DAT_803adc60;
        param_14 = 0;
        param_15 = *DAT_803dd738;
        puVar7 = puVar13;
        iVar11 = (**(code **)(param_15 + 0x34))(puVar3,param_11);
        uVar14 = extraout_f1_00;
        if (iVar11 != 0) {
          puVar7 = (undefined4 *)0x1;
          puVar8 = (undefined4 *)*DAT_803dd738;
          uVar14 = (*(code *)puVar8[0xb])((double)lbl_803E5908,puVar3,puVar13);
        }
      }
      else if ((bVar1 != 0) && (bVar1 < 3)) {
        *(undefined2 *)(param_11 + 0x6e) = 0;
        puVar7 = puVar13;
        puVar8 = puVar13;
        uVar14 = FUN_801bcc94(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,
                              param_11,(int)puVar13,(int)puVar13);
        if (*(char *)((int)puVar13 + 0x405) == '\x01') {
          *(undefined2 *)(puVar13 + 0x9c) = 0;
          param_2 = (double)lbl_803E58DC;
          puVar7 = &DAT_803adc78;
          puVar8 = &DAT_803adc60;
          puVar9 = (undefined4 *)*DAT_803dd70c;
          uVar14 = (*(code *)puVar9[2])(puVar3,puVar13);
          *(undefined *)(param_11 + 0x56) = 0;
        }
      }
    }
    FUN_801bbed0(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,puVar13,
                 puVar7,puVar8,puVar9,param_14,param_15,param_16);
    if (*(short *)(puVar3 + 0x2d) == -1) {
      *(ushort *)(puVar13 + 0x100) = *(ushort *)(puVar13 + 0x100) | 2;
    }
  }
LAB_801bd7dc:
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: dimboss_func11
 * EN v1.0 Address: 0x801BD240
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimboss_func11(void)
{
}

/*
 * --INFO--
 *
 * Function: dimboss_setScale
 * EN v1.0 Address: 0x801BD244
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimboss_setScale(DIMbossObject *obj)
{
  return obj->runtime->scale;
}

/*
 * --INFO--
 *
 * Function: dimboss_getExtraSize
 * EN v1.0 Address: 0x801BD250
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimboss_getExtraSize(void)
{
  return 0x4c8;
}

/*
 * --INFO--
 *
 * Function: dimboss_func08
 * EN v1.0 Address: 0x801BD258
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimboss_func08(void)
{
  return 0x49;
}

/*
 * --INFO--
 *
 * Function: dimboss_free
 * EN v1.0 Address: 0x801BD260
 * EN v1.0 Size: 260b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dimboss_free(DIMbossObject *obj)
{
  DIMbossRuntime *runtime;
  void *childObject;
  void *effect;

  runtime = obj->runtime;
  GameBit_Set(0xefd,0);
  GameBit_Set(0xc1e,1);
  GameBit_Set(0xc1f,0);
  GameBit_Set(0xc20,0);
  GameBit_Set(0xd8f,0);
  GameBit_Set(0x3e2,0);
  obj->objectFlags &= ~0x80;
  fn_8000FACC();
  ObjGroup_RemoveObject(obj,3);
  childObject = obj->childObject;
  if (childObject != NULL) {
    Obj_FreeObject(childObject);
    obj->childObject = NULL;
  }
  (*(code *)(*lbl_803DCAB8 + 0x40))(obj,runtime,0x20);
  if (lbl_803DDB88 != 0) {
    fn_80013E2C(lbl_803DDB88);
  }
  lbl_803DDB88 = 0;
  effect = *runtime->effect;
  if (effect != NULL) {
    fn_8001F384(effect);
  }
  fn_80055000();
}
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: dimboss_render
 * EN v1.0 Address: 0x801BD364
 * EN v1.0 Size: 176b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void dimboss_render(DIMbossObject *obj,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                    undefined4 param_5,char shouldRender)
{
  DIMbossRuntime *runtime;
  DIMbossEffect *effect;
  int visible;

  runtime = obj->runtime;
  visible = shouldRender;
  if (visible == 0) {
    return;
  }
  if (obj->renderPause != 0) {
    return;
  }
  if (runtime->phase == 3) {
    return;
  }
  fn_8003B8F4((double)lbl_803E4C44);
  fn_801BB598(obj,runtime);
  fn_80114DEC(obj,lbl_803AC9DC,0);
  effect = *runtime->effect;
  if (effect == NULL) {
    return;
  }
  if (effect->active == 0) {
    return;
  }
  if (effect->visible != 0) {
    fn_800604B4();
  }
}
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: dimboss_hitDetect
 * EN v1.0 Address: 0x801BD414
 * EN v1.0 Size: 60b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimboss_hitDetect(DIMbossObject *obj)
{
  (*(code *)(*(int *)lbl_803DCA8C + 0xc))(obj,obj->runtime,lbl_803AD018);
}
#pragma scheduling reset
