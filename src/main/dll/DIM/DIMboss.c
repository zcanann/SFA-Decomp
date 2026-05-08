#include "ghidra_import.h"
#include "main/dll/DIM/DIMboss.h"

extern void Music_Trigger(s32 triggerId, s32 mode);
extern undefined4 FUN_800069b8();
extern undefined4 FUN_80006b0c();
extern undefined8 padUpdate();
extern undefined4 fn_80015624();
extern undefined4 fn_80019C24();
extern undefined4 FUN_80017620();
extern undefined4 fn_80016870();
extern uint GameBit_Get();
extern undefined8 GameBit_Set();
extern undefined4 checkReset();
extern undefined8 mmFreeTick();
extern undefined4 ObjModel_ClearRenderAttachment();
extern undefined4 ObjModel_EnableDefaultRenderCallback();
extern int Obj_GetActiveModel();
extern undefined4 Obj_BuildWorldTransformMatrix();
extern undefined4 FUN_80017a98();
extern undefined4 fn_8002B9AC();
extern undefined4 FUN_80017ac8();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_8003b818();
extern undefined8 FUN_80040da0();
extern undefined8 fn_80043034();
extern undefined8 fn_80043074();
extern uint fn_800430AC();
extern undefined4 unlockLevel();
extern undefined4 fn_80043560();
extern undefined8 mapUnload();
extern undefined4 fn_80041E3C();
extern undefined8 mapLoadDataFile();
extern undefined4 mapGetDirIdx();
extern undefined8 fn_800481D4();
extern undefined4 GXFlush_();
extern undefined8 waitNextFrame();
extern undefined4 FUN_80053b3c();
extern undefined4 FUN_8005fe14();
extern undefined4 FUN_80080f70();
extern undefined4 FUN_80080f7c();
extern undefined4 FUN_80080f80();
extern undefined8 fn_80114BB0();
extern undefined4 FUN_801149bc();
extern undefined4 FUN_801bb848();
extern undefined4 fn_801BBB44();
extern undefined8 fn_801BC7E4();
extern undefined4 fn_8011508C();
extern void OSReport(const char *msg, ...);

extern undefined4 Camera_DisableViewYOffset();
extern undefined4 getEnvfxAct();
extern undefined4 Resource_Release();
extern undefined4 fn_8001F384();
extern undefined4 Obj_FreeObject();
extern undefined4 Obj_GetPlayerObject();
extern undefined4 ObjHits_RegisterActiveHitVolumeObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 fn_8003B8F4();
extern undefined4 fn_80055000();
extern undefined4 fn_800604B4();
extern undefined4 fn_80114DEC();
extern undefined4 fn_80115094();
extern undefined4 fn_801BB598();

extern f32 timeDelta;
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
extern undefined4 lbl_803AC9AC[];
extern undefined4 lbl_803AC9DC[];
extern undefined4 lbl_803AD018[];
extern int lbl_803DCA8C;
extern undefined4* lbl_803DCAB8;
extern undefined4 lbl_803DDB88;
extern f32 lbl_803E4BD8;
extern f32 lbl_803E4C44;
extern f32 lbl_803E4C4C;
extern f32 lbl_803E4C50;
extern f32 lbl_803E4C54;
extern char sDIMBossFreeingAssetsForDIMBoss[];
extern char sDIMBossLoadingAssetsForDIMTop[];

typedef struct DIMbossEffect {
  u8 pad00[0x4C];
  u8 visible;
  u8 pad4D[0x2F8 - 0x4D];
  u8 active;
} DIMbossEffect;

typedef struct DIMbossTopState {
  DIMbossEffect *effect;
  u8 pad004[0xA4 - 0x04];
  f32 launchLift;
  u8 pad0A8[0xAC - 0xA8];
  f32 introSinkHeight;
  s32 defeatTimer;
  s8 stompDustDelay;
  u8 pad0B5;
  s8 steamSfxPending;
} DIMbossTopState;

typedef struct DIMbossRuntime {
  u8 pad000[0x274];
  s16 scale;
  u8 pad276[0x2D0 - 0x276];
  undefined4 targetModel;
  u8 pad2D4[0x354 - 0x2D4];
  u8 animMode;
  u8 pad355[0x35C - 0x355];
  u8 moveScratch[0x3F4 - 0x35C];
  s16 activeMoveId;
  s16 eventGameBit;
  u8 pad3F8[0x400 - 0x3F8];
  u16 stateFlags;
  s16 phase;
  u8 pad404;
  u8 hitReactMode;
  u8 pad406[0x40C - 0x406];
  DIMbossTopState *topState;
} DIMbossRuntime;

typedef struct DIMbossConfig {
  u8 pad00[0x08];
  f32 spawnX;
  f32 spawnY;
  f32 spawnZ;
  u8 pad14[0x2E - 0x14];
  s8 animObjId;
} DIMbossConfig;

typedef struct DIMbossObject {
  u8 pad00[0x08];
  f32 baseScale;
  f32 posX;
  f32 posY;
  f32 posZ;
  u8 pad18[0x30 - 0x18];
  undefined4 facingAngle;
  u8 pad34[0x4C - 0x34];
  DIMbossConfig *config;
  u8 pad50[0xA8 - 0x50];
  f32 modelScale;
  u8 padAC[0xAF - 0xAC];
  u8 objectFlags;
  u8 padB0[0xB8 - 0xB0];
  DIMbossRuntime *runtime;
  u8 padBC[0xC8 - 0xBC];
  void *childObject;
  u8 padCC[0xF4 - 0xCC];
  int renderPause;
  int updateInitialized;
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
#pragma scheduling off
#pragma peephole off
void DIMboss_updateState(DIMbossObject *param_1,undefined4 param_2,ObjAnimUpdateState *animUpdate)
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
  
  puVar3 = (undefined4 *)param_1;
  puVar13 = (undefined4 *)puVar3[0x2e];
  iVar12 = puVar3[0x13];
  Obj_GetPlayerObject();
  iVar11 = puVar13[0x103];
  *(undefined2 *)((int)puVar13 + 0x402) = 0;
  (*(code *)(*lbl_803DCAAC + 0x50))(0x1c,5,0);
  if (puVar3[0x3d] == 0) {
    puVar7 = lbl_803AC9DC;
    puVar8 = (undefined4 *)0x1;
    puVar9 = (undefined4 *)0x1;
    fn_80114BB0(puVar3,animUpdate,(float *)lbl_803AC9DC,1,1);
    for (iVar10 = 0; iVar10 < (int)(uint)animUpdate->eventCount; iVar10 = iVar10 + 1) {
      switch(animUpdate->eventIds[iVar10]) {
      case 1:
        (*(code *)(*lbl_803DCAB4 + 0xc))(puVar3,0x800,0,100,0);
        (*(code *)(*lbl_803DCAB4 + 0xc))(puVar3,0x800,0,100,0);
        (*(code *)(*lbl_803DCAB4 + 0xc))(puVar3,0x7ff,0,100,0);
        puVar7 = (undefined4 *)0x0;
        puVar8 = (undefined4 *)0x64;
        puVar9 = (undefined4 *)0x0;
        (*(code *)(*lbl_803DCAB4 + 0xc))(puVar3,0x7ff,0,100,0);
        iVar4 = Obj_GetActiveModel((int)puVar3);
        ObjModel_ClearRenderAttachment(iVar4);
        Music_Trigger(0x27,1);
        break;
      case 2:
        *(undefined2 *)((int)puVar13 + 0x402) = 1;
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) | 0x80;
        (*(code *)(*lbl_803DCAAC + 0x50))(0x1c,0,0);
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
        Music_Trigger(0xee,0);
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
        GameBit_Set(0x17,1);
        Music_Trigger(0x27,0);
        Music_Trigger(0x36,0);
        Music_Trigger(0xee,0);
        break;
      case 0x12:
        (*(code *)(*DAT_803dd6d4 + 0x50))(0x49,4,puVar3,0x3c);
        break;
      case 0x13:
        (*(code *)(*lbl_803DCAAC + 0x50))(0x1c,2,1);
        break;
      case 0x14:
        (*(code *)(*lbl_803DCAAC + 0x50))(0x1c,2,0);
        break;
      case 0x15:
        OSReport(sDIMBossFreeingAssetsForDIMBoss);
        fn_80043074();
        unlockLevel(0,0,1);
        uVar5 = mapGetDirIdx(0x1c);
        mapUnload(uVar5,0x3ff);
        uVar5 = mapGetDirIdx(0x1b);
        mapUnload(uVar5,0x20000000);
        fn_80041E3C(0);
        break;
      case 0x16:
        OSReport(sDIMBossLoadingAssetsForDIMTop);
        uVar5 = mapGetDirIdx(0x13);
        fn_80043560(uVar5,0);
        mapGetDirIdx(0x13);
        mapLoadDataFile(uVar5,0x20);
        uVar5 = mapGetDirIdx(0x13);
        mapLoadDataFile(uVar5,0x21);
        uVar5 = mapGetDirIdx(0x13);
        mapLoadDataFile(uVar5,0x23);
        uVar5 = mapGetDirIdx(0x13);
        mapLoadDataFile(uVar5,0x24);
        uVar5 = mapGetDirIdx(0x13);
        mapLoadDataFile(uVar5,0x30);
        uVar5 = mapGetDirIdx(0x13);
        mapLoadDataFile(uVar5,0x2f);
        uVar5 = mapGetDirIdx(0x13);
        mapLoadDataFile(uVar5,0x2b);
        uVar5 = mapGetDirIdx(0x13);
        mapLoadDataFile(uVar5,0x2a);
        uVar5 = mapGetDirIdx(0x13);
        mapLoadDataFile(uVar5,0x26);
        uVar5 = mapGetDirIdx(0x13);
        mapLoadDataFile(uVar5,0x25);
        uVar5 = mapGetDirIdx(0x13);
        mapLoadDataFile(uVar5,0x1a);
        uVar5 = mapGetDirIdx(0x13);
        mapLoadDataFile(uVar5,0x1b);
        uVar5 = mapGetDirIdx(0x13);
        mapLoadDataFile(uVar5,0xe);
        uVar5 = mapGetDirIdx(0x13);
        mapLoadDataFile(uVar5,0xd);
        bVar2 = false;
        while (uVar6 = fn_800430AC(0), (uVar6 & 0xffefffff) != 0) {
          padUpdate();
          checkReset();
          if (bVar2) {
            waitNextFrame();
          }
          fn_800481D4();
          fn_80015624();
          if (bVar2) {
            mmFreeTick(0);
            fn_80019C24();
            GXFlush_(1,0);
          }
          if (DAT_803dd5d0 != '\0') {
            bVar2 = true;
          }
        }
        fn_80043034();
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
      if (((int)*(short *)((int)puVar13 + 0x3f6) != 0xffffffff) &&
          (uVar6 = GameBit_Get((int)*(short *)((int)puVar13 + 0x3f6)), uVar6 != 0)) {
        puVar7 = (undefined4 *)*DAT_803dd6d4;
        (*(code *)puVar7[0x16])(animUpdate,(int)*(short *)(iVar12 + 0x2c));
        *(undefined2 *)((int)puVar13 + 0x3f6) = 0xffff;
      }
      bVar1 = *(byte *)((int)puVar13 + 0x405);
      if (bVar1 == 1) {
        iVar11 = (*(code *)(*DAT_803dd738 + 0x34))
                          (puVar3,animUpdate,puVar13,&DAT_803adc78,&DAT_803adc60,0);
        if (iVar11 != 0) {
          puVar7 = (undefined4 *)0x1;
          puVar8 = (undefined4 *)*DAT_803dd738;
          (*(code *)puVar8[0xb])((double)lbl_803E5908,puVar3,puVar13);
        }
      }
      else if ((bVar1 != 0) && (bVar1 < 3)) {
        *(undefined2 *)((int)animUpdate + 0x6e) = 0;
        puVar7 = puVar13;
        puVar8 = puVar13;
        fn_801BC7E4(puVar3,animUpdate,(int)puVar13,(int)puVar13);
        if (*(char *)((int)puVar13 + 0x405) == '\x01') {
          *(undefined2 *)(puVar13 + 0x9c) = 0;
          puVar7 = &DAT_803adc78;
          puVar8 = &DAT_803adc60;
          puVar9 = (undefined4 *)*DAT_803dd70c;
          (*(code *)puVar9[2])(puVar3,puVar13);
          *(undefined *)((int)animUpdate + 0x56) = 0;
        }
      }
    }
    fn_801BBB44(puVar3,puVar13);
    if (*(short *)(puVar3 + 0x2d) == -1) {
      *(ushort *)(puVar13 + 0x100) = *(ushort *)(puVar13 + 0x100) | 2;
    }
  }
LAB_801bd7dc:
  return;
}
#pragma peephole reset
#pragma scheduling reset

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
 * Function: DIMboss_setScale
 * EN v1.0 Address: 0x801BD244
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int DIMboss_setScale(DIMbossObject *obj)
{
  return obj->runtime->scale;
}

/*
 * --INFO--
 *
 * Function: DIMboss_getExtraSize
 * EN v1.0 Address: 0x801BD250
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int DIMboss_getExtraSize(void)
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
 * Function: DIMboss_free
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
void DIMboss_free(DIMbossObject *obj)
{
  DIMbossRuntime *runtime;
  DIMbossTopState *topState;
  void *childObject;
  void *effect;

  runtime = obj->runtime;
  topState = runtime->topState;
  GameBit_Set(0xefd,0);
  GameBit_Set(0xc1e,1);
  GameBit_Set(0xc1f,0);
  GameBit_Set(0xc20,0);
  GameBit_Set(0xd8f,0);
  GameBit_Set(0x3e2,0);
  obj->objectFlags &= ~0x80;
  Camera_DisableViewYOffset();
  ObjGroup_RemoveObject(obj,3);
  childObject = obj->childObject;
  if (childObject != NULL) {
    Obj_FreeObject(childObject);
    obj->childObject = NULL;
  }
  (*(code *)(*lbl_803DCAB8 + 0x40))(obj,runtime,0x20);
  if (lbl_803DDB88 != 0) {
    Resource_Release(lbl_803DDB88);
  }
  lbl_803DDB88 = 0;
  effect = topState->effect;
  if (effect != NULL) {
    fn_8001F384(effect);
  }
  fn_80055000();
}
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: DIMboss_render
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
void DIMboss_render(DIMbossObject *obj,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                    undefined4 param_5,char shouldRender)
{
  DIMbossRuntime *runtime;
  DIMbossTopState *topState;
  DIMbossEffect *effect;
  int visible;

  runtime = obj->runtime;
  topState = runtime->topState;
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
  effect = topState->effect;
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
 * Function: DIMboss_hitDetect
 * EN v1.0 Address: 0x801BD414
 * EN v1.0 Size: 60b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMboss_hitDetect(DIMbossObject *obj)
{
  (*(code *)(*(int *)lbl_803DCA8C + 0xc))(obj,obj->runtime,lbl_803AD018);
}

/*
 * --INFO--
 *
 * Function: dimboss_update2
 * EN v1.0 Address: 0x801BD450
 * EN v1.0 Size: 860b
 * EN v1.1 Address: 0x801BDA04
 * EN v1.1 Size: 860b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dimboss_update2(DIMbossObject *obj)
{
  uint gameBitCount;
  undefined4 targetModel;
  DIMbossRuntime *runtime;
  DIMbossConfig *config;
  DIMbossTopState *topState;
  void *childObject;

  runtime = obj->runtime;
  config = obj->config;
  Obj_GetPlayerObject();
  topState = runtime->topState;
  if (obj->renderPause == 0) {
    if (lbl_803E4BD8 < topState->introSinkHeight) {
      fn_80016870(0x432);
      topState->introSinkHeight -= timeDelta;
      if (topState->introSinkHeight < lbl_803E4BD8) {
        topState->introSinkHeight = lbl_803E4BD8;
      }
    }
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (obj->updateInitialized == 0) {
      obj->posX = config->spawnX;
      obj->posY = config->spawnY;
      obj->posZ = config->spawnZ;
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)config->animObjId,obj,0xffffffff);
      obj->updateInitialized = 1;
    }
    else {
      if ((runtime->stateFlags & 2) != 0) {
        (**(code **)(*DAT_803dd738 + 0x28))
                  (obj,runtime,runtime->moveScratch,(int)runtime->activeMoveId,
                   &runtime->hitReactMode,0,0,0,1);
        runtime->stateFlags &= ~2;
        obj->objectFlags &= ~8;
        obj->objectFlags |= 0x80;
        gameBitCount = GameBit_Get(0x20c);
        if (gameBitCount < 3) {
          runtime->phase = 1;
          runtime->animMode = 3;
          obj->objectFlags &= ~8;
          topState->launchLift = lbl_803E4C44;
          GameBit_Set(0x9e,1);
        }
        else {
          runtime->phase = 2;
          runtime->animMode = 3;
          obj->objectFlags &= ~8;
          GameBit_Set(0x9e,0);
        }
      }
      if ((runtime->phase == 0) || (runtime->phase == 3)) {
        if ((topState->stompDustDelay != 0) &&
            (--topState->stompDustDelay == 0)) {
          Obj_BuildWorldTransformMatrix(obj,lbl_803AC9AC,0);
          targetModel = Obj_GetActiveModel(obj);
          ObjModel_EnableDefaultRenderCallback
                    ((double)(obj->modelScale * obj->baseScale),obj,targetModel,lbl_803AC9AC,1);
        }
        if (topState->steamSfxPending < 0) {
          getEnvfxAct(0,0,0xdb,0);
          getEnvfxAct(0,0,0xdc,0);
          FUN_80080f80(7,1,0);
          FUN_80080f70((double)lbl_803E4C4C,(double)lbl_803E4C50,(double)lbl_803E4C54,7);
          FUN_80080f7c(7,0xa0,0xa0,0xff,0x7f,0x28);
          topState->steamSfxPending &= 0x7f;
        }
      }
      else {
        if ((runtime->stateFlags & 4) == 0) {
          targetModel = Obj_GetPlayerObject();
          runtime->targetModel = targetModel;
        }
        else {
          targetModel = fn_8002B9AC();
          runtime->targetModel = targetModel;
        }
        childObject = obj->childObject;
        if (childObject != NULL) {
          *(undefined4 *)((int)childObject + 0x30) = obj->facingAngle;
        }
        fn_801BC7E4(obj,0,runtime,runtime);
        fn_8011508C(lbl_803AC9DC,runtime->targetModel);
        fn_80115094(obj,lbl_803AC9DC);
        fn_801BBB44(obj,runtime);
      }
    }
  }
}
#pragma peephole reset
#pragma scheduling reset
