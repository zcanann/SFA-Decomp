#include "ghidra_import.h"
#include "main/dll/DIM/DIMboss.h"

extern void Music_Trigger(s32 triggerId, s32 mode);
extern undefined8 FUN_80006728();
extern undefined4 FUN_800069b8();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006c88();
extern undefined8 padUpdate();
extern undefined4 dvdCheckError();
extern undefined4 gameTextRun();
extern undefined4 FUN_80017620();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined8 FUN_80017940();
extern undefined4 FUN_80017a50();
extern int FUN_80017a54();
extern undefined4 FUN_80017a90();
extern undefined4 gameTextShow();
extern uint GameBit_Get();
extern undefined8 GameBit_Set();
extern undefined4 checkReset();
extern undefined8 mmFreeTick();
extern undefined4 ObjModel_ClearRenderAttachment();
extern undefined4 ObjModel_EnableDefaultRenderCallback();
extern int Obj_GetActiveModel();
extern undefined4 Obj_BuildWorldTransformMatrix();
extern undefined4 FUN_80017a98();
extern undefined4 getTrickyObject();
extern undefined4 FUN_80017ac8();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_8003b818();
extern undefined8 FUN_80040da0();
extern undefined8 clearLoadedFileFlags_blocks1();
extern undefined8 setLoadedFileFlags_blocks1();
extern uint getLoadedFileFlags();
extern undefined4 unlockLevel();
extern undefined4 lockLevel();
extern undefined8 mapUnload();
extern undefined4 defragMemory();
extern undefined8 mapLoadDataFile();
extern undefined4 mapGetDirIdx();
extern undefined8 loadDataFiles();
extern undefined4 GXFlush_();
extern undefined8 waitNextFrame();
extern undefined4 FUN_80053b3c();
extern undefined4 FUN_8005fe14();
extern undefined4 FUN_80080f70();
extern undefined4 FUN_80080f7c();
extern undefined4 FUN_80080f80();
extern undefined8 dll_2E_func07();
extern undefined4 FUN_801150a4();
extern undefined8 FUN_801150ac();
extern undefined4 FUN_801149bc();
extern undefined4 FUN_801bbed0();
extern undefined4 FUN_801bb848();
extern undefined4 warpDarkIceMines_801bbb44();
extern undefined4 FUN_801bcc94();
extern undefined8 fn_801BC7E4();
extern undefined4 dll_2E_func04();
extern void OSReport(const char *msg, ...);

extern undefined4 Camera_DisableViewYOffset();
extern undefined4 getEnvfxAct();
extern undefined4 Resource_Release();
extern undefined4 ModelLightStruct_free();
extern undefined4 Obj_FreeObject();
extern undefined4 Obj_GetPlayerObject();
extern undefined4 ObjHits_RegisterActiveHitVolumeObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 objRenderFn_8003b8f4();
extern undefined4 timeOfDayFn_80055000();
extern undefined4 queueGlowRender();
extern undefined4 dll_2E_func06();
extern undefined4 dll_2E_func03();
extern undefined4 fn_801BB598();

extern f32 timeDelta;
extern undefined4 DAT_803ad60c;
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
extern f32 lbl_803DC074;
extern f32 lbl_803E5870;
extern f32 lbl_803E58E4;
extern f32 lbl_803E58E8;
extern f32 lbl_803E58EC;
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
    dll_2E_func07(puVar3,animUpdate,(float *)lbl_803AC9DC,1,1);
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
      case DIMBOSS_EVENT_FREE_DIMBOSS_ASSETS:
        OSReport(sDIMBossFreeingAssetsForDIMBoss);
        setLoadedFileFlags_blocks1();
        unlockLevel(0,0,1);
        uVar5 = mapGetDirIdx(DIMBOSS_MAP_DIR);
        mapUnload(uVar5,DIMBOSS_MAP_UNLOAD_MASK);
        uVar5 = mapGetDirIdx(DIMBOSS_GUT_MAP_DIR);
        mapUnload(uVar5,DIMBOSS_GUT_MAP_UNLOAD_MASK);
        defragMemory(0);
        break;
      case DIMBOSS_EVENT_LOAD_DIMTOP_ASSETS:
        OSReport(sDIMBossLoadingAssetsForDIMTop);
        uVar5 = mapGetDirIdx(DIMTOP_MAP_DIR);
        lockLevel(uVar5,0);
        mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(uVar5,DIMTOP_BOOT_DATA_FILE);
        uVar5 = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(uVar5,DIMTOP_INTRO_DATA_FILE);
        uVar5 = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(uVar5,DIMTOP_PLATFORM_DATA_FILE);
        uVar5 = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(uVar5,DIMTOP_LIFT_DATA_FILE);
        uVar5 = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(uVar5,DIMTOP_SCENE_DATA_FILE);
        uVar5 = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(uVar5,DIMTOP_STEAM_DATA_FILE);
        uVar5 = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(uVar5,DIMTOP_BOSS_DATA_FILE_A);
        uVar5 = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(uVar5,DIMTOP_BOSS_DATA_FILE_B);
        uVar5 = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(uVar5,DIMTOP_EFFECT_DATA_FILE_A);
        uVar5 = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(uVar5,DIMTOP_EFFECT_DATA_FILE_B);
        uVar5 = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(uVar5,DIMTOP_ROOM_DATA_FILE_A);
        uVar5 = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(uVar5,DIMTOP_ROOM_DATA_FILE_B);
        uVar5 = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(uVar5,DIMTOP_AUDIO_DATA_FILE_A);
        uVar5 = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(uVar5,DIMTOP_AUDIO_DATA_FILE_B);
        bVar2 = false;
        while (uVar6 = getLoadedFileFlags(0), (uVar6 & 0xffefffff) != 0) {
          padUpdate();
          checkReset();
          if (bVar2) {
            waitNextFrame();
          }
          loadDataFiles();
          dvdCheckError();
          if (bVar2) {
            mmFreeTick(0);
            gameTextRun();
            GXFlush_(1,0);
          }
          if (DAT_803dd5d0 != '\0') {
            bVar2 = true;
          }
        }
        clearLoadedFileFlags_blocks1();
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
    warpDarkIceMines_801bbb44(puVar3,puVar13);
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
  return DIMBOSS_RUNTIME_SIZE;
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
  return DIMBOSS_OBJECT_TYPE_ID;
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
  effect = runtime->topState->effect;
  if (effect != NULL) {
    ModelLightStruct_free(effect);
  }
  timeOfDayFn_80055000();
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
  objRenderFn_8003b8f4((double)lbl_803E4C44);
  fn_801BB598(obj,runtime);
  dll_2E_func06(obj,lbl_803AC9DC,0);
  effect = runtime->topState->effect;
  if (effect == NULL) {
    return;
  }
  if (effect->active == 0) {
    return;
  }
  if (effect->visible != 0) {
    queueGlowRender();
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
  DIMbossTopState *topState;
  DIMbossRuntime *runtime;
  DIMbossConfig *config;
  void *childObject;

  runtime = obj->runtime;
  config = obj->config;
  Obj_GetPlayerObject();
  topState = runtime->topState;
  if (obj->renderPause == 0) {
    if (topState->introSinkHeight > lbl_803E4BD8) {
      gameTextShow(0x432);
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
        if (gameBitCount >= 3) {
          runtime->phase = 2;
          runtime->animMode = 3;
          obj->objectFlags &= ~8;
          GameBit_Set(0x9e,0);
        }
        else {
          runtime->phase = 1;
          runtime->animMode = 3;
          obj->objectFlags &= ~8;
          topState->launchLift = lbl_803E4C44;
          GameBit_Set(0x9e,1);
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
        if ((topState->steamSfxPending & 0x80) != 0) {
          getEnvfxAct(0,0,0xdb,0);
          getEnvfxAct(0,0,0xdc,0);
          FUN_80080f80(7,1,0);
          FUN_80080f70((double)lbl_803E4C4C,(double)lbl_803E4C50,(double)lbl_803E4C54,7);
          FUN_80080f7c(7,0xa0,0xa0,0xff,0x7f,0x28);
          topState->steamSfxPending &= ~0x80;
        }
      }
      else {
        if ((runtime->stateFlags & 4) == 0) {
          targetModel = Obj_GetPlayerObject();
          runtime->targetModel = targetModel;
        }
        else {
          targetModel = getTrickyObject();
          runtime->targetModel = targetModel;
        }
        childObject = obj->childObject;
        if (childObject != NULL) {
          *(undefined4 *)((int)childObject + 0x30) = obj->facingAngle;
        }
        fn_801BC7E4(obj,0,runtime,runtime);
        dll_2E_func04(lbl_803AC9DC,runtime->targetModel);
        dll_2E_func03(obj,lbl_803AC9DC);
        warpDarkIceMines_801bbb44(obj,runtime);
      }
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: DIMboss_update
 * EN v1.0 Address: 0x801BD7AC
 * EN v1.0 Size: 1240b
 * EN v1.1 Address: 0x801BDA04
 * EN v1.1 Size: 860b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMboss_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                    undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                    ushort *param_9)
{
  uint uVar1;
  undefined4 uVar2;
  int in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;

  iVar4 = *(int *)(param_9 + 0x5c);
  iVar3 = *(int *)(param_9 + 0x26);
  FUN_80017a98();
  iVar5 = *(int *)(iVar4 + 0x40c);
  if (*(int *)(param_9 + 0x7a) == 0) {
    if ((double)lbl_803E5870 < (double)*(float *)(iVar5 + 0xac)) {
      FUN_80006c88((double)*(float *)(iVar5 + 0xac),param_2,param_3,param_4,param_5,param_6,param_7,
                   param_8,0x432);
      *(float *)(iVar5 + 0xac) = *(float *)(iVar5 + 0xac) - lbl_803DC074;
      if (*(float *)(iVar5 + 0xac) < lbl_803E5870) {
        *(float *)(iVar5 + 0xac) = lbl_803E5870;
      }
    }
    uVar6 = ObjHits_RegisterActiveHitVolumeObject(param_9);
    if (*(int *)(param_9 + 0x7c) == 0) {
      *(undefined4 *)(param_9 + 6) = *(undefined4 *)(iVar3 + 8);
      *(undefined4 *)(param_9 + 8) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(param_9 + 10) = *(undefined4 *)(iVar3 + 0x10);
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 0x2e),param_9,0xffffffff);
      param_9[0x7c] = 0;
      param_9[0x7d] = 1;
    }
    else {
      if ((*(ushort *)(iVar4 + 0x400) & 2) != 0) {
        in_r7 = iVar4 + 0x405;
        in_r8 = 0;
        in_r9 = 0;
        in_r10 = 0;
        (**(code **)(*DAT_803dd738 + 0x28))
                  (param_9,iVar4,iVar4 + 0x35c,(int)*(short *)(iVar4 + 0x3f4));
        *(ushort *)(iVar4 + 0x400) = *(ushort *)(iVar4 + 0x400) & 0xfffd;
        *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
        *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 0x80;
        uVar1 = FUN_80017690(0x20c);
        if (uVar1 < 3) {
          *(undefined2 *)(iVar4 + 0x402) = 1;
          *(undefined *)(iVar4 + 0x354) = 3;
          *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
          *(float *)(iVar5 + 0xa4) = lbl_803E58DC;
          uVar6 = FUN_80017698(0x9e,1);
        }
        else {
          *(undefined2 *)(iVar4 + 0x402) = 2;
          *(undefined *)(iVar4 + 0x354) = 3;
          *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
          uVar6 = FUN_80017698(0x9e,0);
        }
      }
      if ((*(short *)(iVar4 + 0x402) == 0) || (*(short *)(iVar4 + 0x402) == 3)) {
        if ((*(char *)(iVar5 + 0xb4) != '\0') &&
           (*(char *)(iVar5 + 0xb4) = *(char *)(iVar5 + 0xb4) + -1, *(char *)(iVar5 + 0xb4) == '\0')
           ) {
          FUN_80017a50(param_9,(float *)&DAT_803ad60c,'\0');
          iVar3 = FUN_80017a54((int)param_9);
          uVar6 = FUN_80017940(param_9,iVar3);
        }
        if (*(char *)(iVar5 + 0xb6) < '\0') {
          uVar6 = FUN_80006728(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                               0xdb,0,in_r7,in_r8,in_r9,in_r10);
          FUN_80006728(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0xdc,0,
                       in_r7,in_r8,in_r9,in_r10);
          FUN_80080f80(7,1,0);
          FUN_80080f70((double)lbl_803E58E4,(double)lbl_803E58E8,(double)lbl_803E58EC,7);
          FUN_80080f7c(7,0xa0,0xa0,0xff,0x7f,0x28);
          *(byte *)(iVar5 + 0xb6) = *(byte *)(iVar5 + 0xb6) & 0x7f;
        }
      }
      else {
        if ((*(ushort *)(iVar4 + 0x400) & 4) == 0) {
          uVar2 = FUN_80017a98();
          *(undefined4 *)(iVar4 + 0x2d0) = uVar2;
        }
        else {
          uVar2 = FUN_80017a90();
          *(undefined4 *)(iVar4 + 0x2d0) = uVar2;
        }
        if (*(int *)(param_9 + 100) != 0) {
          *(undefined4 *)(*(int *)(param_9 + 100) + 0x30) = *(undefined4 *)(param_9 + 0x18);
        }
        iVar3 = iVar4;
        iVar5 = iVar4;
        FUN_801bcc94(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0,iVar4,
                     iVar4);
        FUN_801150a4(-0x7fc529c4,*(undefined4 *)(iVar4 + 0x2d0));
        uVar6 = FUN_801150ac();
        FUN_801bbed0(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar4,
                     iVar3,iVar5,in_r7,in_r8,in_r9,in_r10);
      }
    }
  }
  return;
}

extern void fn_801BDAF4(void);

/*
 * --INFO--
 *
 * Function: dimboss_initialise
 * EN v1.0 Address: 0x801BDAD4
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimboss_initialise(void)
{
  fn_801BDAF4();
}

void dimboss_release(void) {}
