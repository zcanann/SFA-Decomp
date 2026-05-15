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
extern uint GameBit_Get(int eventId);
extern undefined8 GameBit_Set(int eventId, int value);
extern undefined8 FUN_80017940();
extern undefined4 FUN_80017a50();
extern int FUN_80017a54();
extern undefined4 FUN_80017a90();
extern undefined4 gameTextShow();
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
extern void fn_8005CEF0(int param_1);
extern undefined4 fn_800894A8();
extern undefined4 fn_800895E0();
extern undefined4 fn_80089710();
extern undefined8 dll_2E_func07();
extern undefined4 FUN_801150a4();
extern undefined8 FUN_801150ac();
extern undefined4 fn_80113F9C();
extern undefined4 fn_80114F64();
extern undefined4 FUN_801149bc();
extern void fn_801B9ECC(void);
extern void fn_801BA224(void);
extern void fn_801BA4B8(void);
extern void fn_801BA590(void);
extern void fn_801BA5A8(void);
extern void fn_801BA5F0(void);
extern void fn_801BA654(void);
extern void fn_801BA780(void);
extern void fn_801BA880(void);
extern void fn_801BA958(void);
extern void fn_801BAA84(void);
extern void fn_801BAB88(void);
extern void fn_801BACB8(void);
extern void fn_801BAE00(void);
extern void fn_801BAF58(void);
extern void fn_801BB0D8(void);
extern void fn_801BB1EC(void);
extern void fn_801BB2B0(void);
extern undefined4 FUN_801bbed0();
extern undefined4 FUN_801bb848();
extern undefined4 warpDarkIceMines_801bbb44();
extern undefined4 FUN_801bcc94();
extern undefined8 fn_801BC7E4();
extern undefined4 dll_2E_func04();
extern void *Resource_Acquire(int id, int mode);
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
extern undefined4 lbl_802C2338[];
extern void (*lbl_803AD000[])(void);
extern void (*lbl_803AD018[])(void);
extern int lbl_803DCA8C;
extern undefined4* lbl_803DCA54;
extern undefined4* lbl_803DCAB8;
extern undefined4 lbl_803DDB88;
extern u8 lbl_803DDB84;
extern f32 lbl_803E4BD8;
extern f32 lbl_803E4C28;
extern f32 lbl_803E4C44;
extern f32 lbl_803E4C4C;
extern f32 lbl_803E4C50;
extern f32 lbl_803E4C54;
extern f32 lbl_803E4C78;
extern char sDIMBossFreeingAssetsForDIMBoss[];
extern char sDIMBossLoadingAssetsForDIMTop[];

typedef void (*DIMbossAnimSetupFn)(DIMbossObject *obj,undefined4 param_2,DIMbossRuntime *runtime,
                                   int param_4,int param_5,int param_6,int param_7,float scale);

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
void DIMboss_updateState(DIMbossObject *obj,undefined4 param_2,ObjAnimUpdateState *animUpdate)
{
  DIMbossRuntime *runtime;
  DIMbossConfig *config;
  DIMbossTopState *topState;
  byte bVar1;
  bool loadWaitStarted;
  undefined4 *puVar3;
  int iVar4;
  undefined4 mapDirIndex;
  uint statusFlags;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  int eventIndex;
  int iVar11;
  int iVar12;
  undefined4 *puVar13;
  
  runtime = obj->runtime;
  config = obj->config;
  topState = runtime->topState;
  puVar3 = (undefined4 *)obj;
  puVar13 = (undefined4 *)runtime;
  iVar12 = (int)config;
  Obj_GetPlayerObject();
  iVar11 = (int)topState;
  runtime->phase = DIMBOSS_PHASE_START;
  (*(code *)(*lbl_803DCAAC + 0x50))(0x1c,5,0);
  if (obj->renderPause == 0) {
    puVar7 = lbl_803AC9DC;
    puVar8 = (undefined4 *)0x1;
    puVar9 = (undefined4 *)0x1;
    dll_2E_func07(puVar3,animUpdate,(float *)lbl_803AC9DC,1,1);
    for (eventIndex = 0; eventIndex < (int)(uint)animUpdate->eventCount; eventIndex = eventIndex + 1) {
      switch(animUpdate->eventIds[eventIndex]) {
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
        iVar11 = (int)topState;
        topState->steamSfxPending |= DIMBOSS_STEAM_SFX_PENDING_FLAG;
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
      case DIMBOSS_EVENT_TRIGGER_DEFEAT_FLAGS:
        topState->defeatTimer = DIMBOSS_DEFEAT_TIMER_START;
        GameBit_Set(0x123,1);
        GameBit_Set(0x17,1);
        Music_Trigger(0x27,0);
        Music_Trigger(0x36,0);
        Music_Trigger(0xee,0);
        break;
      case DIMBOSS_EVENT_SPAWN_DIMBOSS_OBJECT:
        (*(code *)(*DAT_803dd6d4 + 0x50))(DIMBOSS_OBJECT_TYPE_ID,4,puVar3,0x3c);
        break;
      case DIMBOSS_EVENT_ENABLE_DIMBOSS_MAP_AREA:
        (*(code *)(*lbl_803DCAAC + 0x50))(DIMBOSS_MAP_DIR,2,1);
        break;
      case DIMBOSS_EVENT_DISABLE_DIMBOSS_MAP_AREA:
        (*(code *)(*lbl_803DCAAC + 0x50))(DIMBOSS_MAP_DIR,2,0);
        break;
      case DIMBOSS_EVENT_FREE_DIMBOSS_ASSETS:
        OSReport(sDIMBossFreeingAssetsForDIMBoss);
        setLoadedFileFlags_blocks1();
        unlockLevel(0,0,1);
        mapDirIndex = mapGetDirIdx(DIMBOSS_MAP_DIR);
        mapUnload(mapDirIndex,DIMBOSS_MAP_UNLOAD_MASK);
        mapDirIndex = mapGetDirIdx(DIMBOSS_GUT_MAP_DIR);
        mapUnload(mapDirIndex,DIMBOSS_GUT_MAP_UNLOAD_MASK);
        defragMemory(0);
        break;
      case DIMBOSS_EVENT_LOAD_DIMTOP_ASSETS:
        OSReport(sDIMBossLoadingAssetsForDIMTop);
        mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
        lockLevel(mapDirIndex,0);
        mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(mapDirIndex,DIMTOP_BOOT_DATA_FILE);
        mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(mapDirIndex,DIMTOP_INTRO_DATA_FILE);
        mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(mapDirIndex,DIMTOP_PLATFORM_DATA_FILE);
        mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(mapDirIndex,DIMTOP_LIFT_DATA_FILE);
        mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(mapDirIndex,DIMTOP_SCENE_DATA_FILE);
        mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(mapDirIndex,DIMTOP_STEAM_DATA_FILE);
        mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(mapDirIndex,DIMTOP_BOSS_DATA_FILE_A);
        mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(mapDirIndex,DIMTOP_BOSS_DATA_FILE_B);
        mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(mapDirIndex,DIMTOP_EFFECT_DATA_FILE_A);
        mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(mapDirIndex,DIMTOP_EFFECT_DATA_FILE_B);
        mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(mapDirIndex,DIMTOP_ROOM_DATA_FILE_A);
        mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(mapDirIndex,DIMTOP_ROOM_DATA_FILE_B);
        mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(mapDirIndex,DIMTOP_AUDIO_DATA_FILE_A);
        mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
        mapLoadDataFile(mapDirIndex,DIMTOP_AUDIO_DATA_FILE_B);
        loadWaitStarted = false;
        while (statusFlags = getLoadedFileFlags(0), (statusFlags & 0xffefffff) != 0) {
          padUpdate();
          checkReset();
          if (loadWaitStarted) {
            waitNextFrame();
          }
          loadDataFiles();
          dvdCheckError();
          if (loadWaitStarted) {
            mmFreeTick(0);
            gameTextRun();
            GXFlush_(1,0);
          }
          if (DAT_803dd5d0 != '\0') {
            loadWaitStarted = true;
          }
        }
        clearLoadedFileFlags_blocks1();
        break;
      case DIMBOSS_EVENT_SET_SEQUENCE_FLAG:
        lbl_803DDB80 = lbl_803DDB80 | 0x80000;
        break;
      case DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG:
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
      if ((runtime->eventGameBit != -1) &&
          (statusFlags = GameBit_Get((int)runtime->eventGameBit), statusFlags != 0)) {
        puVar7 = (undefined4 *)*DAT_803dd6d4;
        (*(code *)puVar7[0x16])(animUpdate,(int)*(short *)(iVar12 + 0x2c));
        runtime->eventGameBit = -1;
      }
      bVar1 = runtime->hitReactMode;
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
        if (runtime->hitReactMode == 1) {
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
      runtime->stateFlags |= DIMBOSS_STATE_FLAG_START_MOVE;
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
  if (runtime->phase == DIMBOSS_PHASE_NO_RENDER) {
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
 * Function: DIMboss_update
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
void DIMboss_update(DIMbossObject *obj)
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
      (*(code *)(*lbl_803DCA54 + 0x48))((int)config->animObjId,obj,0xffffffff);
      obj->updateInitialized = 1;
    }
    else {
      if ((runtime->stateFlags & DIMBOSS_STATE_FLAG_START_MOVE) != 0) {
        (*(code *)(*lbl_803DCAB8 + 0x28))
                  (obj,runtime,runtime->moveScratch,(int)runtime->activeMoveId,
                   &runtime->hitReactMode,0,0,0,1);
        runtime->stateFlags &= ~DIMBOSS_STATE_FLAG_START_MOVE;
        obj->objectFlags &= ~8;
        obj->objectFlags |= 0x80;
        gameBitCount = GameBit_Get(0x20c);
        if (gameBitCount >= 3) {
          runtime->phase = DIMBOSS_PHASE_GAMEBIT_COUNT_MET;
          runtime->animMode = 3;
          obj->objectFlags &= ~8;
          GameBit_Set(0x9e,0);
        }
        else {
          runtime->phase = DIMBOSS_PHASE_LAUNCH_LIFT;
          runtime->animMode = 3;
          obj->objectFlags &= ~8;
          topState->launchLift = lbl_803E4C44;
          GameBit_Set(0x9e,1);
        }
      }
      if ((runtime->phase == DIMBOSS_PHASE_START) || (runtime->phase == DIMBOSS_PHASE_NO_RENDER)) {
        if ((topState->stompDustDelay != 0) &&
            (--topState->stompDustDelay == 0)) {
          Obj_BuildWorldTransformMatrix(obj,lbl_803AC9AC,0);
          targetModel = Obj_GetActiveModel(obj);
          ObjModel_EnableDefaultRenderCallback
                    ((double)(obj->modelScale * obj->baseScale),obj,targetModel,lbl_803AC9AC,1);
        }
        if ((topState->steamSfxPending & DIMBOSS_STEAM_SFX_PENDING_FLAG) != 0) {
          getEnvfxAct(0,0,0xdb,0);
          getEnvfxAct(0,0,0xdc,0);
          fn_80089710(7,1,0);
          fn_800894A8((double)lbl_803E4C4C,(double)lbl_803E4C50,(double)lbl_803E4C54,7);
          fn_800895E0(7,0xa0,0xa0,0xff,0x7f,0x28);
          topState->steamSfxPending &= ~DIMBOSS_STEAM_SFX_PENDING_FLAG;
        }
      }
      else {
        if ((runtime->stateFlags & DIMBOSS_STATE_FLAG_TARGET_TRICKY) == 0) {
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
 * Function: DIMboss_init
 * EN v1.0 Address: 0x801BD7AC
 * EN v1.0 Size: 1240b
 * EN v1.1 Address: 0x801BDA04
 * EN v1.1 Size: 860b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMboss_init(DIMbossObject *obj,undefined4 param_2,int param_3)
{
  typedef struct DIMbossLocalVec {
    undefined4 x;
    undefined4 y;
    undefined4 z;
    undefined2 mode;
  } DIMbossLocalVec;

  DIMbossRuntime *runtime;
  DIMbossTopState *topState;
  DIMbossLocalVec localVec;
  undefined4 *localVecSrc;
  u8 *animFlagsByte;
  undefined4 mapDir;
  int animFlags;
  f32 liftHeight;

  runtime = obj->runtime;
  localVecSrc = lbl_802C2338;
  localVec.x = localVecSrc[0];
  localVec.y = localVecSrc[1];
  localVec.z = localVecSrc[2];
  localVec.mode = *(undefined2 *)&localVecSrc[3];
  fn_8005CEF0(0);
  obj->updateMode = 2;
  animFlags = 6;
  if (param_3 != 0) {
    animFlags = (animFlags | 1) & 0xff;
  }
  ((DIMbossAnimSetupFn)(*(code *)(*lbl_803DCAB8 + 0x58)))
      (obj,param_2,runtime,0xc,6,0x102,animFlags,lbl_803E4C28);
  obj->updateState = DIMboss_updateState;
  runtime->phase = DIMBOSS_PHASE_START;
  (*(code *)(*(int *)lbl_803DCA8C + 0x14))(obj,runtime,0);
  runtime->field270 = 0;
  runtime->animMode = 3;
  obj->objectFlags |= 0x88;
  if (GameBit_Get(0x210) != 0) {
    runtime->phase = DIMBOSS_PHASE_RENDER_PAUSE;
    obj->renderPause = 1;
  }
  if (GameBit_Get(0x20e) != 0) {
    runtime->phase = DIMBOSS_PHASE_NO_RENDER;
  }
  topState = runtime->topState;
  liftHeight = lbl_803E4BD8;
  topState->idleLift = liftHeight;
  topState->launchLift = liftHeight;
  obj->activeModelId = -1;
  topState->effect = NULL;
  lbl_803DDB84 = 0;
  lbl_803DDB80 = 0;
  GameBit_Set(0x4e4,1);
  fn_80114F64(obj,lbl_803AC9DC,0xffffd8e4,0x1c71,6);
  fn_80113F9C(lbl_803AC9DC,&localVec,&localVec,6);
  animFlagsByte = (u8 *)((int)lbl_803AC9DC + 0x611);
  *animFlagsByte |= 8;
  *animFlagsByte &= 0xfe;
  topState->steamSfxPending =
      (topState->steamSfxPending & ~DIMBOSS_STEAM_SFX_PENDING_FLAG) |
      DIMBOSS_STEAM_SFX_PENDING_FLAG;
  lbl_803DDB88 = (undefined4)Resource_Acquire(0x5a,1);
  if (GameBit_Get(0x1df) == 0) {
    topState->stompDustDelay = 2;
    topState->introSinkHeight = lbl_803E4C78;
    (*(code *)(*lbl_803DCAAC + 0x50))(DIMBOSS_MAP_DIR,5,1);
  }
  else {
    (*(code *)(*lbl_803DCAAC + 0x50))(DIMBOSS_MAP_DIR,5,0);
  }
  topState->defeatTimer = 0;
  if ((*(code *)(*lbl_803DCAAC + 0x40))(7) == 2) {
    (*(code *)(*lbl_803DCAAC + 0x44))(7,3);
  }
  GameBit_Set(0xefd,1);
  unlockLevel(0,0,1);
  mapDir = mapGetDirIdx(DIMBOSS_MAP_DIR);
  lockLevel(mapDir,1);
  mapDir = mapGetDirIdx(DIMBOSS_GUT_MAP_DIR);
  lockLevel(mapDir,0);
  GameBit_Set(0xcbb,0);
  Music_Trigger(0x36,1);
  GameBit_Set(0xda5,0);
  Music_Trigger(0xd7,0);
  Music_Trigger(0xe0,0);
}

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
  DIMboss_initialiseAnimTables();
}

void dimboss_release(void) {}

#pragma scheduling off
#pragma peephole off
void DIMboss_initialiseAnimTables(void)
{
  void (**table)(void);

  table = lbl_803AD018;
  table[0] = fn_801BB2B0;
  table[1] = fn_801BB1EC;
  table[2] = fn_801BB0D8;
  table[3] = fn_801BAF58;
  table[4] = fn_801BAE00;
  table[5] = fn_801BACB8;
  table[6] = fn_801BAB88;
  table[7] = fn_801BAA84;
  table[8] = fn_801BA958;
  table[9] = fn_801BA880;
  table[10] = fn_801BA780;
  table[11] = fn_801BA654;

  table = lbl_803AD000;
  table[0] = fn_801BA5F0;
  table[1] = fn_801BA5A8;
  table[2] = fn_801BA590;
  table[3] = fn_801BA4B8;
  table[4] = fn_801BA224;
  table[5] = fn_801B9ECC;
}
#pragma peephole reset
#pragma scheduling reset
