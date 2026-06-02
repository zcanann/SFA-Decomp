#include "ghidra_import.h"
#include "main/dll/door.h"
#include "main/dll/fruit.h"
#include "main/dll/zBomb.h"

extern undefined4 streamFn_8000a380();
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern void Model_GetVertexPosition(int modelData,int vertexIndex,float *outPosition);
extern void objfx_spawnArcedBurst(int obj,int enabled,f32 radius,int particleKind,
                                   int particleId,int lifetime,f32 scaleX,f32 scaleY,
                                   f32 scaleZ,void *args,int arg9);

extern undefined4* gPathControlInterface;
extern s32 lbl_80329B78[];
extern f32 timeDelta;
extern f32 lbl_803E648C;
extern f32 lbl_803E6494;
extern f32 lbl_803E64AC;
extern f32 lbl_803E64B0;
extern f32 lbl_803E64C4;
extern f32 lbl_803E64C8;
extern f32 lbl_803E64CC;
extern f32 lbl_803E64D0;
extern f32 lbl_803E64D4;

/*
 * --INFO--
 *
 * Function: dfptargetblock_update
 * EN v1.0 Address: 0x80208B70
 * EN v1.0 Size: 524b
 */
#pragma scheduling off
#pragma peephole off
void dfptargetblock_update(DfpTargetBlockObject *obj)
{
  u8 cVar1;
  undefined uVar3;
  DfpTargetBlockState *state;
  DfpTargetBlockHome *home;
  float buf[6];

  state = (DfpTargetBlockState *)obj->state;
  home = obj->home;
  if (obj->objectType == DFPTARGETBLOCK_HOME_OBJECT_TYPE) {
    buf[3] = lbl_803E648C;
    buf[4] = lbl_803E64C4;
    buf[5] = lbl_803E648C;
    objfx_spawnArcedBurst((int)obj,5,lbl_803E64C8,1,2,0x32,lbl_803E64C4,
                 lbl_803E64C4,lbl_803E64B0,buf,0);
  }
  else {
    if (state->completionSfxReady == '\0') {
      uVar3 = GameBit_Get((int)state->completionSfxId);
      state->completionSfxReady = uVar3;
    }
    if (state->stateSfxReady == '\0') {
      uVar3 = GameBit_Get((int)state->stateSfxId);
      state->stateSfxReady = uVar3;
    }
    if (((state->completionSfxReady == '\0') && (state->stateSfxReady != '\0')) &&
       (cVar1 = state->mode, cVar1 != DFPTARGETBLOCK_MODE_SETTLED)) {
      if ((cVar1 == DFPTARGETBLOCK_MODE_RAISING) || (cVar1 == DFPTARGETBLOCK_MODE_RESETTING)) {
        if (obj->y <= home->y) {
          obj->y = obj->y + timeDelta;
          if (obj->y >= home->y) {
            obj->y = home->y;
            state->mode = DFPTARGETBLOCK_MODE_ACTIVE;
          }
        }
      }
      else if (cVar1 == DFPTARGETBLOCK_MODE_LOWERING) {
        if (obj->y >= home->y - lbl_803E64AC) {
          obj->y = lbl_803E6494 * timeDelta + obj->y;
          if (obj->y <= home->y - lbl_803E64AC) {
            obj->y = home->y - lbl_803E64AC;
            state->mode = DFPTARGETBLOCK_MODE_SETTLED;
            GameBit_Set((int)state->completionSfxId,1);
          }
        }
      }
      else if (state->controlId != 0) {
        (*(code *)(*gPathControlInterface + 0x10))((double)timeDelta,obj);
        (*(code *)(*gPathControlInterface + 0x14))(obj,state->controlId);
        (*(code *)(*gPathControlInterface + 0x18))((double)timeDelta,obj,state->controlId);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dfptargetblock_init
 * EN v1.0 Address: 0x80208D7C
 * EN v1.0 Size: 600b
 */
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dfptargetblock_init(DfpTargetBlockObject *obj,int param_2)
{
  char cVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  undefined uVar5;
  int iVar6;
  int iVar8;
  DfpTargetBlockState *state;
  int iVar7;
  double dVar11;
  DfpTargetBlockPoint point;

  state = (DfpTargetBlockState *)obj->state;
  iVar7 = **(int **)(*(int *)((u8 *)obj + 0x7c) + *(char *)((u8 *)obj + 0xad) * 4);
  *(ushort *)((u8 *)obj + 0xb0) = *(ushort *)((u8 *)obj + 0xb0) | 0x4000;
  if (obj->objectType == DFPTARGETBLOCK_HOME_OBJECT_TYPE) {
    lbl_80329B78[0] = (int)obj->x;
    lbl_80329B78[1] = (int)obj->y;
    lbl_80329B78[2] = (int)obj->z;
  }
  else {
    dVar11 = (double)lbl_803E64CC;
    for (iVar8 = 0; iVar8 < (int)(uint)*(ushort *)(iVar7 + 0xe4); iVar8 = iVar8 + 1) {
      Model_GetVertexPosition(iVar7,iVar8,&point.x);
      if ((double)point.y < dVar11) {
        dVar11 = (double)point.y;
      }
    }
    for (iVar8 = 0; iVar8 < (int)(uint)*(ushort *)(iVar7 + 0xe4); iVar8 = iVar8 + 1) {
      Model_GetVertexPosition(iVar7,iVar8,&point.x);
      if ((double)point.y == dVar11) {
        bVar2 = false;
        cVar1 = state->floorPointCount;
        for (iVar6 = 0; iVar6 < cVar1; iVar6 = iVar6 + 1) {
          iVar4 = (int)state + iVar6 * 12;
          if ((point.x == *(float *)(iVar4 + 4)) && (point.z == *(float *)(iVar4 + 12))) {
            bVar2 = true;
            iVar6 = (int)cVar1;
          }
        }
        if (!bVar2) {
          iVar3 = (int)state->floorPointCount;
          state->floorPoints[iVar3].x = point.x;
          state->floorPoints[(int)state->floorPointCount].y = point.y;
          state->floorPoints[(int)state->floorPointCount].z = point.z;
          state->floorPointCount = state->floorPointCount + '\x01';
        }
      }
    }
    state->mode = DFPTARGETBLOCK_MODE_RAISING;
    obj->y = obj->y - lbl_803E64AC;
    state->completionSfxId = *(short *)(param_2 + 0x1e);
    state->stateSfxId = *(short *)(param_2 + 0x20);
    uVar5 = GameBit_Get((int)state->completionSfxId);
    state->completionSfxReady = uVar5;
    uVar5 = GameBit_Get((int)state->stateSfxId);
    state->stateSfxReady = uVar5;
    if (state->completionSfxReady != '\0') {
      obj->x = obj->x + lbl_803E64D0;
      obj->z = obj->z + lbl_803E64D4;
      state->mode = DFPTARGETBLOCK_MODE_SETTLED;
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

void dfptargetblock_release(void)
{
}

void dfptargetblock_initialise(void)
{
}

s32 lbl_80329B78[] = {0, 0, 0};

ObjectDescriptor10WithPadding gDfptargetblockObjDescriptor = {
    {
        0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)dfptargetblock_initialise,
        (ObjectDescriptorCallback)dfptargetblock_release,
        0,
        (ObjectDescriptorCallback)dfptargetblock_init,
        (ObjectDescriptorCallback)dfptargetblock_update,
        (ObjectDescriptorCallback)dfptargetblock_hitDetect,
        (ObjectDescriptorCallback)dfptargetblock_render,
        (ObjectDescriptorCallback)dfptargetblock_free,
        (ObjectDescriptorCallback)dfptargetblock_getObjectTypeId,
        dfptargetblock_getExtraSize,
    },
    0,
};
