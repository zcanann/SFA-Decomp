#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/MMP/mmp_levelcontrol.h"

typedef struct WallanimatorPlacement {
    u8 pad0[0x1C - 0x0];
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} WallanimatorPlacement;


typedef struct WallanimatorState {
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 pad5[0x8 - 0x5];
} WallanimatorState;


typedef struct XyzanimatorState {
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 pad5[0x8 - 0x5];
} XyzanimatorState;



extern undefined4 FUN_80006824();
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017748();
extern void vecRotateZXY(void *in, void *out);
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a90();
extern int getTrickyObject(void);
extern int ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern void objRenderFn_80041018(int obj);
extern int FUN_8005af70();
extern int FUN_8005b398();
extern int mapGetBlock(int blockIdx);
extern uint mapBlockFn_80060678(int *block);
extern void *mapBlockFn_800606ec(int *obj, int idx);
extern void *fn_800606DC(int *obj, int idx);
extern void *fn_800606FC(int *obj, int idx);
extern void *fn_8006070C(int *obj, int idx);
extern int objPosToMapBlockIdx(double x, double y, double z);
extern void mm_free(void *ptr);
extern void DCStoreRange(void *addr, u32 nBytes);
extern int return0_80060B90(void);
extern void *Shader_getLayer(void *shader, int idx);
extern uint FUN_80060058();
extern undefined4 FUN_800600b4();
extern undefined4 FUN_800600c4();
extern int FUN_800600d4();
extern undefined4 FUN_80193a50();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286838();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286884();

extern EffectInterface **gPartfxInterface;
extern f64 DOUBLE_803e4c88;
extern f32 lbl_803E4C68;
extern f32 lbl_803E4C6C;
extern f32 lbl_803E4C70;
extern f32 lbl_803E4C74;
extern f32 lbl_803E4C78;
extern f32 lbl_803E4C7C;
extern f32 lbl_803E4C80;
extern f32 lbl_803E4C94;
extern f32 lbl_803E4C98;
extern f32 lbl_803E3FFC;
extern f32 lbl_803E4000;
extern f32 lbl_803E4008;
extern f64 lbl_803E4010;
extern f32 lbl_803E3FD0;
extern f32 lbl_803E3FD4;
extern f32 lbl_803E3FD8;
extern f32 lbl_803E3FDC;
extern f32 lbl_803E3FE0;
extern f32 lbl_803E3FE4;
extern f32 lbl_803E3FE8;
extern f32 lbl_803E3FEC;
extern f64 lbl_803E3FF0;

/*
 * --INFO--
 *
 * Function: wallanimator_setScale
 * EN v1.0 Address: 0x8019443C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x80194688
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
f32 wallanimator_setScale(int obj,int target)
{
  struct {
    s16 rot[3];
    char pad[6];
    f32 pos[3];
  } effect;
  f32 deltaX;
  f32 deltaY;
  f32 deltaZ;
  f32 out[3];
  int desc;
  int count;
  int *state;
  f32 scale;
  f32 kD0;
  f32 kD4;
  f32 kD8;
  f32 kDC;

  desc = *(int *)&((GameObject *)obj)->anim.placementData;
  count = 6;
  kD0 = lbl_803E3FD0;
  kD4 = lbl_803E3FD4;
  kD8 = lbl_803E3FD8;
  kDC = lbl_803E3FDC;
  do {
    out[0] = kD0 * (f32)(int)randomGetRange(-0x64,0x64);
    out[1] = kD4;
    out[2] = kD4;
    effect.rot[2] = (s16)randomGetRange(-0x7fff,0x8000);
    effect.rot[1] = 0;
    effect.rot[0] = 0;
    vecRotateZXY(effect.rot,out);
    out[2] -= kD8;
    vecRotateZXY((void *)obj,out);
    effect.rot[2] = ((WallanimatorPlacement *)desc)->unk1C;
    effect.rot[0] = *(s16 *)obj;
    effect.pos[0] = ((GameObject *)obj)->anim.worldPosX + out[0];
    effect.pos[1] = kDC + (((GameObject *)obj)->anim.worldPosY + out[1]);
    effect.pos[2] = ((GameObject *)obj)->anim.worldPosZ + out[2];
    (*gPartfxInterface)->spawnObject((void *)obj, 0xca, effect.rot, 0x200001, -1, NULL);
    (*gPartfxInterface)->spawnObject((void *)obj, 0xcb, effect.rot, 0x200001, -1, NULL);
    count--;
  } while (count != 0);

  state = ((GameObject *)obj)->extra;
  deltaY = *(f32 *)(target + 0x10) - ((GameObject *)obj)->anim.localPosY;
  if ((lbl_803E3FE0 > deltaY) || (lbl_803E3FE4 < deltaY)) {
    scale = lbl_803E3FD4;
  }
  else {
    deltaX = *(f32 *)(target + 0xc) - ((GameObject *)obj)->anim.localPosX;
    deltaZ = *(f32 *)(target + 0x14) - ((GameObject *)obj)->anim.localPosZ;
    if (deltaX * deltaX + deltaZ * deltaZ > lbl_803E3FE8) {
      scale = lbl_803E3FD4;
    }
    else {
      *state += 0x3c;
      scale = (f32)*state / lbl_803E3FEC;
    }
  }
  return scale;
}

/*
 * --INFO--
 *
 * Function: FUN_80194544
 * EN v1.0 Address: 0x80194544
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801947D4
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: objFn_801948c0
 * EN v1.0 Address: 0x801948C0
 * EN v1.0 Size: 164b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
f32 objFn_801948c0(u8 *obj,u8 coord)
{
  u8 *state;

  if (obj == NULL || (state = ((GameObject *)obj)->extra, state == NULL)) {
    return lbl_803E4000;
  }
  switch (coord) {
    case 1:
      return ((GameObject *)obj)->anim.localPosX + *(f32 *)(state + 0x40);
    case 2:
      return *(f32 *)(state + 0x40);
    case 3:
      return ((GameObject *)obj)->anim.localPosY + *(f32 *)(state + 0x44);
    case 4:
      return *(f32 *)(state + 0x44);
    case 5:
      return ((GameObject *)obj)->anim.localPosZ + *(f32 *)(state + 0x48);
    case 6:
      return *(f32 *)(state + 0x48);
  }
  return lbl_803E4000;
}

/*
 * --INFO--
 *
 * Function: FUN_80194a70
 * EN v1.0 Address: 0x80194A70
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x80194E3C
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80194a70(int param_1,byte param_2)
{
  int iVar1;
  
  if ((param_1 == 0) || (iVar1 = *(int *)&((GameObject *)param_1)->extra, iVar1 == 0)) {
    return (double)lbl_803E4C98;
  }
  if (param_2 == 4) {
    return (double)*(float *)(iVar1 + 0x44);
  }
  if (param_2 < 4) {
    if (param_2 == 2) {
      return (double)*(float *)(iVar1 + 0x40);
    }
    if (1 < param_2) {
      return (double)(((GameObject *)param_1)->anim.localPosY + *(float *)(iVar1 + 0x44));
    }
    if (param_2 != 0) {
      return (double)(((GameObject *)param_1)->anim.localPosX + *(float *)(iVar1 + 0x40));
    }
  }
  else {
    if (param_2 == 6) {
      return (double)*(float *)(iVar1 + 0x48);
    }
    if (param_2 < 6) {
      return (double)(((GameObject *)param_1)->anim.localPosZ + *(float *)(iVar1 + 0x48));
    }
  }
  return (double)lbl_803E4C98;
}

/*
 * --INFO--
 *
 * Function: FUN_80194b10
 * EN v1.0 Address: 0x80194B10
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x80194EE0
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


typedef struct MapBlockHdr {
  u16 start;
  u16 pad1[2];
  s16 posA;
  s16 posB;
} MapBlockHdr;
typedef struct VertexS16 {
  s16 x;
  s16 y;
  s16 z;
} VertexS16;
typedef struct EdgeVerts {
  u8 pad[6];
  s16 a;
  s16 b;
  s16 c;
  s16 d;
  s16 e;
  s16 f;
} EdgeVerts;

#pragma scheduling off
#pragma peephole off
void fn_80194964(int obj,int state,int block)
{
  ushort blockEnd;
  ushort *mapBlock;
  int blockLayer;
  int coordOffset;
  VertexS16 *vtx;
  uint triangle;
  int triangleOffset;
  int edge;
  int edgeOffset;
  int blockIndex;

  triangleOffset = 0;
  coordOffset = 0;
  edgeOffset = 0;
  for (blockIndex = 0; blockIndex < (int)(uint)*(ushort *)(block + 0x9a); blockIndex++) {
    mapBlock = (ushort *)mapBlockFn_800606ec((int *)block,blockIndex);
    blockLayer = mapBlockFn_80060678((int *)mapBlock);
    if ((int)*(char *)(obj + 0x28) == blockLayer) {
      *(s16 *)(*(int *)(state + 0x10) + coordOffset) = ((MapBlockHdr *)mapBlock)->posA;
      *(s16 *)(*(int *)(state + 0x14) + coordOffset) = ((MapBlockHdr *)mapBlock)->posB;
      coordOffset += 2;
      blockEnd = mapBlock[10];
      triangle = (uint)*mapBlock;
      edgeOffset = triangleOffset;
      for (; (int)triangle < (int)(uint)blockEnd; triangle++) {
        mapBlock = (ushort *)fn_800606DC((int *)block,triangle);
        vtx = (VertexS16 *)(*(int *)(block + 0x58) + (uint)*mapBlock * 6);
        *(s16 *)(*(int *)(state + 0xc) + edgeOffset) = vtx->x;
        *(s16 *)(*(int *)(state + 0xc) + edgeOffset + 2) = vtx->y;
        *(s16 *)(*(int *)(state + 0xc) + edgeOffset + 4) = vtx->z;
        vtx = (VertexS16 *)(*(int *)(block + 0x58) + (uint)mapBlock[1] * 6);
        *(s16 *)(*(int *)(state + 0xc) + edgeOffset + 6) = vtx->x;
        *(s16 *)(*(int *)(state + 0xc) + edgeOffset + 8) = vtx->y;
        *(s16 *)(*(int *)(state + 0xc) + edgeOffset + 10) = vtx->z;
        vtx = (VertexS16 *)(*(int *)(block + 0x58) + (uint)mapBlock[2] * 6);
        *(s16 *)(*(int *)(state + 0xc) + edgeOffset + 0xc) = vtx->x;
        *(s16 *)(*(int *)(state + 0xc) + edgeOffset + 0xe) = vtx->y;
        *(s16 *)(*(int *)(state + 0xc) + edgeOffset + 0x10) = vtx->z;
        edgeOffset += 0x12;
        triangleOffset += 0x12;
      }
    }
  }
  edge = 0;
  for (edgeOffset = 0; edgeOffset < (int)(uint)*(byte *)(block + 0xa1); edgeOffset++) {
    blockIndex = (int)fn_800606FC((int *)block,edgeOffset);
    *(s16 *)(*(int *)(state + 0x28) + edge) = ((EdgeVerts *)blockIndex)->a;
    *(s16 *)(*(int *)(state + 0x2c) + edge) = ((EdgeVerts *)blockIndex)->d;
    *(s16 *)(*(int *)(state + 0x30) + edge) = ((EdgeVerts *)blockIndex)->b;
    *(s16 *)(*(int *)(state + 0x34) + edge) = ((EdgeVerts *)blockIndex)->e;
    *(s16 *)(*(int *)(state + 0x38) + edge) = ((EdgeVerts *)blockIndex)->c;
    *(s16 *)(*(int *)(state + 0x3c) + edge) = ((EdgeVerts *)blockIndex)->f;
    edge += 2;
  }
}

void fn_80194C40(undefined4 def,int state,int block)
{
  ushort blockEnd;
  f32 scale;
  int edgeData;
  ushort *mapBlock;
  int blockLayer;
  void *shader;
  VertexS16 *vtx;
  uint triangle;
  int triangleOffset;
  int vertexOffset;
  int coordOffset;
  int blockIndex;
  int edgeIndex;
  int edgeOffset;
  int vertexIndex;

  triangleOffset = 0;
  coordOffset = triangleOffset;
  vertexOffset = coordOffset;
  for (blockIndex = 0; blockIndex < (int)(uint)*(ushort *)(block + 0x9a); blockIndex++) {
    mapBlock = (ushort *)mapBlockFn_800606ec((int *)block,blockIndex);
    blockLayer = mapBlockFn_80060678((int *)mapBlock);
    if ((int)*(char *)(def + 0x28) == blockLayer) {
      ((MapBlockHdr *)mapBlock)->posA = (int)(*(float *)(state + 0x44) +
                                  (f32)*(s16 *)(*(int *)(state + 0x10) + coordOffset));
      ((MapBlockHdr *)mapBlock)->posB = (int)(*(float *)(state + 0x44) +
                                  (f32)*(s16 *)(*(int *)(state + 0x14) + coordOffset));
      coordOffset += 2;
      blockEnd = mapBlock[10];
      scale = lbl_803E4008;
      triangle = (uint)*mapBlock;
      edgeOffset = vertexOffset;
      for (; (int)triangle < (int)(uint)blockEnd; triangle++) {
        mapBlock = (ushort *)fn_800606DC((int *)block,triangle);
        vertexIndex = edgeOffset;
        for (edgeIndex = 3; edgeIndex != 0; edgeIndex--) {
          vtx = (VertexS16 *)(*(int *)(block + 0x58) + (uint)*mapBlock * 6);
          vtx->x = (int)(scale * *(float *)(state + 0x40) +
                                (f32)*(s16 *)(*(int *)(state + 0xc) + edgeOffset));
          vtx->y = (int)(scale * *(float *)(state + 0x44) +
                                (f32)*(s16 *)(*(int *)(state + 0xc) + edgeOffset + 2));
          vtx->z = (int)(scale * *(float *)(state + 0x48) +
                                (f32)*(s16 *)(*(int *)(state + 0xc) + edgeOffset + 4));
          edgeOffset += 6;
          vertexIndex += 6;
          vertexOffset += 6;
          mapBlock++;
        }
        edgeOffset = vertexIndex;
      }
    }
  }
  DCStoreRange(*(void **)(block + 0x58),(uint)*(ushort *)(block + 0x90) * 6);
  edgeData = 0;
  for (edgeOffset = 0; edgeOffset < (int)(uint)*(byte *)(block + 0xa1); edgeOffset++) {
    vertexOffset = (int)fn_800606FC((int *)block,edgeOffset);
    shader = fn_8006070C((int *)block,*(byte *)(vertexOffset + 0x13));
    shader = Shader_getLayer(shader,0);
    scale = lbl_803E4008;
    if ((uint)*(byte *)((int)shader + 5) == (int)*(char *)(def + 0x28)) {
      ((EdgeVerts *)vertexOffset)->a = (int)(scale * *(float *)(state + 0x40) +
            (f32)*(s16 *)(*(int *)(state + 0x28) + edgeData));
      ((EdgeVerts *)vertexOffset)->d = (int)(scale * *(float *)(state + 0x40) +
            (f32)*(s16 *)(*(int *)(state + 0x2c) + edgeData));
      ((EdgeVerts *)vertexOffset)->b = (int)(scale * *(float *)(state + 0x44) +
            (f32)*(s16 *)(*(int *)(state + 0x30) + edgeData));
      ((EdgeVerts *)vertexOffset)->e = (int)(scale * *(float *)(state + 0x44) +
            (f32)*(s16 *)(*(int *)(state + 0x34) + edgeData));
      ((EdgeVerts *)vertexOffset)->c = (int)(scale * *(float *)(state + 0x48) +
            (f32)*(s16 *)(*(int *)(state + 0x38) + edgeData));
      ((EdgeVerts *)vertexOffset)->f = (int)(scale * *(float *)(state + 0x48) +
            (f32)*(s16 *)(*(int *)(state + 0x3c) + edgeData));
    }
    edgeData += 2;
  }
  *(int *)block = return0_80060B90();
}

/*
 * --INFO--
 *
 * Function: wallanimator_getExtraSize
 * EN v1.0 Address: 0x8019469C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int wallanimator_getExtraSize(void)
{
  return 8;
}

/*
 * --INFO--
 *
 * Function: xyzanimator_getExtraSize
 * EN v1.0 Address: 0x80194B5C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int xyzanimator_getExtraSize(void)
{
  return 0x50;
}

void xyzanimator_free(int obj,int param_2)
{
  int block;
  int state;
  undefined4 def;
  f32 zero;

  zero = lbl_803E4000;
  state = *(int *)&((GameObject *)obj)->extra;
  def = *(undefined4 *)&((GameObject *)obj)->anim.placementData;
  *(float *)(state + 0x40) = lbl_803E4000;
  *(float *)(state + 0x44) = zero;
  *(float *)(state + 0x48) = zero;
  if (param_2 == 0) {
    block = objPosToMapBlockIdx((double)((GameObject *)obj)->anim.localPosX,(double)((GameObject *)obj)->anim.localPosY,
                                (double)((GameObject *)obj)->anim.localPosZ);
    block = mapGetBlock(block);
    if ((block != 0) && (*(int *)(state + 4) != 0)) {
      fn_80194C40(def,state,block);
    }
  }
  if (*(int *)(state + 0xc) != 0) {
    mm_free(*(void **)(state + 0xc));
  }
  ObjGroup_RemoveObject(obj,0x51);
  return;
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3FF8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4004;
void wallanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3FF8); }
void xyzanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4004); }

void wallanimator_free(int obj) {
    ObjGroup_RemoveObject(obj, WALLANIMATOR_GROUP_PRIMARY);
    ObjGroup_RemoveObject(obj, WALLANIMATOR_GROUP_SECONDARY);
}

void wallanimator_update(int obj)
{
  int nearby;
  int *state;
  int desc;
  int tricky;
  float nearestDistance[4];

  state = ((GameObject *)obj)->extra;
  desc = *(int *)&((GameObject *)obj)->anim.placementData;
  *(byte *)&((GameObject *)obj)->anim.resetHitboxMode = *(byte *)&((GameObject *)obj)->anim.resetHitboxMode | 8;

  if (((u32)*(u8 *)(state + 1) >> 7) != 0) {
    return;
  }

  if (*state >= WALLANIMATOR_DONE_TIMER) {
    u8 activeBit = 1;
    *(u8 *)(state + 1) =
        (*(u8 *)(state + 1) & ~WALLANIMATOR_RUNTIME_ACTIVE_FLAG) | (activeBit << 7);
    GameBit_Set((int)*(short *)(desc + 0x18),1);
    Sfx_PlayFromObject(obj,WALLANIMATOR_COMPLETE_SFX);
    return;
  }

  tricky = getTrickyObject();
  if ((void *)tricky != NULL) {
    nearestDistance[0] = lbl_803E3FFC;
    nearby = ObjGroup_FindNearestObject(WALLANIMATOR_NEARBY_GROUP,obj,nearestDistance);
    if ((void *)nearby == NULL) {
      *(byte *)&((GameObject *)obj)->anim.resetHitboxMode = *(byte *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x10;
      *(byte *)&((GameObject *)obj)->anim.resetHitboxMode = *(byte *)&((GameObject *)obj)->anim.resetHitboxMode & ~8;
      if ((*(byte *)&((GameObject *)obj)->anim.resetHitboxMode & 4) != 0) {
        (*(code *)(**(int **)(tricky + 0x68) + 0x28))(tricky,obj,1,1);
      }
      objRenderFn_80041018(obj);
    }
  }
  else {
    *(byte *)&((GameObject *)obj)->anim.resetHitboxMode = *(byte *)&((GameObject *)obj)->anim.resetHitboxMode | 0x10;
  }
}

void wallanimator_init(s16* obj, s16* p2)
{
    register int* state = ((GameObject *)obj)->extra;

    *obj = (s16)p2[0x24 / 2];
    ObjGroup_AddObject((int)obj, WALLANIMATOR_GROUP_PRIMARY);
    ObjGroup_AddObject((int)obj, WALLANIMATOR_GROUP_SECONDARY);
    if (GameBit_Get((int)p2[0x18 / 2]) != 0) {
        ((WallanimatorState *)state)->unk4 |= WALLANIMATOR_RUNTIME_ACTIVE_FLAG;
        *state = WALLANIMATOR_DONE_TIMER;
    }
}
