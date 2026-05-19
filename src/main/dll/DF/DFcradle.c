#include "ghidra_import.h"
#include "main/dll/DF/DFcradle.h"

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void CameraShake_Start(f32 magnitude, f32 duration, f32 param_3);
extern void doRumble(f32 val);
extern void *memcpy(void *dst, const void *src, u32 size);
extern void modelLightStruct_setColorsA8AC(int light, int r, int g, int b, int a);
extern void lightSetFieldBC_8001db14(int light, int value);
extern void modelLightStruct_setField50(int light, int value);
extern void lightFn_8001db6c(f32 value, int light, int which);
extern void lightDistAttenFn_8001dc38(f32 min, f32 max, int light);
extern void ModelLightStruct_free(void *light);
extern int objCreateLight(int obj, int param_2);
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern f32 Vec_distance(float *posA, float *posB);
extern u32 randomGetRange(int min, int max);
extern int Obj_GetPlayerObject(void);
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjGroup_RemoveObject(int obj, int groupId);
extern undefined4 ObjGroup_AddObject(int obj, int groupId);
extern void* ObjGroup_GetObjects();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810ec();
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);

extern undefined4 DAT_80326928;
extern undefined4 DAT_8032692a;
extern undefined4 DAT_8032692c;
extern undefined4 DAT_8032692e;
extern undefined4 DAT_80326930;
extern undefined4 DAT_80326932;
extern f32 lbl_80325D68[];
extern undefined4* DAT_803dd6f8;
extern void *pDll_expgfx;
extern f64 DOUBLE_803e5a28;
extern f64 lbl_803E4DC8;
extern f32 timeDelta;
extern f32 lbl_803E5A24;
extern f32 lbl_803E4DA0;
extern f32 lbl_803E4DA4;
extern f32 lbl_803E4DA8;
extern f32 lbl_803E4DAC;
extern f32 lbl_803E4DB0;
extern f32 lbl_803E4DB4;
extern f32 lbl_803E4DB8;
extern f32 lbl_803E4DBC;
extern f32 lbl_803E4DC0;
extern f32 lbl_803E4DD0;
extern f32 lbl_803E4DD4;
extern f64 lbl_803E4DD8;
extern f32 lbl_803E4DE0;
extern f32 lbl_803E4DE4;
extern f32 lbl_803E4DE8;
extern f64 lbl_803E4DF0;

/*
 * --INFO--
 *
 * Function: dimbossfire_update
 * EN v1.0 Address: 0x801C053C
 * EN v1.0 Size: 1136b
 * EN v1.1 Address: 0x801C0AF0
 * EN v1.1 Size: 1136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossfire_update(int param_1)
{
  uint uVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  byte *pbVar5;
  float fVar6;
  
  pbVar5 = *(byte **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if ((int)*(short *)(iVar4 + 0x20) == 0xffffffff) {
    *(float *)(pbVar5 + 0xc) = *(float *)(pbVar5 + 0xc) - timeDelta;
    if (*(float *)(pbVar5 + 0xc) <= lbl_803E4DA0) {
      uVar1 = randomGetRange(0xf0,0x1e0);
      *(float *)(pbVar5 + 0xc) =
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - lbl_803E4DC8);
      *pbVar5 = *pbVar5 | 1;
      *(float *)(pbVar5 + 4) = lbl_80325D68[pbVar5[1]];
      *(float *)(pbVar5 + 8) = *(float *)(pbVar5 + 4);
      pbVar5[1] = pbVar5[1] + 1;
      if (pbVar5[1] >= 10) {
        pbVar5[1] = 0;
      }
    }
  }
  else {
    uVar1 = GameBit_Get((int)*(short *)(iVar4 + 0x20));
    if (uVar1 != 0) {
      GameBit_Set((int)*(short *)(iVar4 + 0x20),0);
      *pbVar5 = *pbVar5 | 1;
      *(float *)(pbVar5 + 4) = lbl_80325D68[pbVar5[1]];
      *(float *)(pbVar5 + 8) = *(float *)(pbVar5 + 4);
      pbVar5[1] = pbVar5[1] + 1;
      if (pbVar5[1] >= 10) {
        pbVar5[1] = 0;
      }
    }
  }
  if (*(float *)(pbVar5 + 4) > lbl_803E4DA0) {
    if ((*pbVar5 & 1) != 0) {
      *pbVar5 = *pbVar5 & 0xfe;
      ObjHits_SetHitVolumeSlot(param_1,9,1,0);
      ObjHitbox_SetSphereRadius(param_1,0xf);
      ObjHits_EnableObject(param_1);
      if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
        iVar3 = 0;
        do {
          if (*(short *)(iVar4 + 0x1a) == 0) {
            (*(void (***)(int, int, int, int, int, int))pDll_expgfx)[2](param_1,0x4cc,0,2,0xffffffff,0);
          }
          else {
            (*(void (***)(int, int, int, int, int, int))pDll_expgfx)[2](param_1,0x4c9,0,2,0xffffffff,0);
          }
          iVar3 = iVar3 + 1;
        } while (iVar3 < 0x32);
      }
      iVar3 = Obj_GetPlayerObject();
      if ((iVar3 != 0) && ((*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0)) {
        fVar6 = Vec_distance((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18));
        if (fVar6 <= lbl_803E4DA4) {
          fVar6 = lbl_803E4DA8 - fVar6 / lbl_803E4DA4;
          CameraShake_Start(lbl_803E4DAC * fVar6,lbl_803E4DAC,lbl_803E4DB0);
          doRumble(lbl_803E4DB4 * fVar6);
        }
      }
      if (*(int *)(pbVar5 + 0x10) == 0) {
        piVar2 = (int *)objCreateLight(param_1,1);
        *(int **)(pbVar5 + 0x10) = piVar2;
        if (*(int *)(pbVar5 + 0x10) != 0) {
          modelLightStruct_setField50(*(int *)(pbVar5 + 0x10),2);
          lightSetFieldBC_8001db14(*(int *)(pbVar5 + 0x10),1);
          if (*(short *)(iVar4 + 0x1a) == 0) {
            modelLightStruct_setColorsA8AC(*(int *)(pbVar5 + 0x10),0x7f,0xff,0,0);
          }
          else {
            modelLightStruct_setColorsA8AC(*(int *)(pbVar5 + 0x10),0xff,0x7f,0,0);
          }
          lightDistAttenFn_8001dc38(lbl_803E4DB8,lbl_803E4DBC,*(int *)(pbVar5 + 0x10));
          lightFn_8001db6c(lbl_803E4DA0,*(int *)(pbVar5 + 0x10),1);
          lightFn_8001db6c(*(float *)(pbVar5 + 4) / lbl_803E4DC0,*(int *)(pbVar5 + 0x10),0);
        }
      }
      Sfx_PlayFromObject(param_1,0x188);
    }
    *(float *)(pbVar5 + 4) = *(float *)(pbVar5 + 4) - timeDelta;
    if (*(float *)(pbVar5 + 4) > lbl_803E4DA0) {
      (*(void (***)(int, int, int, int, int, int))pDll_expgfx)[2](param_1,0x4ca,0,2,0xffffffff,0);
      if (*(short *)(iVar4 + 0x1a) == 0) {
        (*(void (***)(int, int, int, int, int, int))pDll_expgfx)[2](param_1,0x4cd,0,2,0xffffffff,0);
      }
      else {
        (*(void (***)(int, int, int, int, int, int))pDll_expgfx)[2](param_1,0x4cb,0,2,0xffffffff,0);
      }
    }
    else {
      *(float *)(pbVar5 + 4) = lbl_803E4DA0;
      if (*(uint *)(pbVar5 + 0x10) != 0) {
        ModelLightStruct_free(*(void **)(pbVar5 + 0x10));
        *(int *)(pbVar5 + 0x10) = 0;
      }
      ObjHits_SetHitVolumeSlot(param_1,0,0,0);
      ObjHitbox_SetSphereRadius(param_1,0);
      ObjHits_DisableObject(param_1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dimbossfire_init
 * EN v1.0 Address: 0x801C09AC
 * EN v1.0 Size: 172b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossfire_init(int obj,undefined4 param_2,int param_3)
{
  uint uVar1;
  undefined uVar2;
  int state;

  state = *(int *)(obj + 0xb8);
  ObjHits_SetHitVolumeSlot(obj,0,0,0);
  ObjHitbox_SetSphereRadius(obj,0);
  ObjHits_DisableObject(obj);
  if (param_3 == 0) {
    uVar1 = randomGetRange(0xf0,0x1e0);
    *(float *)(state + 0xc) =
         (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - lbl_803E4DC8);
    uVar2 = randomGetRange(0,9);
    *(undefined *)(state + 1) = uVar2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dimbossfire_release
 * EN v1.0 Address: 0x801C0A58
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C0B30
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossfire_release(void)
{
}

/*
 * --INFO--
 *
 * Function: dimbossfire_initialise
 * EN v1.0 Address: 0x801C0A5C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C0B34
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossfire_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: ccriverflow_getExtraSize
 * EN v1.0 Address: 0x801C0A60
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801C0B38
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ccriverflow_getExtraSize(void)
{
  return 1;
}

/*
 * --INFO--
 *
 * Function: ccriverflow_free
 * EN v1.0 Address: 0x801C0A68
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ccriverflow_free(int obj)
{
  if (**(byte **)(obj + 0xb8) != 0) {
    ObjGroup_RemoveObject(obj,0x14);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: ccriverflow_render
 * EN v1.0 Address: 0x801C0A9C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C0B88
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ccriverflow_render(void)
{
}

/*
 * --INFO--
 *
 * Function: ccriverflow_update
 * EN v1.0 Address: 0x801C0AA0
 * EN v1.0 Size: 148b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ccriverflow_update(int obj)
{
  uint uVar1;
  byte *state;

  if (*(short *)(*(int *)(obj + 0x4c) + 0x1c) != -1) {
    state = *(byte **)(obj + 0xb8);
    uVar1 = GameBit_Get((int)*(short *)(*(int *)(obj + 0x4c) + 0x1c));
    if (uVar1 != 0) {
      if (*state != 0) {
        *state = 0;
        ObjGroup_RemoveObject(obj,0x14);
      }
    }
    else if (*state == 0) {
      *state = 1;
      ObjGroup_AddObject(obj,0x14);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: ccriverflow_init
 * EN v1.0 Address: 0x801C0B34
 * EN v1.0 Size: 196b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ccriverflow_init(short *obj,int params)
{
  if (*(short *)(params + 0x1c) == -1) {
    ObjGroup_AddObject((int)obj,0x14);
    **(undefined **)(obj + 0x5c) = 1;
  }
  *obj = (ushort)*(byte *)(params + 0x18) << 8;
  *(undefined4 *)(obj + 4) = *(undefined4 *)(*(int *)(obj + 0x28) + 4);
  *(float *)(obj + 4) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(params + 0x19)) - lbl_803E4DD8) *
       lbl_803E4DD0 + *(float *)(obj + 4);
  if (*(float *)(obj + 4) < lbl_803E4DD4) {
    *(float *)(obj + 4) = lbl_803E4DD4;
  }
  if (*(byte *)(params + 0x1a) == 0) {
    *(undefined *)(params + 0x1a) = 0xff;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_801C0BF8
 * EN v1.0 Address: 0x801C0BF8
 * EN v1.0 Size: 616b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801C0BF8(void *templateData,int angle,float *startNode,float *endNode,short *out)
{
  int startX;
  int startY;
  int startZ;
  int endX;
  int endY;
  int endZ;
  int i;
  short *vertex;
  float angleRadians;
  double vertexX;

  startX = (int)(lbl_803E4DE0 * startNode[0]);
  startY = (int)(lbl_803E4DE0 * startNode[1]);
  startZ = (int)(lbl_803E4DE0 * startNode[2]);
  endX = (int)(lbl_803E4DE0 * endNode[0]);
  endY = (int)(lbl_803E4DE0 * endNode[1]);
  endZ = (int)(lbl_803E4DE0 * endNode[2]);
  memcpy(out,templateData,0x60);

  angleRadians = (lbl_803E4DE4 * (float)(short)angle) / lbl_803E4DE8;
  vertex = out;
  for (i = 0; i < 6; i++) {
    vertexX = (float)(int)*vertex;
    *vertex = (short)(int)(vertexX * sin(angleRadians));
    vertex[2] = (short)(int)(-vertexX * fn_80293E80(angleRadians));
    vertex += 8;
  }

  out[0] += startX;
  out[1] += startY;
  out[2] += startZ;
  out[0x18] += endX;
  out[0x19] += endY;
  out[0x1a] += endZ;
  out[8] += startX;
  out[9] += startY;
  out[10] += startZ;
  out[0x20] += endX;
  out[0x21] += endY;
  out[0x22] += endZ;
  out[0x10] += startX;
  out[0x11] += startY;
  out[0x12] += startZ;
  out[0x28] += endX;
  out[0x29] += endY;
  out[0x2a] += endZ;
  return;
}
