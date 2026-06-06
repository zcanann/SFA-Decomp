#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/dll_138.h"
#include "main/dll/pushable.h"


extern undefined4 FUN_80003494();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80017698();
extern uint GameBit_Get(int bit);
extern void GameBit_Set(int bit, int value);
extern uint FUN_80017730();
extern undefined4 FUN_80017754();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017778();
extern int FUN_80017a98();
extern int Obj_GetPlayerObject();
extern void setMatrixFromObjectPos(float *outMtx, short *inObj);
extern int FUN_80039520();
extern int *objFindTexture(int obj, int textureIndex, int materialIndex);
extern int FUN_800620e8();
extern undefined4 FUN_800e8630();
extern undefined8 FUN_80286820();
extern undefined4 FUN_8028686c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern int ObjMsg_Pop(int obj, int *outMessage, int *outSender, int *outParam);
extern void Obj_FreeObject(int obj);
extern f32 sqrtf(f32 x);

extern void **gCameraInterface;
extern f64 DOUBLE_803e4210;
extern f32 lbl_803DC074;
extern f32 lbl_803E41C0;
extern f32 lbl_803E41EC;
extern f32 lbl_803E41F0;
extern f32 lbl_803E41FC;
extern f32 lbl_803E4204;
extern f32 lbl_803E4220;
extern f32 lbl_803E4230;
extern f32 lbl_803E3528;
extern f32 lbl_803E3588;
extern f32 lbl_803E3598;
extern f32 timeDelta;
extern f32 lbl_803E3564;
extern f32 lbl_803E356C;
extern f32 lbl_803E3580;
extern f32 lbl_803E3584;

/*
 * --INFO--
 *
 * Function: fn_80174A80
 * EN v1.0 Address: 0x80174ED4
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x80174F2C
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_80174A80(int obj, PushableState *ext)
{
    int def;
    u8 *tex;
    f32 f;
    f32 v;
    f32 lim;

    def = *(int *)&((GameObject *)obj)->anim.placementData;
    ext->eyeOpenSpeed = lbl_803E3580;
    f = lbl_803E3584;
    ext->eyeDriftSpeedX = f;
    ext->eyeDriftSpeedY = f;
    ext->blinkInterval = lbl_803E3564 * (f32)(int)randomGetRange(0x19, 0x4b);
    ext->blinkStep = ext->blinkInterval / (f32)(int)randomGetRange(0x28, 0x46);
    f = lbl_803E3528;
    ext->blinkPhase = f;
    ext->gameBit = *(short *)(def + 0x18);
    ext->gameBit2 = *(short *)(def + 0x1a);
    ext->unk_F0 = f;
    ext->nearestObj = NULL;
    GameBit_Set(ext->gameBit, 0);
    tex = (u8 *)objFindTexture(obj, 0, 0);

    ext->eyePosX = ext->eyePosX + ext->eyeDriftSpeedX;
    v = ext->eyePosX;
    lim = lbl_803E356C;
    if (v > lim) {
        ext->eyePosX = lim;
    } else if (v < lbl_803E3528) {
        ext->eyePosX = lim;
    }

    ext->eyePosY = ext->eyePosY + ext->eyeDriftSpeedY;
    v = ext->eyePosY;
    lim = lbl_803E356C;
    if (v > lim) {
        ext->eyePosY = lim;
    } else if (v < lbl_803E3528) {
        ext->eyePosY = lim;
    }

    tex[0xc] = 10;
    tex[0xd] = 10;
    tex[0xe] = 10;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_80174BFC
 * EN v1.0 Address: 0x80174BFC
 * EN v1.0 Size: 1296b
 */
typedef struct Dll138PoseCopy {
    s16 rot[3];
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} Dll138PoseCopy;

typedef struct Dll138HitInfo {
    u8 pad0[0x1c];
    f32 angleX;
    u8 pad1[4];
    f32 angleZ;
    u8 pad2[0x29];
    s8 id;
    u8 pad3[2];
} Dll138HitInfo;

extern void Matrix_TransformPoint(f32 *matrix, f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ);
extern int objBboxFn_800640cc(f32 *from, f32 *to, f32 radius, int mode, void *hit, int obj, int p7, int p8, u8 p9, int p10);
extern int getAngle(f32 a, f32 b);
extern f32 mathSinf(f32);
extern f32 mathCosf(f32);
extern void memcpy(void *dst, void *src, int n);
extern void saveGame_saveObjectPos(int obj);
extern int Sfx_PlayFromObject(int a, int b);
extern f32 lbl_803E358C;
extern f32 lbl_803E3590;
extern f32 lbl_803E3594;

#pragma peephole off
#pragma scheduling off
void fn_80174BFC(int obj, int ext)
{
    f32 *ptOut;
    f32 *vel;
    int extPtr;
    int def;
    int i;
    s8 bits;
    f32 *velBase;
    int iter;
    f32 scale;
    f32 savedX;
    f32 savedY;
    f32 savedZ;
    Dll138PoseCopy pose;
    f32 mtx[16];
    f32 points[21];
    Dll138HitInfo hit;

    def = *(int *)&((GameObject *)obj)->anim.placementData;
    velBase = (f32 *)((PushableState *)ext)->probeLocal;
    Obj_GetPlayerObject();
    savedX = ((GameObject *)obj)->anim.localPosX;
    savedY = ((GameObject *)obj)->anim.localPosY;
    savedZ = ((GameObject *)obj)->anim.localPosZ;
    bits = 0xf;
    iter = 0;
    scale = lbl_803E3588;
    while (bits != 0) {
        bits = 0xf;
        iter = iter + 1;
        if (iter > 4) {
            ((GameObject *)obj)->anim.localPosX = savedX;
            ((GameObject *)obj)->anim.localPosY = savedY;
            ((GameObject *)obj)->anim.localPosZ = savedZ;
            break;
        }
        i = 0;
        ptOut = points;
        vel = velBase;
        extPtr = ext;
        for (; i < ((PushableState *)ext)->pointCount; i++) {
            pose.rot[0] = ((GameObject *)obj)->anim.rotX;
            pose.rot[1] = ((GameObject *)obj)->anim.rotY;
            pose.rot[2] = ((GameObject *)obj)->anim.rotZ;
            pose.scale = scale;
            pose.x = ((GameObject *)obj)->anim.localPosX;
            pose.y = ((GameObject *)obj)->anim.localPosY;
            pose.z = ((GameObject *)obj)->anim.localPosZ;
            setMatrixFromObjectPos(mtx, (short *)&pose);
            Matrix_TransformPoint(mtx, vel[0], vel[1], vel[2], ptOut, &points[i * 3 + 1],
                                  &points[i * 3 + 2]);
            if ((1 << i & 0xf) != 0) {
                if (objBboxFn_800640cc((f32 *)(extPtr + 0x78), ptOut, lbl_803E358C, 1, &hit, obj,
                                       8, 0xd, (u8)(i + 3), 10) == 0) {
                    bits = (s8)(bits & ~(1 << i));
                } else {
                    int angle;
                    int delta;
                    if (hit.id != -1 && (((PushableState *)ext)->flags & 1) == 0) {
                        int gamebit;
                        ((PushableState *)ext)->flags |= 1;
                        gamebit = *(s16 *)(def + 0x18);
                        if (gamebit > -1) {
                            switch (((GameObject *)obj)->anim.seqId) {
                            case 0x411:
                            case 0x21e:
                                break;
                            case 0x7df:
                                ((PushableState *)ext)->flags &= ~1;
                                if (hit.id == ((PushableState *)ext)->requiredHitId) {
                                    int *tex = objFindTexture(obj, 0, 0);
                                    if (tex != NULL) {
                                        *tex = 0x100;
                                    }
                                    GameBit_Set(*(s16 *)(def + 0x18), 1);
                                    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                                    ((PushableState *)ext)->flags |= 0x80;
                                }
                                break;
                            case 0x1cb:
                                if (hit.id == 1) {
                                    GameBit_Set(gamebit, 1);
                                    Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
                                    ((PushableState *)ext)->flags |= 0x80;
                                    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                                    saveGame_saveObjectPos(obj);
                                }
                                break;
                            default: {
                                s8 t = *(s8 *)(def + 0x23);
                                if (t > -1 && t == hit.id) {
                                    GameBit_Set(gamebit, 1);
                                    Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
                                }
                                break;
                            }
                            }
                        }
                    }
                    mathSinf(lbl_803E3590 * (f32)((PushableState *)ext)->yaw / lbl_803E3594);
                    mathCosf(lbl_803E3590 * (f32)((PushableState *)ext)->yaw / lbl_803E3594);
                    angle = getAngle(hit.angleX, hit.angleZ);
                    delta = ((PushableState *)ext)->yaw - (angle & 0xffff);
                    if (delta > 0x8000) {
                        delta -= 0xffff;
                    }
                    if (delta < -0x8000) {
                        delta += 0xffff;
                    }
                    delta = delta / 0xb6;
                    if (delta > -0x1e && delta < 0x1e) {
                        ((PushableState *)ext)->flags |= 0x100;
                        ((PushableState *)ext)->pushAmountX = lbl_803E3528;
                    } else if (delta > 0x96 || delta < -0x96) {
                        ((PushableState *)ext)->flags |= 0x200;
                        ((PushableState *)ext)->pushAmountX = lbl_803E3528;
                    } else if (delta > 0x3c && delta < 0x78) {
                        ((PushableState *)ext)->flags |= 0x800;
                        ((PushableState *)ext)->pushAmountZ = lbl_803E3528;
                    } else if (delta < -0x3c && delta > -0x78) {
                        ((PushableState *)ext)->flags |= 0x400;
                        ((PushableState *)ext)->pushAmountZ = lbl_803E3528;
                    }
                    memcpy((void *)(extPtr + 0x78), ptOut, 0xc);
                    mtx[12] = ptOut[0];
                    mtx[13] = ptOut[1];
                    mtx[14] = ptOut[2];
                    Matrix_TransformPoint(mtx, -vel[0], -vel[1], -vel[2], (f32 *)(obj + 0xc),
                                          (f32 *)(obj + 0x10), (f32 *)(obj + 0x14));
                }
            }
            ptOut += 3;
            vel += 3;
            extPtr += 0xc;
        }
    }
    memcpy(((PushableState *)ext)->cornerWorld, points, ((PushableState *)ext)->pointCount * 0xc);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_8017510C
 * EN v1.0 Address: 0x80175468
 * EN v1.0 Size: 744b
 * EN v1.1 Address: 0x801755B8
 * EN v1.1 Size: 796b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
undefined4 fn_8017510C(short *param_1,short *param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  PushableState *iVar3;
  f32 dx;
  f32 dz;
  f32 len;
  f32 k;
  
  iVar3 = *(PushableState **)(param_1 + 0x5c);
  iVar3->savePosDelay = 0x3c;
  if (param_1[0x5a] != -1) {
    (*(void (**)(short *))((char *)*gCameraInterface + 0x4c))(param_1);
  }
  *(short *)(param_3 + 0x70) = -1;
  if (*(char *)(param_3 + 0x56) != '\0') {
    if (*(char *)(param_3 + 0x56) != '\x02') {
      *(float *)(param_3 + 0x4c) = lbl_803E3588;
      *(float *)(param_3 + 0x40) = *(float *)(param_1 + 6) - *(float *)(param_2 + 6);
      *(float *)(param_3 + 0x44) = *(float *)(param_1 + 8) - *(float *)(param_2 + 8);
      *(float *)(param_3 + 0x48) = *(float *)(param_1 + 10) - *(float *)(param_2 + 10);
      *(short *)(param_3 + 0x50) = *param_1 - (u16)*param_2;
      if (0x8000 < *(short *)(param_3 + 0x50)) {
        *(short *)(param_3 + 0x50) = *(short *)(param_3 + 0x50) - 0xffff;
      }
      if (*(short *)(param_3 + 0x50) < -0x8000) {
        *(short *)(param_3 + 0x50) = *(short *)(param_3 + 0x50) + 0xffff;
      }
      *(short *)(param_3 + 0x52) = param_1[1] - (u16)param_2[1];
      if (0x8000 < *(short *)(param_3 + 0x52)) {
        *(short *)(param_3 + 0x52) = *(short *)(param_3 + 0x52) - 0xffff;
      }
      if (*(short *)(param_3 + 0x52) < -0x8000) {
        *(short *)(param_3 + 0x52) = *(short *)(param_3 + 0x52) + 0xffff;
      }
      *(short *)(param_3 + 0x54) = (u16)param_2[2] - (u16)param_1[2];
      if (0x8000 < *(short *)(param_3 + 0x54)) {
        *(short *)(param_3 + 0x54) = *(short *)(param_3 + 0x54) - 0xffff;
      }
      if (*(short *)(param_3 + 0x54) < -0x8000) {
        *(short *)(param_3 + 0x54) = *(short *)(param_3 + 0x54) + 0xffff;
      }
      *(undefined *)(param_3 + 0x56) = 2;
    }
    *(float *)(param_3 + 0x4c) =
         -(*(float *)(param_3 + 0x24) * timeDelta - *(float *)(param_3 + 0x4c));
    if (*(float *)(param_3 + 0x4c) <= lbl_803E3528) {
      *(undefined *)(param_3 + 0x56) = 0;
    }
  }
  if (*(int *)(param_1 + 0x7c) == 0) {
    *(int *)(param_1 + 0x7c) = 2;
  }
  if ((param_1[0x23] == 0x21e) || (param_1[0x23] == 0x411)) {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
    if (('\0' < *(char *)(*(int *)(param_1 + 0x2c) + 0x10f)) &&
       ((*(short *)(*(int *)(*(int *)(param_1 + 0x2c) + 0x100) + 0x44) == 0x24 &&
        (uVar1 = GameBit_Get(0x103), uVar1 == 0)))) {
      GameBit_Set(0x103,1);
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & ~8;
      iVar2 = Obj_GetPlayerObject();
      dx = *(float *)(param_1 + 6) - *(float *)(iVar2 + 0xc);
      dz = *(float *)(param_1 + 10) - *(float *)(iVar2 + 0x14);
      len = sqrtf(dx * dx + dz * dz);
      if (len != lbl_803E3528) {
        dx = dx / len;
        dz = dz / len;
      }
      k = lbl_803E3598;
      iVar3->unk_C0 = k * dx;
      iVar3->unk_C4 = lbl_803E3528;
      iVar3->unk_C8 = k * dz;
      return 4;
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_80175428
 * EN v1.0 Address: 0x80175428
 * EN v1.0 Size: 248b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void fn_80175428(int obj)
{
  PushableState *state;
  int msgSender;
  int msg;
  int msgParam;

  state = ((GameObject *)obj)->extra;
  msgParam = 0;
  while (ObjMsg_Pop(obj,&msg,&msgSender,&msgParam) != 0) {
    switch (msg) {
    case 0xf0003:
      state->msgSenderObj = msgSender;
      break;
    case 0xe:
      if ((((GameObject *)obj)->anim.seqId != 0x21e) && (((GameObject *)obj)->anim.seqId != 0x411)) {
        Obj_FreeObject(obj);
      }
      break;
    case 0x40001:
      if (((GameObject *)obj)->anim.seqId == 0x21e) {
        state->unk_F0 = *(float *)msgParam;
      }
      if (((GameObject *)obj)->anim.seqId == 0x411) {
        state->unk_F0 = *(float *)msgParam;
      }
      break;
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: pushable_render2
 * EN v1.0 Address: 0x80175520
 * EN v1.0 Size: 16b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int pushable_render2(int obj)
{
  return (*(PushableState **)&((GameObject *)obj)->extra)->flags & 1;
}

/*
 * --INFO--
 *
 * Function: pushable_modelMtxFn
 * EN v1.0 Address: 0x80175530
 * EN v1.0 Size: 28b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void pushable_modelMtxFn(int obj,int modelNo)
{
  int extra = *(int *)&((GameObject *)obj)->extra;
  uint flags = *(uint *)(extra + 0xa8);

  *(uint *)(extra + 0xa8) = flags | (1 << modelNo);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: pushable_func0B
 * EN v1.0 Address: 0x8017554C
 * EN v1.0 Size: 128b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct Dll138Vec3 {
    f32 x;
    f32 y;
    f32 z;
} Dll138Vec3;

#pragma scheduling off
#pragma peephole off
#pragma fp_contract off
int pushable_func0B(int obj,int other)
{
  int state;
  f32 delta[3];
  f32 *d;

  state = *(int *)&((GameObject *)obj)->extra;
  d = delta;
  d[0] = *(f32 *)(other + 0xc) - ((GameObject *)obj)->anim.localPosX;
  d[1] = *(f32 *)(other + 0x10) - ((GameObject *)obj)->anim.localPosY;
  d[2] = *(f32 *)(other + 0x14) - ((GameObject *)obj)->anim.localPosZ;
  return sqrtf(d[2] * d[2] + (d[0] * d[0] + d[1] * d[1])) <
         *(f32 *)(state + 0xc);
}
#pragma fp_contract reset
#pragma peephole reset
#pragma scheduling reset
