#include "main/dll/CF/CFguardian.h"
#include "main/game_object.h"

extern undefined4 FUN_80006b14();
extern int FUN_80017730();
extern undefined4 FUN_80017748();
extern undefined4 ObjHits_DisableObject();
extern int Obj_GetActiveModel(int obj);
extern byte FUN_80063a68();
extern undefined4 FUN_80063a74();
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void objfx_spawnDirectionalBurst(int obj, u8 idx, f32 scale, int model, int mode, u8 chance,
                           f32 alpha, int flags, int unused);
extern void trackDolphin_buildSweptBounds(uint *boundsOut,float *startPoints,float *endPoints,
                                          float *radii,int pointCount);
extern undefined4 FUN_80183c74();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();

extern undefined4 DAT_802c2a00;
extern undefined4 DAT_802c2a04;
extern undefined4 DAT_802c2a08;
extern undefined4 DAT_802c2a0c;
extern undefined4 DAT_802c2a10;
extern undefined4 DAT_802c2a14;
extern undefined4 DAT_803ad400;
extern undefined4 DAT_803ad404;
extern undefined4 DAT_803ad408;
extern undefined4 DAT_803ad40c;
extern undefined4 DAT_803de748;
extern u8 lbl_803DBDBC;
extern f64 DOUBLE_803e4660;
extern f32 FLOAT_803e4644;
extern f32 FLOAT_803e4680;
extern f32 FLOAT_803e468c;
extern f32 FLOAT_803e4690;
extern f32 FLOAT_803e4694;
extern f32 FLOAT_803e4698;
extern f32 lbl_803E3A00;
extern f32 lbl_803E3A04;

typedef struct GuardianAngleParams {
  s16 a, b, c;
  f32 w;
  f32 x, y, z;
} GuardianAngleParams;

/*
 * --INFO--
 *
 * Function: fn_801845FC
 * EN v1.0 Address: 0x801845FC
 * EN v1.0 Size: 492b
 */
void fn_801845FC(u8 *obj, f32 *p2, u8 mode, f32 *p3)
{
  extern int getAngle(f32, f32);
  extern f32 sqrtf(f32);
  extern void vecRotateZXY(void *, f32 *);
  extern f32 lbl_803E39F8;
  extern f32 lbl_803E39FC;
  extern f32 lbl_803E3A00;
  f32 *sub = ((GameObject *)obj)->extra;
  GuardianAngleParams st;
  f32 buf[3];

  if (mode == 1) {
    buf[0] = p2[1];
    buf[1] = p2[2];
    buf[2] = p2[3];
  } else if (mode == 0) {
    buf[0] = p3[0];
    buf[1] = p3[1];
    buf[2] = p3[2];
  } else if (mode == 2) {
    f32 sq, d;
    ((GameObject *)obj)->anim.velocityX = p3[0];
    ((GameObject *)obj)->anim.velocityZ = p3[2];
    sq = ((GameObject *)obj)->anim.velocityX * ((GameObject *)obj)->anim.velocityX
       + ((GameObject *)obj)->anim.velocityZ * ((GameObject *)obj)->anim.velocityZ;
    if (sq != lbl_803E39F8) {
      sq = sqrtf(sq);
    }
    ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX / (d = lbl_803E39FC * sq);
    ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ / d;
    sub[0] = ((GameObject *)obj)->anim.velocityX;
    sub[1] = ((GameObject *)obj)->anim.velocityZ;
    ((GameObject *)obj)->anim.rotX = (u16)getAngle(-p3[0], -p3[2]);
    return;
  }

  st.x = lbl_803E39F8;
  st.y = lbl_803E39F8;
  st.z = lbl_803E39F8;
  st.w = lbl_803E3A00;
  st.c = 0;
  st.b = 0;
  st.a = ((GameObject *)obj)->anim.rotX;

  vecRotateZXY(&st, buf);

  if (p2) {
    u16 a = getAngle(buf[0], buf[1]);
    ((GameObject *)obj)->anim.rotY = (u16)getAngle(buf[2], buf[1]);
    ((GameObject *)obj)->anim.rotZ = a;
  } else {
    ((GameObject *)obj)->anim.rotZ = 0;
    ((GameObject *)obj)->anim.rotY = (s16)getAngle(p3[0] + p3[2], p3[1]);
    if (((GameObject *)obj)->anim.rotY < 0) {
      ((GameObject *)obj)->anim.rotY *= -1;
    }
    ((GameObject *)obj)->anim.rotX = (s16)getAngle(p3[0], p3[2]);
  }
}
/*
 * --INFO--
 *
 * Function: scarab_getExtraSize
 * EN v1.0 Address: 0x801847E8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80184918
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int scarab_getExtraSize(void)
{
  return 0x34;
}

/*
 * --INFO--
 *
 * Function: scarab_free
 * EN v1.0 Address: 0x801847F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80184920
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void scarab_free(void)
{
}

void scarab_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
  int state;
  int model;
  u8 *shellColors;
  int i;

  state = *(int *)&((GameObject *)obj)->extra;
  model = Obj_GetActiveModel(obj);
  if (((GameObject *)obj)->anim.seqId == 0x3d6) {
    i = 0;
    shellColors = &lbl_803DBDBC;
    for (; i < 7; i++) {
      if (*shellColors == *(u8 *)(*(int *)(model + 0x34) + 8)) {
        i++;
        if (i == 7) {
          i = 0;
        }
        *(u8 *)(*(int *)(model + 0x34) + 8) = (&lbl_803DBDBC)[i];
        break;
      }
      shellColors++;
    }
  }

  if (*(s16 *)(state + 0x10) == 0) {
    if (((GameObject *)obj)->unkF8 != 0) {
      if (visible != -1) {
        return;
      }
    } else if (visible == 0) {
      return;
    }

    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E3A00);
    if ((visible != 0) && (((GameObject *)obj)->anim.alpha != 0)) {
      objfx_spawnDirectionalBurst(obj, 5, lbl_803E3A00, (u8)*(s16 *)(state + 0x22), 1, 0x14,
                     lbl_803E3A04, 0, 0);
    }
  }
}
