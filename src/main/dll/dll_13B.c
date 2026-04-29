#include "ghidra_import.h"
#include "main/dll/dll_13B.h"
#include "main/objanim.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_80017620();
extern uint FUN_80017760();
extern undefined4 FUN_80017a98();
extern int FUN_80017af8();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_80035b84();
extern undefined4 ObjHits_DisableObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008112c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern void fn_8003B8F4(double scale);

extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de710;
extern f64 DOUBLE_803e3d08;
extern f64 DOUBLE_803e3d80;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e3cf8;
extern f32 FLOAT_803e3d14;
extern f32 FLOAT_803e3d38;
extern f32 FLOAT_803e3d3c;
extern f32 FLOAT_803e3d60;
extern f32 FLOAT_803e3d64;
extern f32 FLOAT_803e3d68;
extern f32 FLOAT_803e3d6c;
extern f32 FLOAT_803e3d70;
extern f32 FLOAT_803e3d78;
extern f32 lbl_803DB414;
extern f32 lbl_803E30D0;
extern f32 lbl_803E30D4;

/*
 * --INFO--
 *
 * Function: FUN_80169360
 * EN v1.0 Address: 0x80169360
 * EN v1.0 Size: 648b
 * EN v1.1 Address: 0x80169564
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80169360(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
  double dVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int iVar8;
  undefined4 *puVar9;
  int iVar10;
  undefined8 uVar11;
  
  uVar11 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar11 >> 0x20);
  iVar10 = *(int *)(iVar2 + 0xb8);
  uVar7 = 6;
  if (param_11 != 0) {
    uVar7 = 7;
  }
  uVar4 = 8;
  uVar5 = 6;
  uVar6 = 0;
  iVar8 = *DAT_803dd738;
  (**(code **)(iVar8 + 0x58))((double)FLOAT_803e3d60,iVar2,(int)uVar11,iVar10);
  *(undefined4 *)(iVar2 + 0xbc) = 0;
  puVar9 = *(undefined4 **)(iVar10 + 0x40c);
  FUN_800305f8((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,
               4,0x10,uVar4,uVar5,uVar6,uVar7,iVar8);
  *(float *)(iVar2 + 0x98) = FLOAT_803e3d14;
  *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 8;
  (**(code **)(*DAT_803dd70c + 0x14))(iVar2,iVar10,0);
  *(undefined2 *)(iVar10 + 0x270) = 0;
  *(float *)(iVar10 + 0x2a0) = FLOAT_803e3d14;
  *(float *)(iVar10 + 0x280) = FLOAT_803e3cf8;
  uVar7 = FUN_80017a98();
  *(undefined4 *)(iVar10 + 0x2d0) = uVar7;
  *(undefined *)(iVar10 + 0x25f) = 0;
  ObjHits_DisableObject(iVar2);
  uVar3 = FUN_80017760(300,600);
  puVar9[0xd] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e3d08);
  uVar3 = FUN_80017760(0,499);
  dVar1 = DOUBLE_803e3d08;
  puVar9[0xe] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e3d08);
  puVar9[0xf] = FLOAT_803e3cf8;
  *puVar9 = 0;
  *(ushort *)(iVar2 + 0xb0) = *(ushort *)(iVar2 + 0xb0) | 0x2000;
  *(float *)(iVar2 + 8) =
       FLOAT_803e3d38 +
       (float)((double)CONCAT44(0x43300000,(int)*(char *)((int)uVar11 + 0x28) ^ 0x80000000) - dVar1)
       / FLOAT_803e3d3c;
  FUN_80035b84(iVar2,(short)(int)(FLOAT_803e3d64 * *(float *)(iVar2 + 8)));
  if (param_11 == 0) {
    DAT_803de710 = FUN_80006b14(0x5a);
  }
  FUN_8028688c();
  return;
}

int kaldachompme_getExtraSize(void)
{
  return 0x10;
}

int kaldachompme_func08(void)
{
  return 0;
}

void kaldachompme_free(void)
{
}

void kaldachompme_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                         undefined4 param_5,char renderFlag)
{
  if (renderFlag != '\0') {
    fn_8003B8F4((double)lbl_803E30D0);
  }
}

void kaldachompme_hitDetect(void)
{
}

void kaldachompme_update(int obj)
{
  float *extra;
  float current;
  float target;
  float step;

  extra = *(float **)(obj + 0xb8);
  current = extra[0];
  target = extra[2];
  if (current != target) {
    step = extra[1];
    if (step > lbl_803E30D4) {
      if (current < target) {
        extra[0] = current + step * lbl_803DB414;
      }
      else {
        extra[0] = target;
      }
    }
    else {
      if (current > target) {
        extra[0] = current + step * lbl_803DB414;
      }
      else {
        extra[0] = target;
      }
    }
  }
  ObjAnim_SetCurrentMove((double)extra[0],obj,(uint)*(byte *)((int)extra + 0xc),0);
}

void kaldachompme_init(int obj,int params)
{
  *(s16 *)(obj + 4) = (s16)(*(u8 *)(params + 0x18) << 8);
  *(s16 *)(obj + 2) = (s16)(*(u8 *)(params + 0x19) << 8);
  *(s16 *)(obj + 0) = (s16)(*(u8 *)(params + 0x1a) << 8);
  *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) | 0x2000);
  ObjAnim_SetCurrentMove((double)lbl_803E30D4,obj,0,0);
}

void kaldachompme_release(void)
{
}

void kaldachompme_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801695e8
 * EN v1.0 Address: 0x801695E8
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x8016980C
 * EN v1.1 Size: 576b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801695e8(int param_1,byte param_2)
{
  float *pfVar1;
  int iVar2;
  
  if (param_1 == 0) {
    return;
  }
  iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  if (iVar2 == 0x41ccc) {
    iVar2 = FUN_80017af8(0x4b411);
  }
  else if (iVar2 < 0x41ccc) {
    if (iVar2 == 0x41cc6) {
      iVar2 = FUN_80017af8(0x4b404);
    }
    else if (iVar2 < 0x41cc6) {
      if (iVar2 == 0x41cc4) {
        iVar2 = FUN_80017af8(0x4b402);
      }
      else if (iVar2 < 0x41cc4) {
        if (iVar2 != 0x41be9) {
          return;
        }
        iVar2 = FUN_80017af8(0x4b3f9);
      }
      else {
        iVar2 = FUN_80017af8(0x4b403);
      }
    }
    else if (iVar2 == 0x41cc9) {
      iVar2 = FUN_80017af8(0x4b40f);
    }
    else {
      if (0x41cc8 < iVar2) {
        return;
      }
      if (iVar2 < 0x41cc8) {
        iVar2 = FUN_80017af8(0x4b40b);
      }
      else {
        iVar2 = FUN_80017af8(0x4b40c);
      }
    }
  }
  else if (iVar2 == 0x41cd6) {
    iVar2 = FUN_80017af8(0x4b415);
  }
  else if (iVar2 < 0x41cd6) {
    if (iVar2 == 0x41cd2) {
      iVar2 = FUN_80017af8(0x4b410);
    }
    else {
      if (iVar2 < 0x41cd2) {
        return;
      }
      if (iVar2 < 0x41cd5) {
        return;
      }
      iVar2 = FUN_80017af8(0x4b414);
    }
  }
  else if (iVar2 == 0x43d14) {
    iVar2 = FUN_80017af8(0x4b3b5);
  }
  else {
    if (0x43d13 < iVar2) {
      return;
    }
    if (iVar2 != 0x41cd9) {
      return;
    }
    iVar2 = FUN_80017af8(0x4b453);
  }
  pfVar1 = *(float **)(iVar2 + 0xb8);
  if (pfVar1 != (float *)0x0) {
    if (param_2 == 2) {
      pfVar1[2] = FLOAT_803e3d68;
      *pfVar1 = FLOAT_803e3d6c;
      pfVar1[1] = FLOAT_803e3d70;
      *(undefined *)(pfVar1 + 3) = 1;
    }
    else if ((param_2 < 2) && (param_2 != 0)) {
      pfVar1[2] = FLOAT_803e3d68;
      *pfVar1 = FLOAT_803e3d6c;
      pfVar1[1] = FLOAT_803e3d70;
      *(undefined *)(pfVar1 + 3) = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016980c
 * EN v1.0 Address: 0x8016980C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80169A4C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016980c(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80169834
 * EN v1.0 Address: 0x80169834
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x80169A80
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80169834(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  float *pfVar2;
  double dVar3;
  double dVar4;
  
  pfVar2 = *(float **)(param_9 + 0xb8);
  dVar4 = (double)*pfVar2;
  fVar1 = pfVar2[2];
  dVar3 = (double)fVar1;
  if (dVar4 != dVar3) {
    param_3 = (double)pfVar2[1];
    if (param_3 <= (double)FLOAT_803e3d6c) {
      if (dVar4 <= dVar3) {
        *pfVar2 = fVar1;
      }
      else {
        *pfVar2 = (float)(param_3 * (double)FLOAT_803dc074 + dVar4);
      }
    }
    else if (dVar3 <= dVar4) {
      *pfVar2 = fVar1;
    }
    else {
      *pfVar2 = (float)(param_3 * (double)FLOAT_803dc074 + dVar4);
    }
  }
  FUN_800305f8((double)*pfVar2,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
               (uint)*(byte *)(pfVar2 + 3),0,param_12,param_13,param_14,param_15,param_16);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80169960
 * EN v1.0 Address: 0x80169960
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x80169B0C
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80169960(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  param_9[2] = (ushort)*(byte *)(param_10 + 0x18) << 8;
  param_9[1] = (ushort)*(byte *)(param_10 + 0x19) << 8;
  *param_9 = (ushort)*(byte *)(param_10 + 0x1a) << 8;
  param_9[0x58] = param_9[0x58] | 0x2000;
  FUN_800305f8((double)FLOAT_803e3d6c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80169a44
 * EN v1.0 Address: 0x80169A44
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x80169B80
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80169a44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  uint uVar1;
  int *piVar2;
  int local_18 [2];
  undefined4 local_10;
  uint uStack_c;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  *(undefined *)(param_9 + 0x36) = 0;
  *(undefined4 *)(param_9 + 0xf4) = 0xdc;
  *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfffe;
  if (*piVar2 != 0) {
    FUN_800175cc((double)FLOAT_803e3d78,*piVar2,'\0');
  }
  if (*(short *)(param_9 + 0x46) == 0x869) {
    uVar1 = FUN_80017760(0,1);
    uStack_c = FUN_80017760(0x32,0x3c);
    uStack_c = uStack_c ^ 0x80000000;
    local_10 = 0x43300000;
    FUN_8008112c((double)(float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e3d80),param_2,
                 param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,1,0,uVar1 & 0xff,0,1,0);
  }
  else {
    for (local_18[0] = 0; local_18[0] < 0x19; local_18[0] = local_18[0] + 1) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x715,0,1,0xffffffff,local_18);
    }
    FUN_80006824(param_9,0x279);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80169c04
 * EN v1.0 Address: 0x80169C04
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x80169CC8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80169c04(int param_1)
{
  if (**(uint **)(param_1 + 0xb8) != 0) {
    FUN_80017620(**(uint **)(param_1 + 0xb8));
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void kaldachompspit_hitDetect(void) {}
